import type Database from 'better-sqlite3';
import crypto from 'crypto';
import express from 'express';
import fs from 'fs';
import { createNotification, recordAudit } from '../audit.ts';
import type { AppConfig } from '../config.ts';
import { generateRandomToken, hashPassword, sha256Hex, signToken, verifyToken } from '../crypto.ts';
import {
  buildCandidateInvitationEmail,
  buildDocumentRejectionEmail,
  type EmailService,
} from '../email.ts';
import { resolvePrivateDocumentPath } from '../fileSecurity.ts';
import { createAuthMiddleware, getClientIp } from '../middleware.ts';

export function createCandidatesRouter(
  db: Database.Database,
  config: AppConfig,
  emailService: EmailService,
): express.Router {
  const router = express.Router();
  const { requireAuth, requireRole } = createAuthMiddleware(db, config);

  // Note: document download supports either authenticated HR/Admin cookie OR short-lived signed download token
  router.get('/:id/documents/:docId/download', (req, res, next) => {
    const sigToken = typeof req.query.sig === 'string' ? req.query.sig : '';
    if (sigToken) {
      const payload = verifyToken(sigToken, config.sessionSecret, 'doc_download');
      if (!payload || payload.docId !== req.params.docId) {
        res.status(403).json({ error: 'Download link is invalid or expired.' });
        return;
      }
      const doc = db
        .prepare('SELECT * FROM candidate_documents WHERE id = ? AND candidate_id = ?')
        .get(req.params.docId, req.params.id) as
        | {
            id: string;
            original_filename: string;
            stored_filename: string;
            mime_type: string;
          }
        | undefined;
      if (!doc) {
        res.status(404).json({ error: 'Document not found.' });
        return;
      }
      const fullPath = resolvePrivateDocumentPath(config, doc.stored_filename);
      if (!fs.existsSync(fullPath)) {
        res.status(404).json({ error: 'Document binary missing from private storage.' });
        return;
      }
      res.setHeader('Content-Type', doc.mime_type);
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.setHeader('Cache-Control', 'no-store');
      res.setHeader(
        'Content-Disposition',
        `${req.query.disposition === 'attachment' ? 'attachment' : 'inline'}; filename="${doc.original_filename.replace(/[^a-zA-Z0-9._-]/g, '_')}"`,
      );
      fs.createReadStream(fullPath).pipe(res);
      return;
    }
    next();
  });

  router.use(requireAuth);

  // List candidates (HR/Admin see all; Manager sees only assigned/department candidates; Employee/Accounts blocked)
  router.get('/', requireRole('HR', 'Admin', 'Manager'), (req, res) => {
    const actor = req.authUser!;
    const rows =
      actor.role === 'Manager'
        ? db
            .prepare(`
              SELECT c.*, u.full_name AS recruiter_name, u.email AS recruiter_email
              FROM candidates c
              LEFT JOIN users u ON u.id = c.assigned_recruiter_id
              WHERE c.assigned_recruiter_id = ? OR c.department = ?
              ORDER BY c.updated_at DESC
            `)
            .all(actor.id, actor.department)
        : db
            .prepare(`
              SELECT c.*, u.full_name AS recruiter_name, u.email AS recruiter_email
              FROM candidates c
              LEFT JOIN users u ON u.id = c.assigned_recruiter_id
              ORDER BY c.updated_at DESC
            `)
            .all();

    const docCounts = db
      .prepare(`
        SELECT candidate_id,
               SUM(CASE WHEN status = 'Uploaded' THEN 1 ELSE 0 END) AS uploaded_count,
               SUM(CASE WHEN status = 'Approved' THEN 1 ELSE 0 END) AS approved_count,
               SUM(CASE WHEN status IN ('Rejected', 'Re-upload Required') THEN 1 ELSE 0 END) AS rejected_count
        FROM candidate_documents
        WHERE is_current = 1
        GROUP BY candidate_id
      `)
      .all() as Array<{
      candidate_id: string;
      uploaded_count: number;
      approved_count: number;
      rejected_count: number;
    }>;

    const countMap = new Map(docCounts.map((d) => [d.candidate_id, d]));

    res.json({
      candidates: (rows as Array<Record<string, unknown>>).map((c) => ({
        ...c,
        docSummary: countMap.get(String(c.id)) || {
          uploaded_count: 0,
          approved_count: 0,
          rejected_count: 0,
        },
      })),
    });
  });

  // Step 1: Recruiter/HR creates candidate record with duplicate prevention
  router.post('/', requireRole('HR', 'Admin'), (req, res) => {
    const actor = req.authUser!;
    const {
      fullName,
      email,
      mobile,
      jobPosition,
      department,
      assignedRecruiterId,
      experienceYears,
      expectedCtc,
      noticePeriodDays,
      notes,
    } = req.body as {
      fullName?: string;
      email?: string;
      mobile?: string;
      jobPosition?: string;
      department?: string;
      assignedRecruiterId?: string;
      experienceYears?: number;
      expectedCtc?: string;
      noticePeriodDays?: number;
      notes?: string;
    };

    if (!fullName?.trim() || !email?.trim() || !mobile?.trim() || !jobPosition?.trim() || !department?.trim()) {
      res.status(400).json({
        error: 'Candidate full name, email, mobile number, job position, and department are required.',
      });
      return;
    }

    const cleanEmail = email.trim().toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) {
      res.status(400).json({ error: 'Please provide a valid candidate email address.' });
      return;
    }

    const cleanMobile = mobile.replace(/\s+/g, '');
    const duplicate = db
      .prepare('SELECT id, full_name, email FROM candidates WHERE lower(email) = ? OR mobile = ?')
      .get(cleanEmail, cleanMobile) as { id: string; full_name: string; email: string } | undefined;

    if (duplicate) {
      res.status(409).json({
        error: `Duplicate candidate prevented: ${duplicate.full_name} (${duplicate.email}) already exists.`,
      });
      return;
    }

    const recruiterId = assignedRecruiterId?.trim() || actor.id;
    const recruiterExists = db.prepare('SELECT id FROM users WHERE id = ? AND is_active = 1').get(recruiterId);
    if (!recruiterExists) {
      res.status(400).json({ error: 'Assigned recruiter account not found or inactive.' });
      return;
    }

    const id = `cand_${crypto.randomUUID()}`;
    const now = new Date().toISOString();

    db.prepare(`
      INSERT INTO candidates (
        id, full_name, email, mobile, job_position, department, assigned_recruiter_id,
        experience_years, expected_ctc, notice_period_days, notes,
        email_confirmed_by_recruiter, status, doc_verification_status,
        created_by, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 'New', 'Not Started', ?, ?, ?)
    `).run(
      id,
      fullName.trim(),
      cleanEmail,
      cleanMobile,
      jobPosition.trim(),
      department.trim(),
      recruiterId,
      Number(experienceYears || 0),
      (expectedCtc || '').trim(),
      Number(noticePeriodDays ?? 30),
      (notes || '').trim(),
      actor.id,
      now,
      now,
    );

    recordAudit(db, {
      actorUserId: actor.id,
      actorLabel: actor.email,
      actorRole: actor.role,
      action: 'CANDIDATE_CREATED',
      entityType: 'candidate',
      entityId: id,
      afterState: { fullName: fullName.trim(), email: cleanEmail, jobPosition: jobPosition.trim() },
      ipAddress: getClientIp(req),
    });

    const candidate = db.prepare('SELECT * FROM candidates WHERE id = ?').get(id);
    res.status(201).json({ candidate });
  });

  // Candidate Detail + Checklist + Document Versions + Invitations + Audit
  router.get('/:id', requireRole('HR', 'Admin', 'Manager'), (req, res) => {
    const actor = req.authUser!;
    const candidate = db
      .prepare(`
        SELECT c.*, u.full_name AS recruiter_name, u.email AS recruiter_email
        FROM candidates c
        LEFT JOIN users u ON u.id = c.assigned_recruiter_id
        WHERE c.id = ?
      `)
      .get(req.params.id) as Record<string, unknown> | undefined;

    if (!candidate) {
      res.status(404).json({ error: 'Candidate not found.' });
      return;
    }

    if (
      actor.role === 'Manager' &&
      candidate.assigned_recruiter_id !== actor.id &&
      candidate.department !== actor.department
    ) {
      res.status(403).json({ error: 'Forbidden: candidate outside your assigned scope.' });
      return;
    }

    const requirements = db
      .prepare('SELECT * FROM document_requirements WHERE is_enabled = 1 ORDER BY sort_order ASC')
      .all() as Array<{
      id: string;
      doc_type: string;
      label: string;
      description: string;
      is_mandatory: number;
      max_size_mb: number;
    }>;

    const allDocs = db
      .prepare(`
        SELECT d.*, r.full_name AS reviewer_name
        FROM candidate_documents d
        LEFT JOIN users r ON r.id = d.reviewed_by
        WHERE d.candidate_id = ?
        ORDER BY d.version DESC, d.uploaded_at DESC
      `)
      .all(req.params.id) as Array<Record<string, unknown>>;

    const currentDocsByType = new Map<string, Record<string, unknown>>();
    for (const d of allDocs) {
      if (d.is_current === 1) {
        const signedToken = signToken(
          { sub: actor.id, typ: 'doc_download', docId: String(d.id) },
          600,
          config.sessionSecret,
        );
        currentDocsByType.set(String(d.doc_type), {
          ...d,
          signedDownloadUrl: `/api/candidates/${req.params.id}/documents/${d.id}/download?sig=${encodeURIComponent(signedToken)}`,
        });
      }
    }

    const checklist = requirements.map((reqItem) => {
      const doc = currentDocsByType.get(reqItem.doc_type) || null;
      return {
        requirement: reqItem,
        currentDocument: doc,
        status: doc ? doc.status : 'Pending',
        history: allDocs.filter((d) => d.doc_type === reqItem.doc_type),
      };
    });

    const invitations = db
      .prepare(`
        SELECT id, purpose, expires_at, accepted_at, revoked_at, revoke_reason,
               sent_to_email, email_delivery_status, email_delivery_error, created_at
        FROM candidate_invitations
        WHERE candidate_id = ?
        ORDER BY created_at DESC
      `)
      .all(req.params.id);

    res.json({
      candidate,
      checklist,
      invitations,
    });
  });

  // Explicit confirmation of candidate email before sending upload invitation
  router.post('/:id/confirm-email', requireRole('HR', 'Admin'), (req, res) => {
    const actor = req.authUser!;
    const { confirmedEmail } = req.body as { confirmedEmail?: string };
    const candidate = db.prepare('SELECT * FROM candidates WHERE id = ?').get(req.params.id) as
      | { id: string; email: string }
      | undefined;

    if (!candidate) {
      res.status(404).json({ error: 'Candidate not found.' });
      return;
    }

    if (!confirmedEmail || confirmedEmail.trim().toLowerCase() !== candidate.email.toLowerCase()) {
      res.status(400).json({ error: 'Confirmed email does not match candidate email on file.' });
      return;
    }

    const now = new Date().toISOString();
    db.prepare('UPDATE candidates SET email_confirmed_by_recruiter = 1, updated_at = ? WHERE id = ?').run(
      now,
      candidate.id,
    );

    recordAudit(db, {
      actorUserId: actor.id,
      actorLabel: actor.email,
      actorRole: actor.role,
      action: 'CANDIDATE_EMAIL_CONFIRMED',
      entityType: 'candidate',
      entityId: candidate.id,
      afterState: { confirmedEmail: candidate.email },
      ipAddress: getClientIp(req),
    });

    res.json({ ok: true, emailConfirmed: true });
  });

  // Step 2: Send secure document upload invitation (idempotent + hashed token + real email delivery)
  async function issueInvitation(params: {
    req: express.Request;
    candidateId: string;
    purpose: 'initial_upload' | 'reupload';
    targetDocTypes?: string[] | null;
    idempotencyKey?: string;
    rejectionInfo?: { docLabel: string; reason: string };
    revokePrevious?: boolean;
  }) {
    const actor = params.req.authUser!;
    const candidate = db.prepare('SELECT * FROM candidates WHERE id = ?').get(params.candidateId) as
      | {
          id: string;
          full_name: string;
          email: string;
          job_position: string;
          email_confirmed_by_recruiter: number;
          status: string;
        }
      | undefined;

    if (!candidate) {
      return { statusCode: 404, body: { error: 'Candidate not found.' } };
    }

    if (!candidate.email_confirmed_by_recruiter) {
      return {
        statusCode: 400,
        body: { error: 'Please confirm the candidate’s email address before sending the document upload link.' },
      };
    }

    // Idempotency check
    if (params.idempotencyKey) {
      const existingInv = db
        .prepare('SELECT * FROM candidate_invitations WHERE idempotency_key = ?')
        .get(params.idempotencyKey) as Record<string, unknown> | undefined;
      if (existingInv) {
        return {
          statusCode: 200,
          body: {
            deduplicated: true,
            invitation: existingInv,
            emailDelivery: {
              status: existingInv.email_delivery_status,
              error: existingInv.email_delivery_error,
            },
          },
        };
      }
    }

    const policy = db
      .prepare('SELECT candidate_link_expiry_hours FROM security_policies WHERE id = 1')
      .get() as { candidate_link_expiry_hours: number } | undefined;
    const expiryHours = policy?.candidate_link_expiry_hours || config.defaultCandidateLinkExpiryHours;

    const rawToken = generateRandomToken(32);
    const tokenHash = sha256Hex(rawToken);
    const now = new Date();
    const expiresAt = new Date(now.getTime() + expiryHours * 60 * 60 * 1000).toISOString();
    const invId = `inv_${crypto.randomUUID()}`;

    const reqDocs = db
      .prepare('SELECT label FROM document_requirements WHERE is_enabled = 1 ORDER BY sort_order ASC')
      .all() as Array<{ label: string }>;

    const origin = (params.req.headers.origin as string | undefined) || config.appUrl;
    // Public URL carries ONLY the opaque cryptographically random token (no candidate ID!)
    const uploadLink = `${origin.replace(/\/+$/, '')}/candidate-upload?t=${encodeURIComponent(rawToken)}`;

    const emailContent = params.rejectionInfo
      ? buildDocumentRejectionEmail({
          candidateName: candidate.full_name,
          jobPosition: candidate.job_position,
          documentLabel: params.rejectionInfo.docLabel,
          rejectionReason: params.rejectionInfo.reason,
          reuploadLink: uploadLink,
          expiresAtIso: expiresAt,
          supportEmail: config.supportEmail,
        })
      : buildCandidateInvitationEmail({
          candidateName: candidate.full_name,
          jobPosition: candidate.job_position,
          uploadLink,
          expiresAtIso: expiresAt,
          requiredDocLabels: reqDocs.map((d) => d.label),
          supportEmail: config.supportEmail,
        });

    const tx = db.transaction(() => {
      if (params.revokePrevious) {
        db.prepare(`
          UPDATE candidate_invitations
          SET revoked_at = ?, revoke_reason = 'superseded_by_resend'
          WHERE candidate_id = ? AND revoked_at IS NULL AND accepted_at IS NULL
        `).run(now.toISOString(), candidate.id);

        db.prepare(`
          UPDATE candidate_upload_sessions
          SET revoked_at = ?
          WHERE candidate_id = ? AND revoked_at IS NULL
        `).run(now.toISOString(), candidate.id);
      }

      db.prepare(`
        INSERT INTO candidate_invitations (
          id, candidate_id, token_hash, purpose, target_doc_types_json, idempotency_key,
          expires_at, sent_by, sent_to_email, email_delivery_status, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?)
      `).run(
        invId,
        candidate.id,
        tokenHash,
        params.purpose,
        params.targetDocTypes ? JSON.stringify(params.targetDocTypes) : null,
        params.idempotencyKey ?? null,
        expiresAt,
        actor.id,
        candidate.email,
        now.toISOString(),
      );

      if (params.purpose === 'initial_upload' && candidate.status === 'New') {
        db.prepare(`
          UPDATE candidates
          SET status = 'Document Link Sent', doc_verification_status = 'In Progress', updated_at = ?
          WHERE id = ?
        `).run(now.toISOString(), candidate.id);
      }

      recordAudit(db, {
        actorUserId: actor.id,
        actorLabel: actor.email,
        actorRole: actor.role,
        action: params.revokePrevious ? 'CANDIDATE_INVITATION_RESENT' : 'CANDIDATE_INVITATION_SENT',
        entityType: 'candidate_invitation',
        entityId: invId,
        afterState: { candidateId: candidate.id, sentTo: candidate.email, expiresAt, purpose: params.purpose },
        ipAddress: getClientIp(params.req),
      });
    });
    tx();

    const delivery = await emailService.sendEmail({
      to: candidate.email,
      subject: emailContent.subject,
      text: emailContent.text,
      html: emailContent.html,
      templateName: params.rejectionInfo ? 'candidate_reupload' : 'candidate_invitation',
      idempotencyKey: params.idempotencyKey ? `email_${params.idempotencyKey}` : undefined,
      relatedEntityType: 'candidate_invitation',
      relatedEntityId: invId,
    });

    db.prepare(`
      UPDATE candidate_invitations
      SET email_delivery_status = ?, email_delivery_error = ?
      WHERE id = ?
    `).run(delivery.status, delivery.error ?? null, invId);

    const invitation = db
      .prepare('SELECT id, purpose, expires_at, sent_to_email, email_delivery_status, email_delivery_error, created_at FROM candidate_invitations WHERE id = ?')
      .get(invId);

    return {
      statusCode: 201,
      body: {
        invitation,
        emailDelivery: delivery,
        // Never expose raw token in normal list APIs; returned only once at creation time for secure recruiter verification/copy if SMTP isn't configured yet
        uploadLink: delivery.delivered ? undefined : uploadLink,
        rawTokenForTestOnly: process.env.NODE_ENV === 'test' ? rawToken : undefined,
      },
    };
  }

  router.post('/:id/send-invitation', requireRole('HR', 'Admin'), async (req, res) => {
    const { idempotencyKey } = req.body as { idempotencyKey?: string };
    const result = await issueInvitation({
      req,
      candidateId: req.params.id,
      purpose: 'initial_upload',
      idempotencyKey,
      revokePrevious: false,
    });
    res.status(result.statusCode).json(result.body);
  });

  router.post('/:id/resend-invitation', requireRole('HR', 'Admin'), async (req, res) => {
    const { idempotencyKey } = req.body as { idempotencyKey?: string };
    const result = await issueInvitation({
      req,
      candidateId: req.params.id,
      purpose: 'initial_upload',
      idempotencyKey,
      revokePrevious: true,
    });
    res.status(result.statusCode).json(result.body);
  });

  router.post('/:id/revoke-invitation', requireRole('HR', 'Admin'), (req, res) => {
    const actor = req.authUser!;
    const { reason } = req.body as { reason?: string };
    const now = new Date().toISOString();

    const tx = db.transaction(() => {
      db.prepare(`
        UPDATE candidate_invitations
        SET revoked_at = ?, revoke_reason = ?
        WHERE candidate_id = ? AND revoked_at IS NULL
      `).run(now, reason || 'revoked_by_recruiter', req.params.id);

      db.prepare(`
        UPDATE candidate_upload_sessions
        SET revoked_at = ?
        WHERE candidate_id = ? AND revoked_at IS NULL
      `).run(now, req.params.id);

      recordAudit(db, {
        actorUserId: actor.id,
        actorLabel: actor.email,
        actorRole: actor.role,
        action: 'CANDIDATE_INVITATION_REVOKED',
        entityType: 'candidate',
        entityId: req.params.id,
        metadata: { reason: reason || 'revoked_by_recruiter' },
        ipAddress: getClientIp(req),
      });
    });
    tx();

    res.json({ ok: true });
  });

  // Protected download for authenticated HR/Admin/Manager
  router.get('/:id/documents/:docId/download', requireRole('HR', 'Admin', 'Manager'), (req, res) => {
    const doc = db
      .prepare('SELECT * FROM candidate_documents WHERE id = ? AND candidate_id = ?')
      .get(req.params.docId, req.params.id) as
      | { id: string; original_filename: string; stored_filename: string; mime_type: string }
      | undefined;
    if (!doc) {
      res.status(404).json({ error: 'Document not found.' });
      return;
    }

    const fullPath = resolvePrivateDocumentPath(config, doc.stored_filename);
    if (!fs.existsSync(fullPath)) {
      res.status(404).json({ error: 'Document file not found in private storage.' });
      return;
    }

    res.setHeader('Content-Type', doc.mime_type);
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader(
      'Content-Disposition',
      `${req.query.disposition === 'attachment' ? 'attachment' : 'inline'}; filename="${doc.original_filename.replace(/[^a-zA-Z0-9._-]/g, '_')}"`,
    );
    fs.createReadStream(fullPath).pipe(res);
  });

  // Step 6: HR/Recruiter Document Review (Approve / Reject with mandatory reason / Request Re-upload)
  router.post('/:id/documents/:docId/review', requireRole('HR', 'Admin'), async (req, res) => {
    const actor = req.authUser!;
    const { decision, rejectionReason } = req.body as {
      decision?: 'Approved' | 'Rejected' | 'Re-upload Required';
      rejectionReason?: string;
    };

    if (decision !== 'Approved' && decision !== 'Rejected' && decision !== 'Re-upload Required') {
      res.status(400).json({ error: 'Invalid review decision.' });
      return;
    }

    if ((decision === 'Rejected' || decision === 'Re-upload Required') && !rejectionReason?.trim()) {
      res.status(400).json({ error: 'A rejection reason is mandatory when rejecting or requesting re-upload.' });
      return;
    }

    const doc = db
      .prepare(`
        SELECT d.*, r.label AS doc_label
        FROM candidate_documents d
        JOIN document_requirements r ON r.id = d.requirement_id
        WHERE d.id = ? AND d.candidate_id = ? AND d.is_current = 1
      `)
      .get(req.params.docId, req.params.id) as
      | {
          id: string;
          candidate_id: string;
          doc_type: string;
          doc_label: string;
          status: string;
        }
      | undefined;

    if (!doc) {
      res.status(404).json({ error: 'Current document version not found.' });
      return;
    }

    const candidate = db.prepare('SELECT * FROM candidates WHERE id = ?').get(req.params.id) as {
      id: string;
      full_name: string;
      email: string;
      job_position: string;
      assigned_recruiter_id: string;
      status: string;
    };

    const now = new Date().toISOString();
    const targetDocStatus = decision === 'Approved' ? 'Approved' : 'Re-upload Required';

    const tx = db.transaction(() => {
      db.prepare(`
        UPDATE candidate_documents
        SET status = ?, rejection_reason = ?, reviewed_by = ?, reviewed_at = ?
        WHERE id = ?
      `).run(
        targetDocStatus,
        decision === 'Approved' ? null : rejectionReason!.trim(),
        actor.id,
        now,
        doc.id,
      );

      recordAudit(db, {
        actorUserId: actor.id,
        actorLabel: actor.email,
        actorRole: actor.role,
        action: decision === 'Approved' ? 'DOCUMENT_APPROVED' : 'DOCUMENT_REJECTED',
        entityType: 'candidate_document',
        entityId: doc.id,
        beforeState: { status: doc.status, docType: doc.doc_type },
        afterState: {
          status: targetDocStatus,
          docType: doc.doc_type,
          reason: decision === 'Approved' ? null : rejectionReason!.trim(),
        },
        ipAddress: getClientIp(req),
      });
    });
    tx();

    // If rejected/re-upload required -> update candidate status & send fresh targeted re-upload link
    if (decision !== 'Approved') {
      db.prepare(`
        UPDATE candidates
        SET status = 'Re-upload Required', doc_verification_status = 'Action Required', updated_at = ?
        WHERE id = ?
      `).run(now, candidate.id);

      // Collect all currently rejected/re-upload doc types for targeted re-upload
      const rejectedTypes = (
        db
          .prepare(`
            SELECT doc_type FROM candidate_documents
            WHERE candidate_id = ? AND is_current = 1 AND status IN ('Rejected', 'Re-upload Required')
          `)
          .all(candidate.id) as Array<{ doc_type: string }>
      ).map((r) => r.doc_type);

      const invRes = await issueInvitation({
        req,
        candidateId: candidate.id,
        purpose: 'reupload',
        targetDocTypes: rejectedTypes,
        rejectionInfo: {
          docLabel: doc.doc_label,
          reason: rejectionReason!.trim(),
        },
        revokePrevious: true,
      });

      res.json({
        documentStatus: targetDocStatus,
        candidateStatus: 'Re-upload Required',
        reuploadInvitation: invRes.body,
      });
      return;
    }

    // Check if ALL enabled mandatory requirements now have an Approved current document
    const mandatoryReqs = db
      .prepare('SELECT doc_type FROM document_requirements WHERE is_enabled = 1 AND is_mandatory = 1')
      .all() as Array<{ doc_type: string }>;

    const approvedSet = new Set(
      (
        db
          .prepare(`
            SELECT doc_type FROM candidate_documents
            WHERE candidate_id = ? AND is_current = 1 AND status = 'Approved'
          `)
          .all(candidate.id) as Array<{ doc_type: string }>
      ).map((r) => r.doc_type),
    );

    const anyRejected = db
      .prepare(`
        SELECT COUNT(*) AS cnt FROM candidate_documents
        WHERE candidate_id = ? AND is_current = 1 AND status IN ('Rejected', 'Re-upload Required')
      `)
      .get(candidate.id) as { cnt: number };

    const allMandatoryApproved =
      anyRejected.cnt === 0 && mandatoryReqs.every((m) => approvedSet.has(m.doc_type));

    if (allMandatoryApproved) {
      db.prepare(`
        UPDATE candidates
        SET doc_verification_status = 'Completed',
            status = 'Documents Verified – Pending HR Approval',
            updated_at = ?
        WHERE id = ?
      `).run(now, candidate.id);

      // Notify assigned recruiter and all active HR users
      const recipients = db
        .prepare("SELECT id FROM users WHERE is_active = 1 AND (id = ? OR role = 'HR')")
        .all(candidate.assigned_recruiter_id) as Array<{ id: string }>;

      for (const rec of recipients) {
        createNotification(db, {
          recipientUserId: rec.id,
          title: 'Document Verification Completed',
          message: `All mandatory documents for ${candidate.full_name} (${candidate.job_position}) are verified. Ready for HR onboarding approval.`,
          category: 'success',
          relatedEntityType: 'candidate',
          relatedEntityId: candidate.id,
        });
      }

      recordAudit(db, {
        actorUserId: actor.id,
        actorLabel: actor.email,
        actorRole: actor.role,
        action: 'DOCUMENT_VERIFICATION_COMPLETED',
        entityType: 'candidate',
        entityId: candidate.id,
        beforeState: { status: candidate.status },
        afterState: {
          docVerificationStatus: 'Completed',
          status: 'Documents Verified – Pending HR Approval',
        },
        ipAddress: getClientIp(req),
      });

      res.json({
        documentStatus: 'Approved',
        verificationCompleted: true,
        candidateStatus: 'Documents Verified – Pending HR Approval',
      });
      return;
    }

    res.json({
      documentStatus: 'Approved',
      verificationCompleted: false,
      candidateStatus: candidate.status,
    });
  });

  // Preserve Existing Recruitment -> HR Approval -> Offer -> Onboarding -> Employee Creation Workflow
  router.post('/:id/advance-stage', requireRole('HR', 'Admin'), async (req, res) => {
    const actor = req.authUser!;
    const { nextStage, createEmployeeAccount, ctcAnnual, passwordForEmployee } = req.body as {
      nextStage?: 'Offer Extended' | 'Onboarding Approved' | 'Joined' | 'Rejected';
      createEmployeeAccount?: boolean;
      ctcAnnual?: number;
      passwordForEmployee?: string;
    };

    const candidate = db.prepare('SELECT * FROM candidates WHERE id = ?').get(req.params.id) as
      | {
          id: string;
          full_name: string;
          email: string;
          mobile: string;
          job_position: string;
          department: string;
          assigned_recruiter_id: string;
          status: string;
          doc_verification_status: string;
        }
      | undefined;

    if (!candidate) {
      res.status(404).json({ error: 'Candidate not found.' });
      return;
    }

    if (!nextStage) {
      res.status(400).json({ error: 'nextStage is required.' });
      return;
    }

    // Never allow skipping document verification or HR approvals
    if (
      (nextStage === 'Offer Extended' || nextStage === 'Onboarding Approved' || nextStage === 'Joined') &&
      candidate.doc_verification_status !== 'Completed'
    ) {
      res.status(400).json({
        error: 'Cannot advance to Offer or Onboarding before mandatory document verification is Completed.',
      });
      return;
    }

    if (nextStage === 'Onboarding Approved' && candidate.status !== 'Offer Extended' && candidate.status !== 'Documents Verified – Pending HR Approval') {
      res.status(400).json({ error: 'Candidate must complete document verification before HR Onboarding Approval.' });
      return;
    }

    if (nextStage === 'Joined' && candidate.status !== 'Onboarding Approved') {
      res.status(400).json({ error: 'Existing HR Onboarding Approval is required before marking candidate as Joined.' });
      return;
    }

    const now = new Date().toISOString();
    let createdEmployeeId: string | null = null;

    if (nextStage === 'Joined' && createEmployeeAccount) {
      const existingEmp = db
        .prepare('SELECT id FROM employees WHERE source_candidate_id = ? OR lower(email) = ?')
        .get(candidate.id, candidate.email.toLowerCase()) as { id: string } | undefined;
      if (existingEmp) {
        res.status(409).json({
          error: 'An employee record already exists for this candidate. Duplicate employee creation prevented.',
        });
        return;
      }

      if (!passwordForEmployee || passwordForEmployee.length < 10) {
        res.status(400).json({
          error: 'Initial employee account password (minimum 10 characters) is required when creating employee record.',
        });
        return;
      }

      const pwHash = await hashPassword(passwordForEmployee);
      const userId = `usr_${crypto.randomUUID()}`;
      createdEmployeeId = `emp_${crypto.randomUUID()}`;
      const annual = Math.max(0, Number(ctcAnnual || 800000));
      const monthly = Math.round(annual / 12);
      const basic = Math.round(monthly * 0.5);
      const hra = Math.round(monthly * 0.25);
      const allowances = Math.max(0, monthly - basic - hra);
      const empCode = `9HR-${String(Math.floor(1000 + Math.random() * 9000))}`;
      const username = candidate.email.split('@')[0].replace(/[^a-zA-Z0-9._-]/g, '') + Math.floor(10 + Math.random() * 89);

      const tx = db.transaction(() => {
        db.prepare(`
          INSERT INTO users (
            id, username, email, full_name, role, department, designation,
            password_hash, totp_enabled, is_active, created_at, updated_at
          ) VALUES (?, ?, ?, ?, 'Employee', ?, ?, ?, 0, 1, ?, ?)
        `).run(
          userId,
          username.toLowerCase(),
          candidate.email.toLowerCase(),
          candidate.full_name,
          candidate.department,
          candidate.job_position,
          pwHash,
          now,
          now,
        );

        db.prepare(`
          INSERT INTO employees (
            id, user_id, employee_code, full_name, email, mobile, department, designation,
            joining_date, employment_status, ctc_annual, basic_salary, hra, allowances,
            source_candidate_id, created_at, updated_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'Active', ?, ?, ?, ?, ?, ?, ?)
        `).run(
          createdEmployeeId,
          userId,
          empCode,
          candidate.full_name,
          candidate.email.toLowerCase(),
          candidate.mobile,
          candidate.department,
          candidate.job_position,
          now.slice(0, 10),
          annual,
          basic,
          hra,
          allowances,
          candidate.id,
          now,
          now,
        );
      });
      tx();
    }

    db.prepare(`
      UPDATE candidates
      SET status = ?,
          hr_approved_by = CASE WHEN ? IN ('Onboarding Approved', 'Offer Extended') THEN ? ELSE hr_approved_by END,
          hr_approved_at = CASE WHEN ? IN ('Onboarding Approved', 'Offer Extended') THEN ? ELSE hr_approved_at END,
          offer_letter_sent_at = CASE WHEN ? = 'Offer Extended' THEN ? ELSE offer_letter_sent_at END,
          updated_at = ?
      WHERE id = ?
    `).run(nextStage, nextStage, actor.id, nextStage, now, nextStage, now, now, candidate.id);

    recordAudit(db, {
      actorUserId: actor.id,
      actorLabel: actor.email,
      actorRole: actor.role,
      action: 'CANDIDATE_STAGE_ADVANCED',
      entityType: 'candidate',
      entityId: candidate.id,
      beforeState: { status: candidate.status },
      afterState: { status: nextStage, createdEmployeeId },
      ipAddress: getClientIp(req),
    });

    res.json({ ok: true, status: nextStage, createdEmployeeId });
  });

  return router;
}
