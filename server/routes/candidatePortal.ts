import type Database from 'better-sqlite3';
import crypto from 'crypto';
import express from 'express';
import multer from 'multer';
import path from 'path';
import { createNotification, recordAudit } from '../audit.ts';
import type { AppConfig } from '../config.ts';
import { generateRandomToken, sha256BufferHex, sha256Hex } from '../crypto.ts';
import { buildRecruiterSubmissionEmail, type EmailService } from '../email.ts';
import { savePrivateDocument, validateAndScanUpload } from '../fileSecurity.ts';
import {
  COOKIE_CANDIDATE_SESSION,
  createAuthMiddleware,
  createRateLimiter,
  getClientIp,
  setSecureCookie,
} from '../middleware.ts';

export function createCandidatePortalRouter(
  db: Database.Database,
  config: AppConfig,
  emailService: EmailService,
): express.Router {
  const router = express.Router();
  const { requireCandidateSession } = createAuthMiddleware(db, config);

  const acceptLimiter = createRateLimiter({
    windowMs: 60_000,
    maxRequests: 25,
    keyPrefix: 'cand_accept',
  });
  const uploadLimiter = createRateLimiter({
    windowMs: 60_000,
    maxRequests: 30,
    keyPrefix: 'cand_upload',
  });

  const upload = multer({
    storage: multer.memoryStorage(),
    limits: {
      fileSize: 26 * 1024 * 1024, // hard ceiling; per-requirement & policy limits enforced in handler
      files: 1,
    },
  });

  // Step 3: Single-use invitation token acceptance -> exchanges for isolated HTTP-only candidate upload session
  router.post('/accept-invitation', acceptLimiter, (req, res) => {
    const { token } = req.body as { token?: string };
    if (!token?.trim()) {
      res.status(400).json({ error: 'Invitation token is required.' });
      return;
    }

    const tokenHash = sha256Hex(token.trim());
    const inv = db
      .prepare(`
        SELECT i.*, c.full_name, c.job_position, c.department
        FROM candidate_invitations i
        JOIN candidates c ON c.id = i.candidate_id
        WHERE i.token_hash = ?
      `)
      .get(tokenHash) as
      | {
          id: string;
          candidate_id: string;
          purpose: 'initial_upload' | 'reupload';
          expires_at: string;
          accepted_at: string | null;
          revoked_at: string | null;
          full_name: string;
          job_position: string;
          department: string;
        }
      | undefined;

    if (!inv) {
      res.status(404).json({ error: 'This upload invitation link is invalid.' });
      return;
    }

    if (inv.revoked_at) {
      res.status(410).json({ error: 'This upload invitation link has been revoked by HR.' });
      return;
    }

    if (new Date(inv.expires_at).getTime() <= Date.now()) {
      recordAudit(db, {
        actorLabel: `candidate:${inv.candidate_id}`,
        actorRole: 'Candidate',
        action: 'CANDIDATE_INVITATION_EXPIRED_REJECTED',
        entityType: 'candidate_invitation',
        entityId: inv.id,
        ipAddress: getClientIp(req),
      });
      res.status(410).json({
        error: `This upload invitation link has expired. Please contact ${config.supportEmail} for a new link.`,
      });
      return;
    }

    // Single-use invitation token enforcement
    if (inv.accepted_at) {
      res.status(410).json({
        error: 'This single-use invitation link has already been redeemed. If you need a fresh link, contact HR.',
      });
      return;
    }

    const now = new Date();
    const sessionTokenRaw = generateRandomToken(32);
    const sessionTokenHash = sha256Hex(sessionTokenRaw);
    const sessionId = `cses_${crypto.randomUUID()}`;
    const sessionExpires = new Date(
      Math.min(
        new Date(inv.expires_at).getTime(),
        now.getTime() + 12 * 60 * 60 * 1000,
      ),
    );

    const tx = db.transaction(() => {
      const updated = db
        .prepare(`
          UPDATE candidate_invitations
          SET accepted_at = ?
          WHERE id = ? AND accepted_at IS NULL AND revoked_at IS NULL
        `)
        .run(now.toISOString(), inv.id);

      if (updated.changes !== 1) {
        throw new Error('INVITATION_ALREADY_USED');
      }

      db.prepare(`
        INSERT INTO candidate_upload_sessions (
          id, candidate_id, invitation_id, session_token_hash, ip_address, user_agent, expires_at, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        sessionId,
        inv.candidate_id,
        inv.id,
        sessionTokenHash,
        getClientIp(req),
        String(req.headers['user-agent'] || '').slice(0, 250),
        sessionExpires.toISOString(),
        now.toISOString(),
      );

      recordAudit(db, {
        actorLabel: inv.full_name,
        actorRole: 'Candidate',
        action: 'CANDIDATE_INVITATION_ACCEPTED',
        entityType: 'candidate_invitation',
        entityId: inv.id,
        ipAddress: getClientIp(req),
      });
    });

    try {
      tx();
    } catch {
      res.status(410).json({ error: 'This single-use invitation link has already been redeemed.' });
      return;
    }

    setSecureCookie(
      req,
      res,
      COOKIE_CANDIDATE_SESSION,
      sessionTokenRaw,
      Math.max(60_000, sessionExpires.getTime() - now.getTime()),
    );

    res.json({
      authenticated: true,
      candidateName: inv.full_name,
      jobPosition: inv.job_position,
      department: inv.department,
      purpose: inv.purpose,
    });
  });

  // Get ONLY this candidate's checklist and document status (never internal candidate IDs or other candidates!)
  router.get('/session', requireCandidateSession, (req, res) => {
    const ses = req.candidateSession!;
    const candidate = db
      .prepare('SELECT full_name, job_position, department, status, doc_verification_status FROM candidates WHERE id = ?')
      .get(ses.candidateId) as
      | {
          full_name: string;
          job_position: string;
          department: string;
          status: string;
          doc_verification_status: string;
        }
      | undefined;

    if (!candidate) {
      res.status(404).json({ error: 'Candidate session unavailable.' });
      return;
    }

    const policy = db
      .prepare('SELECT max_upload_size_mb FROM security_policies WHERE id = 1')
      .get() as { max_upload_size_mb: number } | undefined;

    const requirements = db
      .prepare('SELECT id, doc_type, label, description, is_mandatory, allowed_extensions, max_size_mb FROM document_requirements WHERE is_enabled = 1 ORDER BY sort_order ASC')
      .all() as Array<{
      id: string;
      doc_type: string;
      label: string;
      description: string;
      is_mandatory: number;
      allowed_extensions: string;
      max_size_mb: number;
    }>;

    const docs = db
      .prepare(`
        SELECT doc_type, original_filename, mime_type, file_size_bytes, status, rejection_reason, version, uploaded_at
        FROM candidate_documents
        WHERE candidate_id = ? AND is_current = 1
      `)
      .all(ses.candidateId) as Array<{
      doc_type: string;
      original_filename: string;
      mime_type: string;
      file_size_bytes: number;
      status: string;
      rejection_reason: string | null;
      version: number;
      uploaded_at: string;
    }>;

    const docMap = new Map(docs.map((d) => [d.doc_type, d]));

    const checklist = requirements.map((r) => {
      const current = docMap.get(r.doc_type) || null;
      const isApprovedLocked = current?.status === 'Approved';
      const canUpload = !isApprovedLocked;
      return {
        docType: r.doc_type,
        label: r.label,
        description: r.description,
        isMandatory: Boolean(r.is_mandatory),
        maxSizeMb: Math.min(r.max_size_mb, policy?.max_upload_size_mb || 5),
        allowedExtensions: r.allowed_extensions,
        status: current ? current.status : 'Pending',
        rejectionReason: current?.rejection_reason || null,
        uploadedFile: current
          ? {
              filename: current.original_filename,
              sizeBytes: current.file_size_bytes,
              version: current.version,
              uploadedAt: current.uploaded_at,
            }
          : null,
        canUpload,
      };
    });

    res.json({
      candidate: {
        fullName: candidate.full_name,
        jobPosition: candidate.job_position,
        department: candidate.department,
        status: candidate.status,
        docVerificationStatus: candidate.doc_verification_status,
      },
      purpose: ses.purpose,
      supportEmail: config.supportEmail,
      checklist,
    });
  });

  // Step 4: Upload document with extension + MIME + magic bytes + malware scan + private storage + versioning
  router.post('/upload', requireCandidateSession, uploadLimiter, upload.single('file'), async (req, res) => {
    const ses = req.candidateSession!;
    const docType = String(req.body?.docType || '').trim();
    const file = req.file;

    if (!docType || !file) {
      res.status(400).json({ error: 'Both docType and file are required.' });
      return;
    }

    const reqItem = db
      .prepare('SELECT * FROM document_requirements WHERE doc_type = ? AND is_enabled = 1')
      .get(docType) as
      | { id: string; doc_type: string; label: string; max_size_mb: number }
      | undefined;

    if (!reqItem) {
      res.status(400).json({ error: 'Requested document type is not configured or enabled.' });
      return;
    }

    const currentDoc = db
      .prepare(`
        SELECT id, status, version FROM candidate_documents
        WHERE candidate_id = ? AND doc_type = ? AND is_current = 1
      `)
      .get(ses.candidateId, docType) as { id: string; status: string; version: number } | undefined;

    // Approved documents MUST remain approved and cannot be overwritten
    if (currentDoc && currentDoc.status === 'Approved') {
      res.status(409).json({
        error: `${reqItem.label} has already been verified and approved by HR and does not need re-uploading.`,
      });
      return;
    }

    // If session is reupload-only, prevent modifying unrelated non-rejected documents if already submitted
    if (
      ses.purpose === 'reupload' &&
      ses.targetDocTypes &&
      ses.targetDocTypes.length > 0 &&
      currentDoc &&
      currentDoc.status !== 'Rejected' &&
      currentDoc.status !== 'Re-upload Required'
    ) {
      res.status(403).json({
        error: 'Only rejected documents may be replaced during a re-upload session.',
      });
      return;
    }

    const policy = db
      .prepare('SELECT max_upload_size_mb FROM security_policies WHERE id = 1')
      .get() as { max_upload_size_mb: number } | undefined;
    const effectiveMaxMb = Math.min(reqItem.max_size_mb, policy?.max_upload_size_mb || config.defaultMaxUploadSizeMb);

    const scan = await validateAndScanUpload(
      {
        originalname: file.originalname,
        mimetype: file.mimetype,
        buffer: file.buffer,
        size: file.size,
      },
      effectiveMaxMb,
      config,
    );

    if (!scan.safe) {
      recordAudit(db, {
        actorLabel: `candidate:${ses.candidateId}`,
        actorRole: 'Candidate',
        action: 'DOCUMENT_UPLOAD_BLOCKED_SECURITY',
        entityType: 'candidate',
        entityId: ses.candidateId,
        metadata: {
          docType,
          filename: path.basename(file.originalname),
          reason: scan.reason,
          scanner: scan.scanner,
        },
        ipAddress: getClientIp(req),
      });
      res.status(422).json({ error: scan.reason || 'File rejected by security scanner.' });
      return;
    }

    const ext = scan.detectedType === 'pdf' ? 'pdf' : scan.detectedType === 'jpg' ? 'jpg' : 'png';
    const saved = savePrivateDocument(config, file.buffer, ext);
    const fileSha = sha256BufferHex(file.buffer);
    const nextVersion = currentDoc ? currentDoc.version + 1 : 1;
    const docId = `doc_${crypto.randomUUID()}`;
    const now = new Date().toISOString();

    const tx = db.transaction(() => {
      if (currentDoc) {
        db.prepare('UPDATE candidate_documents SET is_current = 0 WHERE id = ?').run(currentDoc.id);
      }

      db.prepare(`
        INSERT INTO candidate_documents (
          id, candidate_id, requirement_id, doc_type, original_filename, stored_filename,
          mime_type, file_size_bytes, sha256_hash, malware_scan_status, malware_scan_detail,
          status, version, is_current, uploaded_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'clean', ?, 'Uploaded', ?, 1, ?)
      `).run(
        docId,
        ses.candidateId,
        reqItem.id,
        docType,
        path.basename(file.originalname).slice(0, 180),
        saved.storedFilename,
        scan.detectedMime,
        file.size,
        fileSha,
        scan.scanner,
        nextVersion,
        now,
      );

      recordAudit(db, {
        actorLabel: `candidate:${ses.candidateId}`,
        actorRole: 'Candidate',
        action: currentDoc ? 'CANDIDATE_DOCUMENT_REPLACED' : 'CANDIDATE_DOCUMENT_UPLOADED',
        entityType: 'candidate_document',
        entityId: docId,
        afterState: {
          docType,
          version: nextVersion,
          sizeBytes: file.size,
          sha256: fileSha,
          scanner: scan.scanner,
        },
        ipAddress: getClientIp(req),
      });
    });
    tx();

    res.status(201).json({
      ok: true,
      document: {
        docType,
        filename: path.basename(file.originalname),
        sizeBytes: file.size,
        status: 'Uploaded',
        version: nextVersion,
        uploadedAt: now,
      },
    });
  });

  // Step 5: Candidate submits uploaded documents -> updates candidate status + notifies recruiter in-app & email
  router.post('/submit', requireCandidateSession, async (req, res) => {
    const ses = req.candidateSession!;

    const candidate = db
      .prepare(`
        SELECT c.*, u.full_name AS recruiter_name, u.email AS recruiter_email
        FROM candidates c
        JOIN users u ON u.id = c.assigned_recruiter_id
        WHERE c.id = ?
      `)
      .get(ses.candidateId) as
      | {
          id: string;
          full_name: string;
          job_position: string;
          assigned_recruiter_id: string;
          recruiter_name: string;
          recruiter_email: string;
          status: string;
        }
      | undefined;

    if (!candidate) {
      res.status(404).json({ error: 'Candidate not found.' });
      return;
    }

    const mandatoryReqs = db
      .prepare('SELECT doc_type, label FROM document_requirements WHERE is_enabled = 1 AND is_mandatory = 1')
      .all() as Array<{ doc_type: string; label: string }>;

    const currentDocs = db
      .prepare(`
        SELECT doc_type, original_filename, status, version
        FROM candidate_documents
        WHERE candidate_id = ? AND is_current = 1
      `)
      .all(ses.candidateId) as Array<{
      doc_type: string;
      original_filename: string;
      status: string;
      version: number;
    }>;

    const validSubmittedSet = new Set(
      currentDocs
        .filter((d) => d.status === 'Uploaded' || d.status === 'Approved')
        .map((d) => d.doc_type),
    );

    const missing = mandatoryReqs.filter((m) => !validSubmittedSet.has(m.doc_type));
    if (missing.length > 0) {
      res.status(400).json({
        error: `Please upload all mandatory documents before submitting: ${missing.map((m) => m.label).join(', ')}`,
      });
      return;
    }

    const now = new Date().toISOString();
    const tx = db.transaction(() => {
      db.prepare(`
        UPDATE candidates
        SET status = 'Documents Submitted – Pending HR Verification',
            doc_verification_status = 'Submitted',
            updated_at = ?
        WHERE id = ?
      `).run(now, candidate.id);

      db.prepare('UPDATE candidate_upload_sessions SET submitted_at = ? WHERE id = ?').run(
        now,
        ses.sessionId,
      );

      createNotification(db, {
        recipientUserId: candidate.assigned_recruiter_id,
        title: 'Candidate Documents Submitted',
        message: `${candidate.full_name} (${candidate.job_position}) submitted ${currentDocs.length} document(s) for HR verification.`,
        category: 'action',
        relatedEntityType: 'candidate',
        relatedEntityId: candidate.id,
      });

      recordAudit(db, {
        actorLabel: candidate.full_name,
        actorRole: 'Candidate',
        action: 'CANDIDATE_DOCUMENTS_SUBMITTED',
        entityType: 'candidate',
        entityId: candidate.id,
        beforeState: { status: candidate.status },
        afterState: {
          status: 'Documents Submitted – Pending HR Verification',
          documentCount: currentDocs.length,
        },
        ipAddress: getClientIp(req),
      });
    });
    tx();

    const origin = (req.headers.origin as string | undefined) || config.appUrl;
    const candidateRecordUrl = `${origin.replace(/\/+$/, '')}/?section=recruitment&candidate=${encodeURIComponent(candidate.id)}`;
    const tpl = buildRecruiterSubmissionEmail({
      recruiterName: candidate.recruiter_name,
      candidateName: candidate.full_name,
      jobPosition: candidate.job_position,
      submittedAtIso: now,
      documentCount: currentDocs.length,
      candidateRecordUrl,
    });

    await emailService.sendEmail({
      to: candidate.recruiter_email,
      subject: tpl.subject,
      text: tpl.text,
      html: tpl.html,
      templateName: 'recruiter_submission_notification',
      idempotencyKey: `submit_${ses.sessionId}_${currentDocs.length}`,
      relatedEntityType: 'candidate',
      relatedEntityId: candidate.id,
    });

    res.json({
      submitted: true,
      status: 'Documents Submitted – Pending HR Verification',
      submittedAt: now,
      documentCount: currentDocs.length,
      documents: currentDocs,
    });
  });

  return router;
}
