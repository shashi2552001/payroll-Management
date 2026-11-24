import type Database from 'better-sqlite3';
import crypto from 'crypto';
import nodemailer, { type Transporter } from 'nodemailer';
import type { AppConfig } from './config.ts';

export interface EmailSendResult {
  delivered: boolean;
  status: 'sent' | 'failed' | 'smtp_not_configured';
  messageId?: string;
  error?: string;
  attempts: number;
  deduplicated?: boolean;
}

export interface EmailService {
  isConfigured(): boolean;
  sendEmail(params: {
    to: string;
    subject: string;
    text: string;
    html: string;
    templateName: string;
    idempotencyKey?: string;
    relatedEntityType?: string;
    relatedEntityId?: string;
  }): Promise<EmailSendResult>;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export function createEmailService(
  db: Database.Database,
  config: AppConfig,
  customTransport?: Transporter,
): EmailService {
  const isConfigured = (): boolean => {
    if (customTransport) return true;
    return Boolean(config.smtp.host && config.smtp.port);
  };

  const getTransport = (): Transporter | null => {
    if (customTransport) return customTransport;
    if (!config.smtp.host) return null;
    return nodemailer.createTransport({
      host: config.smtp.host,
      port: config.smtp.port,
      secure: config.smtp.secure,
      auth:
        config.smtp.user || config.smtp.pass
          ? {
              user: config.smtp.user,
              pass: config.smtp.pass,
            }
          : undefined,
      connectionTimeout: 8000,
      greetingTimeout: 8000,
      socketTimeout: 10000,
    });
  };

  return {
    isConfigured,
    async sendEmail(params) {
      const now = new Date().toISOString();

      if (params.idempotencyKey) {
        const existing = db
          .prepare('SELECT * FROM email_deliveries WHERE idempotency_key = ?')
          .get(params.idempotencyKey) as
          | { status: string; message_id: string | null; error_message: string | null; attempts: number }
          | undefined;
        if (existing && existing.status === 'sent') {
          return {
            delivered: true,
            status: 'sent',
            messageId: existing.message_id || undefined,
            attempts: existing.attempts,
            deduplicated: true,
          };
        }
      }

      const deliveryId = `eml_${crypto.randomUUID()}`;
      const transport = getTransport();

      if (!transport) {
        const errMsg =
          'SMTP email service is not configured. Set SMTP_HOST, SMTP_PORT, SMTP_USER, and SMTP_PASS environment variables.';
        db.prepare(`
          INSERT OR REPLACE INTO email_deliveries (
            id, recipient_email, subject, template_name, idempotency_key,
            attempts, status, message_id, error_message, related_entity_type,
            related_entity_id, created_at, updated_at
          ) VALUES (?, ?, ?, ?, ?, 0, 'smtp_not_configured', NULL, ?, ?, ?, ?, ?)
        `).run(
          deliveryId,
          params.to,
          params.subject,
          params.templateName,
          params.idempotencyKey ?? null,
          errMsg,
          params.relatedEntityType ?? null,
          params.relatedEntityId ?? null,
          now,
          now,
        );
        return {
          delivered: false,
          status: 'smtp_not_configured',
          error: errMsg,
          attempts: 0,
        };
      }

      const maxAttempts = 3;
      let lastError = '';
      let attempts = 0;

      for (let i = 1; i <= maxAttempts; i++) {
        attempts = i;
        try {
          const info = await transport.sendMail({
            from: config.smtp.from,
            to: params.to,
            subject: params.subject,
            text: params.text,
            html: params.html,
          });
          const doneAt = new Date().toISOString();
          db.prepare(`
            INSERT OR REPLACE INTO email_deliveries (
              id, recipient_email, subject, template_name, idempotency_key,
              attempts, status, message_id, error_message, related_entity_type,
              related_entity_id, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, 'sent', ?, NULL, ?, ?, ?, ?)
          `).run(
            deliveryId,
            params.to,
            params.subject,
            params.templateName,
            params.idempotencyKey ?? null,
            attempts,
            info.messageId || null,
            params.relatedEntityType ?? null,
            params.relatedEntityId ?? null,
            now,
            doneAt,
          );
          return {
            delivered: true,
            status: 'sent',
            messageId: info.messageId,
            attempts,
          };
        } catch (err) {
          lastError = err instanceof Error ? err.message : 'Unknown SMTP error';
          if (i < maxAttempts) {
            await sleep(150 * Math.pow(2, i - 1));
          }
        }
      }

      const failAt = new Date().toISOString();
      db.prepare(`
        INSERT OR REPLACE INTO email_deliveries (
          id, recipient_email, subject, template_name, idempotency_key,
          attempts, status, message_id, error_message, related_entity_type,
          related_entity_id, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, 'failed', NULL, ?, ?, ?, ?, ?)
      `).run(
        deliveryId,
        params.to,
        params.subject,
        params.templateName,
        params.idempotencyKey ?? null,
        attempts,
        lastError,
        params.relatedEntityType ?? null,
        params.relatedEntityId ?? null,
        now,
        failAt,
      );

      return {
        delivered: false,
        status: 'failed',
        error: lastError,
        attempts,
      };
    },
  };
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

export function buildCandidateInvitationEmail(params: {
  candidateName: string;
  jobPosition: string;
  uploadLink: string;
  expiresAtIso: string;
  requiredDocLabels: string[];
  supportEmail: string;
}): { subject: string; text: string; html: string } {
  const expiryFormatted = new Date(params.expiresAtIso).toUTCString();
  const docSummary = params.requiredDocLabels.join(', ');
  const subject = 'Action Required – Upload Your Documents for 9HR India';

  const text = [
    `Subject: ${subject}`,
    '',
    `Dear ${params.candidateName},`,
    '',
    `Thank you for your interest in joining 9HR India for the position of ${params.jobPosition}.`,
    '',
    'Please use the secure link below to upload the requested documents required for your recruitment and onboarding process.',
    '',
    `Requested Documents: ${docSummary}`,
    '',
    params.uploadLink,
    '',
    `Link Expiry: ${expiryFormatted}`,
    `Support Contact: ${params.supportEmail}`,
    '',
    'Please complete the upload before the mentioned expiry date.',
    '',
    'Regards,',
    'HR Team – 9HR India',
  ].join('\n');

  const docItemsHtml = params.requiredDocLabels
    .map((d) => `<li style="margin:4px 0;color:#334155;">${escapeHtml(d)}</li>`)
    .join('');

  const html = `
    <div style="font-family:'Plus Jakarta Sans',Arial,sans-serif;max-width:600px;margin:0 auto;padding:24px;background:#f8fafc;color:#0f172a;">
      <div style="background:#ffffff;border:1px solid #e2e8f0;border-radius:12px;padding:32px;">
        <div style="font-size:20px;font-weight:700;color:#0b131e;margin-bottom:4px;">9HR India</div>
        <div style="font-size:13px;color:#64748b;margin-bottom:24px;">Secure Candidate Onboarding &amp; Document Verification</div>
        <p style="font-size:15px;line-height:1.6;">Dear ${escapeHtml(params.candidateName)},</p>
        <p style="font-size:15px;line-height:1.6;">Thank you for your interest in joining <strong>9HR India</strong> for the role of <strong>${escapeHtml(params.jobPosition)}</strong>.</p>
        <p style="font-size:15px;line-height:1.6;">Please use the secure link below to upload the requested documents required for your recruitment and onboarding process.</p>
        <div style="margin:20px 0;padding:16px;background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;">
          <div style="font-size:13px;font-weight:600;color:#0f172a;margin-bottom:8px;">Requested Documents:</div>
          <ul style="margin:0;padding-left:18px;font-size:13px;">${docItemsHtml}</ul>
        </div>
        <div style="margin:24px 0;">
          <a href="${escapeHtml(params.uploadLink)}" style="display:inline-block;background:#1d4ed8;color:#ffffff;text-decoration:none;font-weight:600;font-size:14px;padding:12px 24px;border-radius:8px;">Open Secure Upload Portal</a>
        </div>
        <p style="font-size:13px;color:#475569;line-height:1.5;">
          <strong>Link Expires:</strong> ${escapeHtml(expiryFormatted)}<br />
          <strong>Support Contact:</strong> ${escapeHtml(params.supportEmail)}
        </p>
        <p style="font-size:14px;color:#334155;margin-top:20px;">Please complete the upload before the mentioned expiry date.</p>
        <p style="font-size:14px;color:#0f172a;margin-top:24px;">Regards,<br /><strong>HR Team – 9HR India</strong></p>
      </div>
    </div>
  `;

  return { subject, text, html };
}

export function buildRecruiterSubmissionEmail(params: {
  recruiterName: string;
  candidateName: string;
  jobPosition: string;
  submittedAtIso: string;
  documentCount: number;
  candidateRecordUrl: string;
}): { subject: string; text: string; html: string } {
  const subject = `Documents Submitted – ${params.candidateName} (${params.jobPosition})`;
  const text = [
    `Hello ${params.recruiterName},`,
    '',
    `${params.candidateName} (${params.jobPosition}) has submitted ${params.documentCount} document(s) on ${new Date(params.submittedAtIso).toUTCString()}.`,
    'Status: Documents Submitted – Pending HR Verification',
    '',
    `Review Candidate Record: ${params.candidateRecordUrl}`,
    '',
    'Regards,',
    '9HR India Security & Onboarding System',
  ].join('\n');

  const html = `
    <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;padding:24px;background:#f8fafc;color:#0f172a;">
      <div style="background:#ffffff;border:1px solid #e2e8f0;border-radius:12px;padding:28px;">
        <h2 style="margin:0 0 12px 0;font-size:18px;">Candidate Documents Submitted</h2>
        <p style="font-size:14px;line-height:1.6;">Hello ${escapeHtml(params.recruiterName)},</p>
        <p style="font-size:14px;line-height:1.6;"><strong>${escapeHtml(params.candidateName)}</strong> (${escapeHtml(params.jobPosition)}) has uploaded and submitted <strong>${params.documentCount}</strong> document(s) for verification.</p>
        <p style="font-size:13px;color:#475569;">Submitted at: ${escapeHtml(new Date(params.submittedAtIso).toUTCString())}</p>
        <div style="margin:20px 0;">
          <a href="${escapeHtml(params.candidateRecordUrl)}" style="display:inline-block;background:#1d4ed8;color:#ffffff;text-decoration:none;font-weight:600;font-size:14px;padding:10px 20px;border-radius:8px;">Open Candidate Record</a>
        </div>
      </div>
    </div>
  `;

  return { subject, text, html };
}

export function buildDocumentRejectionEmail(params: {
  candidateName: string;
  jobPosition: string;
  documentLabel: string;
  rejectionReason: string;
  reuploadLink: string;
  expiresAtIso: string;
  supportEmail: string;
}): { subject: string; text: string; html: string } {
  const subject = `Action Required – Re-upload ${params.documentLabel} for 9HR India`;
  const text = [
    `Dear ${params.candidateName},`,
    '',
    `During document verification for ${params.jobPosition} at 9HR India, the following document requires re-upload:`,
    `Document: ${params.documentLabel}`,
    `Reason: ${params.rejectionReason}`,
    '',
    'Any previously approved documents remain approved. You only need to re-upload the rejected document using the secure link below:',
    params.reuploadLink,
    '',
    `Link Expires: ${new Date(params.expiresAtIso).toUTCString()}`,
    `Support Contact: ${params.supportEmail}`,
    '',
    'Regards,',
    'HR Team – 9HR India',
  ].join('\n');

  const html = `
    <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;padding:24px;background:#f8fafc;color:#0f172a;">
      <div style="background:#ffffff;border:1px solid #e2e8f0;border-radius:12px;padding:28px;">
        <h2 style="margin:0 0 12px 0;font-size:18px;color:#0f172a;">Document Re-upload Required</h2>
        <p style="font-size:14px;line-height:1.6;">Dear ${escapeHtml(params.candidateName)},</p>
        <p style="font-size:14px;line-height:1.6;">Please re-upload the following document for your <strong>${escapeHtml(params.jobPosition)}</strong> onboarding with 9HR India:</p>
        <div style="margin:16px 0;padding:14px;background:#fef2f2;border:1px solid #fecaca;border-radius:8px;">
          <div style="font-size:14px;font-weight:600;color:#991b1b;">${escapeHtml(params.documentLabel)}</div>
          <div style="font-size:13px;color:#7f1d1d;margin-top:4px;">Reason: ${escapeHtml(params.rejectionReason)}</div>
        </div>
        <p style="font-size:13px;color:#334155;">All previously approved documents remain approved. Only the document listed above requires re-upload.</p>
        <div style="margin:20px 0;">
          <a href="${escapeHtml(params.reuploadLink)}" style="display:inline-block;background:#1d4ed8;color:#ffffff;text-decoration:none;font-weight:600;font-size:14px;padding:10px 20px;border-radius:8px;">Re-upload Document</a>
        </div>
        <p style="font-size:12px;color:#64748b;">Link Expires: ${escapeHtml(new Date(params.expiresAtIso).toUTCString())} · Support: ${escapeHtml(params.supportEmail)}</p>
      </div>
    </div>
  `;

  return { subject, text, html };
}

export function buildPasswordResetEmail(params: {
  fullName: string;
  resetLink: string;
  expiresMinutes: number;
  supportEmail: string;
}): { subject: string; text: string; html: string } {
  const subject = '9HR India – Password Reset Request';
  const text = [
    `Hello ${params.fullName},`,
    '',
    'We received a request to reset your 9HR India account password.',
    `Use the secure link below within ${params.expiresMinutes} minutes:`,
    params.resetLink,
    '',
    'If you did not request this reset, please ignore this message and contact IT Security.',
    `Support: ${params.supportEmail}`,
  ].join('\n');

  const html = `
    <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;padding:24px;background:#f8fafc;color:#0f172a;">
      <div style="background:#ffffff;border:1px solid #e2e8f0;border-radius:12px;padding:28px;">
        <h2 style="margin:0 0 12px 0;font-size:18px;">9HR India Password Reset</h2>
        <p style="font-size:14px;line-height:1.6;">Hello ${escapeHtml(params.fullName)},</p>
        <p style="font-size:14px;line-height:1.6;">Use the link below to reset your password. This link expires in ${params.expiresMinutes} minutes and can only be used once.</p>
        <div style="margin:20px 0;">
          <a href="${escapeHtml(params.resetLink)}" style="display:inline-block;background:#1d4ed8;color:#ffffff;text-decoration:none;font-weight:600;font-size:14px;padding:10px 20px;border-radius:8px;">Reset Password</a>
        </div>
        <p style="font-size:12px;color:#64748b;">If you did not request a password reset, contact ${escapeHtml(params.supportEmail)}.</p>
      </div>
    </div>
  `;

  return { subject, text, html };
}
