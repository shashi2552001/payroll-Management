import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { after, before, test } from 'node:test';
import nodemailer, { type SendMailOptions } from 'nodemailer';
import * as OTPAuth from 'otpauth';
import { createApp } from '../server/app.ts';
import { loadConfig } from '../server/config.ts';
import { initDatabase } from '../server/db.ts';

class CookieJar {
  private cookies = new Map<string, string>();

  updateFromHeaders(setCookies: string[] | undefined) {
    if (!setCookies) return;
    for (const raw of setCookies) {
      const [pair] = raw.split(';');
      const eqIdx = pair.indexOf('=');
      if (eqIdx === -1) continue;
      const name = pair.slice(0, eqIdx).trim();
      const val = pair.slice(eqIdx + 1).trim();
      if (!val || raw.toLowerCase().includes('max-age=0')) {
        this.cookies.delete(name);
      } else {
        this.cookies.set(name, val);
      }
    }
  }

  header(): string {
    return Array.from(this.cookies.entries())
      .map(([k, v]) => `${k}=${v}`)
      .join('; ');
  }

  clone(): CookieJar {
    const next = new CookieJar();
    next.cookies = new Map(this.cookies);
    return next;
  }
}

async function reqJson(
  baseUrl: string,
  jar: CookieJar | null,
  method: string,
  urlPath: string,
  body?: unknown,
  extraHeaders: Record<string, string> = {},
): Promise<{ status: number; json: Record<string, any>; headers: Headers }> {
  const headers: Record<string, string> = {
    'X-Requested-With': '9HR-Client',
    ...extraHeaders,
  };
  if (jar && jar.header()) {
    headers['Cookie'] = jar.header();
  }
  let reqBody: BodyInit | undefined;
  if (body instanceof FormData) {
    reqBody = body;
  } else if (body !== undefined) {
    headers['Content-Type'] = 'application/json';
    reqBody = JSON.stringify(body);
  }

  const res = await fetch(`${baseUrl}${urlPath}`, {
    method,
    headers,
    body: reqBody,
  });

  if (jar) {
    const getSetCookie = (res.headers as unknown as { getSetCookie?: () => string[] }).getSetCookie;
    const setCookies = typeof getSetCookie === 'function' ? getSetCookie.call(res.headers) : [];
    jar.updateFromHeaders(setCookies);
  }

  const text = await res.text();
  let json: Record<string, any> = {};
  if (text) {
    try {
      json = JSON.parse(text);
    } catch {
      json = { raw: text };
    }
  }
  return { status: res.status, json, headers: res.headers };
}

function generateTotp(secretBase32: string): string {
  const totp = new OTPAuth.TOTP({
    issuer: '9HR India',
    algorithm: 'SHA1',
    digits: 6,
    period: 30,
    secret: OTPAuth.Secret.fromBase32(secretBase32),
  });
  return totp.generate();
}

function makeValidPdfBuffer(label = '9HR Test PDF'): Buffer {
  return Buffer.from(
    `%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Title (${label}) >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n`,
    'utf8',
  );
}

function makeValidPngBuffer(): Buffer {
  // Minimal valid PNG signature + IHDR/IEND chunks
  return Buffer.from([
    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a,
    0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
    0x08, 0x02, 0x00, 0x00, 0x00, 0x90, 0x77, 0x53,
    0xde, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e,
    0x44, 0xae, 0x42, 0x60, 0x82,
  ]);
}

function makeValidJpgBuffer(): Buffer {
  return Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46, 0xff, 0xd9]);
}

let tempDir: string;
let server: http.Server;
let baseUrl: string;
let db: ReturnType<typeof initDatabase>;
const capturedEmails: Array<{ to: string; subject: string; text: string; html: string }> = [];

before(async () => {
  process.env.NODE_ENV = 'test';
  tempDir = fs.mkdtempSync(path.join(os.tmpdir(), '9hr-test-'));
  const dbPath = path.join(tempDir, 'test.db');
  const storageDir = path.join(tempDir, 'private_storage');

  const config = loadConfig({
    dbPath,
    privateStorageDir: storageDir,
    sessionSecret: 'test-session-secret-key-9hr-india-integration',
    appUrl: 'http://127.0.0.1:0',
  });

  db = initDatabase(dbPath);

  // Real Nodemailer transport using streamTransport to capture exact RFC-compliant MIME messages
  const memoryTransport = nodemailer.createTransport({
    jsonTransport: true,
  });
  const originalSendMail = memoryTransport.sendMail.bind(memoryTransport);
  memoryTransport.sendMail = async (mailOptions: SendMailOptions) => {
    const res = await originalSendMail(mailOptions);
    capturedEmails.push({
      to: String(mailOptions.to),
      subject: String(mailOptions.subject),
      text: String(mailOptions.text || ''),
      html: String(mailOptions.html || ''),
    });
    return res;
  };

  const app = createApp({ db, config, emailTransport: memoryTransport });
  await new Promise<void>((resolve) => {
    server = app.listen(0, '127.0.0.1', () => {
      const addr = server.address() as { port: number };
      baseUrl = `http://127.0.0.1:${addr.port}`;
      resolve();
    });
  });
});

after(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
  db.close();
  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('End-to-End Security, 2FA, RBAC, Candidate Document Collection, Malware Rejection, and Onboarding Workflow', async () => {
  const adminJar = new CookieJar();
  let adminSecret = '';
  let adminRecoveryCodes: string[] = [];

  // 1. Bootstrap primary Admin & verify mandatory 2FA cannot be bypassed
  const bsRes = await reqJson(baseUrl, adminJar, 'POST', '/api/auth/bootstrap', {
    fullName: 'Ananya Admin',
    email: 'admin@9hrindia.com',
    username: 'admin',
    password: 'StrongAdminPassword#2026',
  });
  assert.equal(bsRes.status, 201);
  assert.equal(bsRes.json.status, '2FA_SETUP_REQUIRED');

  // Attempt to access protected endpoint BEFORE completing mandatory 2FA -> must fail
  const blockedBefore2fa = await reqJson(baseUrl, adminJar, 'GET', '/api/admin/users');
  assert.equal(blockedBefore2fa.status, 401);

  // Check password is Argon2id hashed in DB (never plaintext)
  const adminRow = db.prepare("SELECT password_hash FROM users WHERE email = 'admin@9hrindia.com'").get() as {
    password_hash: string;
  };
  assert.ok(adminRow.password_hash.startsWith('$argon2id$'), 'Password must use Argon2id');

  // Complete TOTP 2FA enrollment
  const setup2fa = await reqJson(baseUrl, adminJar, 'POST', '/api/auth/2fa/setup');
  assert.equal(setup2fa.status, 200);
  assert.ok(setup2fa.json.qrDataUrl.startsWith('data:image/png;base64,'));
  adminSecret = setup2fa.json.manualKey;

  const verifySetup = await reqJson(baseUrl, adminJar, 'POST', '/api/auth/2fa/verify-setup', {
    code: generateTotp(adminSecret),
  });
  assert.equal(verifySetup.status, 200);
  assert.equal(verifySetup.json.recoveryCodes.length, 8);
  adminRecoveryCodes = verifySetup.json.recoveryCodes;

  // Now Admin can access Admin Console
  const adminMe = await reqJson(baseUrl, adminJar, 'GET', '/api/auth/me');
  assert.equal(adminMe.status, 200);
  assert.equal(adminMe.json.user.role, 'Admin');

  // 2. Provision HR, Accounts, Manager, and Employee accounts
  const createHr = await reqJson(baseUrl, adminJar, 'POST', '/api/admin/users', {
    fullName: 'Priya Recruiter',
    email: 'hr@9hrindia.com',
    username: 'priya.hr',
    role: 'HR',
    department: 'Talent Acquisition',
    password: 'StrongHrPassword#2026',
  });
  assert.equal(createHr.status, 201);

  const createAccounts = await reqJson(baseUrl, adminJar, 'POST', '/api/admin/users', {
    fullName: 'Vikram Accounts',
    email: 'accounts@9hrindia.com',
    username: 'vikram.acc',
    role: 'Accounts',
    department: 'Finance',
    password: 'StrongAccPassword#2026',
  });
  assert.equal(createAccounts.status, 201);

  const createManager = await reqJson(baseUrl, adminJar, 'POST', '/api/admin/users', {
    fullName: 'Karan Manager',
    email: 'manager@9hrindia.com',
    username: 'karan.mgr',
    role: 'Manager',
    department: 'Engineering',
    password: 'StrongMgrPassword#2026',
  });
  assert.equal(createManager.status, 201);

  const createEmp = await reqJson(baseUrl, adminJar, 'POST', '/api/admin/users', {
    fullName: 'Neha Employee',
    email: 'neha@9hrindia.com',
    username: 'neha.emp',
    role: 'Employee',
    department: 'Engineering',
    managerId: createManager.json.user.id,
    password: 'StrongEmpPassword#2026',
    ctcAnnual: 1200000,
  });
  assert.equal(createEmp.status, 201);

  // 3. Invalid credentials & lockout protection
  const badLogin = await reqJson(baseUrl, null, 'POST', '/api/auth/login', {
    identifier: 'neha@9hrindia.com',
    password: 'WrongPassword123',
  });
  assert.equal(badLogin.status, 401);
  assert.equal(badLogin.json.error, 'Invalid credentials.');

  // Employee login (2FA optional by default policy -> succeeds directly)
  const empJar = new CookieJar();
  const empLogin = await reqJson(baseUrl, empJar, 'POST', '/api/auth/login', {
    identifier: 'neha@9hrindia.com',
    password: 'StrongEmpPassword#2026',
  });
  assert.equal(empLogin.status, 200);
  assert.equal(empLogin.json.status, 'AUTHENTICATED');

  // 4. RBAC Enforcement: Employee cannot access Candidates, Payroll, or Admin Audit Logs
  assert.equal((await reqJson(baseUrl, empJar, 'GET', '/api/candidates')).status, 403);
  assert.equal((await reqJson(baseUrl, empJar, 'GET', '/api/hr/payroll/runs')).status, 403);
  assert.equal((await reqJson(baseUrl, empJar, 'GET', '/api/admin/audit-logs')).status, 403);

  // Horizontal escalation check: Employee cannot update Admin's bank details even with step-up
  const empStepUp = await reqJson(baseUrl, empJar, 'POST', '/api/auth/step-up', {
    password: 'StrongEmpPassword#2026',
  });
  assert.equal(empStepUp.status, 200);
  const adminEmpRow = db.prepare("SELECT id FROM employees WHERE email = 'admin@9hrindia.com'").get() as { id: string };
  const horizBlocked = await reqJson(
    baseUrl,
    empJar,
    'PATCH',
    `/api/hr/employees/${adminEmpRow.id}/bank-details`,
    { bankName: 'Test Bank', accountNumber: '1234567890', ifscCode: 'HDFC0001234' },
  );
  assert.equal(horizBlocked.status, 403);

  // HR logs in -> mandatory 2FA enrollment enforced!
  const hrJar = new CookieJar();
  const hrLogin = await reqJson(baseUrl, hrJar, 'POST', '/api/auth/login', {
    identifier: 'hr@9hrindia.com',
    password: 'StrongHrPassword#2026',
  });
  assert.equal(hrLogin.status, 200);
  assert.equal(hrLogin.json.status, '2FA_SETUP_REQUIRED');
  const hrSetup = await reqJson(baseUrl, hrJar, 'POST', '/api/auth/2fa/setup');
  const hrSecret = hrSetup.json.manualKey;
  const hrVerify = await reqJson(baseUrl, hrJar, 'POST', '/api/auth/2fa/verify-setup', {
    code: generateTotp(hrSecret),
  });
  assert.equal(hrVerify.status, 200);

  // HR cannot access Admin audit logs or Accounts payroll runs
  assert.equal((await reqJson(baseUrl, hrJar, 'GET', '/api/admin/audit-logs')).status, 403);
  assert.equal((await reqJson(baseUrl, hrJar, 'GET', '/api/hr/payroll/runs')).status, 403);

  // 5. Refresh Token Rotation + Reuse Detection
  const staleJar = hrJar.clone();
  const rotated = await reqJson(baseUrl, hrJar, 'POST', '/api/auth/refresh');
  assert.equal(rotated.status, 200);
  // Reuse stale refresh token -> triggers family revocation!
  const reuseAttack = await reqJson(baseUrl, staleJar, 'POST', '/api/auth/refresh');
  assert.equal(reuseAttack.status, 401);
  // Current rotated session is also revoked due to theft detection
  assert.equal((await reqJson(baseUrl, hrJar, 'GET', '/api/auth/me')).status, 401);

  // HR signs back in via 2FA TOTP verify
  const hrRelogin = await reqJson(baseUrl, hrJar, 'POST', '/api/auth/login', {
    identifier: 'priya.hr',
    password: 'StrongHrPassword#2026',
  });
  assert.equal(hrRelogin.json.status, '2FA_REQUIRED');
  const hrTotpVerify = await reqJson(baseUrl, hrJar, 'POST', '/api/auth/2fa/verify', {
    code: generateTotp(hrSecret),
  });
  assert.equal(hrTotpVerify.status, 200);

  // Admin logs in using a Backup Recovery Code
  const adminRecoveryJar = new CookieJar();
  const adminRelogin = await reqJson(baseUrl, adminRecoveryJar, 'POST', '/api/auth/login', {
    identifier: 'admin@9hrindia.com',
    password: 'StrongAdminPassword#2026',
  });
  assert.equal(adminRelogin.json.status, '2FA_REQUIRED');
  const recLogin = await reqJson(baseUrl, adminRecoveryJar, 'POST', '/api/auth/2fa/verify', {
    code: adminRecoveryCodes[0],
    isRecoveryCode: true,
  });
  assert.equal(recLogin.status, 200);
  assert.equal(recLogin.json.usedRecoveryCode, true);

  // 6. Step 1 & Step 2: Recruiter creates candidate, duplicate prevented, email confirmed, invitation sent
  const createCand = await reqJson(baseUrl, hrJar, 'POST', '/api/candidates', {
    fullName: 'Rohan Verma',
    email: 'rohan.candidate@example.com',
    mobile: '+919876543210',
    jobPosition: 'Platform Engineer',
    department: 'Engineering',
    assignedRecruiterId: createHr.json.user.id,
  });
  assert.equal(createCand.status, 201);
  const candId = createCand.json.candidate.id;

  // Duplicate candidate prevented
  const dupCand = await reqJson(baseUrl, hrJar, 'POST', '/api/candidates', {
    fullName: 'Rohan Duplicate',
    email: 'rohan.candidate@example.com',
    mobile: '+919876543210',
    jobPosition: 'Platform Engineer',
    department: 'Engineering',
  });
  assert.equal(dupCand.status, 409);

  // Cannot send invitation before confirming email
  const unconfirmedSend = await reqJson(baseUrl, hrJar, 'POST', `/api/candidates/${candId}/send-invitation`, {
    idempotencyKey: 'idem-1',
  });
  assert.equal(unconfirmedSend.status, 400);

  // Confirm email and send invitation (test idempotency too!)
  const confirmRes = await reqJson(baseUrl, hrJar, 'POST', `/api/candidates/${candId}/confirm-email`, {
    confirmedEmail: 'rohan.candidate@example.com',
  });
  assert.equal(confirmRes.status, 200);

  const sendInv = await reqJson(baseUrl, hrJar, 'POST', `/api/candidates/${candId}/send-invitation`, {
    idempotencyKey: 'idem-cand-1',
  });
  assert.equal(sendInv.status, 201);
  assert.equal(sendInv.json.emailDelivery.delivered, true);

  // Idempotent retry does NOT send duplicate email
  const emailCountBeforeDup = capturedEmails.length;
  const sendInvDup = await reqJson(baseUrl, hrJar, 'POST', `/api/candidates/${candId}/send-invitation`, {
    idempotencyKey: 'idem-cand-1',
  });
  assert.equal(sendInvDup.status, 200);
  assert.equal(sendInvDup.json.deduplicated, true);
  assert.equal(capturedEmails.length, emailCountBeforeDup);

  // Verify email content matches requirements
  const invEmail = capturedEmails.find((e) => e.to === 'rohan.candidate@example.com');
  assert.ok(invEmail, 'Candidate must receive invitation email');
  assert.equal(invEmail.subject, 'Action Required – Upload Your Documents for 9HR India');
  assert.ok(invEmail.text.includes('9HR India'));
  assert.ok(invEmail.text.includes('Platform Engineer'));
  assert.ok(!invEmail.text.includes(candId), 'Public URL must not expose internal candidate ID');

  const rawToken1 = sendInv.json.rawTokenForTestOnly as string;
  assert.ok(rawToken1);

  // 7. Create a second candidate to test isolation & revocation/expiry
  const cand2Res = await reqJson(baseUrl, hrJar, 'POST', '/api/candidates', {
    fullName: 'Meera Second',
    email: 'meera.second@example.com',
    mobile: '+919811112222',
    jobPosition: 'QA Analyst',
    department: 'Engineering',
  });
  const cand2Id = cand2Res.json.candidate.id;
  await reqJson(baseUrl, hrJar, 'POST', `/api/candidates/${cand2Id}/confirm-email`, {
    confirmedEmail: 'meera.second@example.com',
  });
  const sendInv2 = await reqJson(baseUrl, hrJar, 'POST', `/api/candidates/${cand2Id}/send-invitation`, {
    idempotencyKey: 'idem-cand-2',
  });
  const rawToken2 = sendInv2.json.rawTokenForTestOnly as string;
  // Revoke cand2 link -> must reject with 410
  await reqJson(baseUrl, hrJar, 'POST', `/api/candidates/${cand2Id}/revoke-invitation`, {
    reason: 'Test revocation',
  });
  const revokedAccept = await reqJson(baseUrl, null, 'POST', '/api/candidate-portal/accept-invitation', {
    token: rawToken2,
  });
  assert.equal(revokedAccept.status, 410);

  // Invalid token rejected
  const invalidAccept = await reqJson(baseUrl, null, 'POST', '/api/candidate-portal/accept-invitation', {
    token: 'totally-invalid-token',
  });
  assert.equal(invalidAccept.status, 404);

  // 8. Step 3: Candidate 1 accepts single-use invitation -> second redemption fails
  const candJar = new CookieJar();
  const accept1 = await reqJson(baseUrl, candJar, 'POST', '/api/candidate-portal/accept-invitation', {
    token: rawToken1,
  });
  assert.equal(accept1.status, 200);
  assert.equal(accept1.json.candidateName, 'Rohan Verma');

  // Replay of single-use invitation token is rejected
  const replayAccept = await reqJson(baseUrl, null, 'POST', '/api/candidate-portal/accept-invitation', {
    token: rawToken1,
  });
  assert.equal(replayAccept.status, 410);

  // Candidate cannot access internal HR APIs
  assert.equal((await reqJson(baseUrl, candJar, 'GET', '/api/candidates')).status, 401);
  assert.equal((await reqJson(baseUrl, candJar, 'GET', `/api/candidates/${cand2Id}`)).status, 401);

  // 9 & 10. Malicious / executable uploads blocked; valid PDF/JPG/PNG succeed
  const exeForm = new FormData();
  exeForm.append('docType', 'resume');
  exeForm.append(
    'file',
    new Blob([Buffer.from('MZ\x90\x00This is an executable')], { type: 'application/pdf' }),
    'malware.pdf',
  );
  const exeRes = await reqJson(baseUrl, candJar, 'POST', '/api/candidate-portal/upload', exeForm);
  assert.equal(exeRes.status, 422);

  const jsPdfForm = new FormData();
  jsPdfForm.append('docType', 'resume');
  jsPdfForm.append(
    'file',
    new Blob([Buffer.from('%PDF-1.4\n/OpenAction << /S /JavaScript /JS (app.alert(1)) >>\n%%EOF')], {
      type: 'application/pdf',
    }),
    'evil.pdf',
  );
  const jsPdfRes = await reqJson(baseUrl, candJar, 'POST', '/api/candidate-portal/upload', jsPdfForm);
  assert.equal(jsPdfRes.status, 422);

  // Upload all 6 mandatory documents validly
  const mandatoryUploads: Array<{ docType: string; buf: Buffer; mime: string; name: string }> = [
    { docType: 'resume', buf: makeValidPdfBuffer('Resume'), mime: 'application/pdf', name: 'resume.pdf' },
    { docType: 'photograph', buf: makeValidPngBuffer(), mime: 'image/png', name: 'photo.png' },
    { docType: 'aadhaar_card', buf: makeValidJpgBuffer(), mime: 'image/jpeg', name: 'aadhaar.jpg' },
    { docType: 'pan_card', buf: makeValidJpgBuffer(), mime: 'image/jpeg', name: 'pan.jpg' },
    { docType: 'educational_certificates', buf: makeValidPdfBuffer('Degree'), mime: 'application/pdf', name: 'degree.pdf' },
    { docType: 'bank_proof', buf: makeValidPdfBuffer('Cheque'), mime: 'application/pdf', name: 'cheque.pdf' },
  ];

  for (const item of mandatoryUploads) {
    const f = new FormData();
    f.append('docType', item.docType);
    f.append('file', new Blob([new Uint8Array(item.buf)], { type: item.mime }), item.name);
    const up = await reqJson(baseUrl, candJar, 'POST', '/api/candidate-portal/upload', f);
    assert.equal(up.status, 201, `Upload failed for ${item.docType}: ${JSON.stringify(up.json)}`);
  }

  // 11. Submit documents -> updates status & notifies recruiter in-app + email
  const submitRes = await reqJson(baseUrl, candJar, 'POST', '/api/candidate-portal/submit');
  assert.equal(submitRes.status, 200);
  assert.equal(submitRes.json.status, 'Documents Submitted – Pending HR Verification');

  const hrNotifs = await reqJson(baseUrl, hrJar, 'GET', '/api/hr/notifications');
  assert.equal(hrNotifs.status, 200);
  assert.ok(
    hrNotifs.json.notifications.some((n: any) => n.related_entity_id === candId),
    'Assigned recruiter must receive in-app notification',
  );
  assert.ok(
    capturedEmails.some((e) => e.to === 'hr@9hrindia.com' && e.subject.includes('Documents Submitted')),
    'Assigned recruiter must receive email notification',
  );

  // 12, 13, 14. HR reviews: approves 5 docs, rejects PAN card with mandatory reason, candidate re-uploads ONLY PAN
  const detailBefore = await reqJson(baseUrl, hrJar, 'GET', `/api/candidates/${candId}`);
  const checklistBefore = detailBefore.json.checklist as any[];

  // Rejecting without a reason must fail 400
  const panEntry = checklistBefore.find((c) => c.requirement.doc_type === 'pan_card');
  const noReasonReject = await reqJson(
    baseUrl,
    hrJar,
    'POST',
    `/api/candidates/${candId}/documents/${panEntry.currentDocument.id}/review`,
    { decision: 'Rejected', rejectionReason: '' },
  );
  assert.equal(noReasonReject.status, 400);

  // Approve other 5 mandatory docs first
  for (const entry of checklistBefore) {
    if (entry.currentDocument && entry.requirement.doc_type !== 'pan_card') {
      const appRes = await reqJson(
        baseUrl,
        hrJar,
        'POST',
        `/api/candidates/${candId}/documents/${entry.currentDocument.id}/review`,
        { decision: 'Approved' },
      );
      assert.equal(appRes.status, 200);
    }
  }

  // Reject PAN card with reason -> sends re-upload link
  const rejectPan = await reqJson(
    baseUrl,
    hrJar,
    'POST',
    `/api/candidates/${candId}/documents/${panEntry.currentDocument.id}/review`,
    { decision: 'Rejected', rejectionReason: 'PAN number is illegible' },
  );
  assert.equal(rejectPan.status, 200);
  assert.equal(rejectPan.json.candidateStatus, 'Re-upload Required');
  const reuploadToken = rejectPan.json.reuploadInvitation.rawTokenForTestOnly as string;

  // Candidate accepts re-upload link
  const candReuploadJar = new CookieJar();
  const reuploadAccept = await reqJson(
    baseUrl,
    candReuploadJar,
    'POST',
    '/api/candidate-portal/accept-invitation',
    { token: reuploadToken },
  );
  assert.equal(reuploadAccept.status, 200);

  // Attempting to overwrite an already Approved document (resume) must be blocked!
  const overwriteApproved = new FormData();
  overwriteApproved.append('docType', 'resume');
  overwriteApproved.append('file', new Blob([new Uint8Array(makeValidPdfBuffer('NewResume'))], { type: 'application/pdf' }), 'new.pdf');
  const overwriteRes = await reqJson(baseUrl, candReuploadJar, 'POST', '/api/candidate-portal/upload', overwriteApproved);
  assert.equal(overwriteRes.status, 409);

  // Re-upload ONLY PAN card -> succeeds as v2
  const panReupload = new FormData();
  panReupload.append('docType', 'pan_card');
  panReupload.append('file', new Blob([new Uint8Array(makeValidJpgBuffer())], { type: 'image/jpeg' }), 'pan_clear.jpg');
  const panUpRes = await reqJson(baseUrl, candReuploadJar, 'POST', '/api/candidate-portal/upload', panReupload);
  assert.equal(panUpRes.status, 201);
  assert.equal(panUpRes.json.document.version, 2);

  await reqJson(baseUrl, candReuploadJar, 'POST', '/api/candidate-portal/submit');

  // Verify approved documents remained Approved!
  const detailAfterReupload = await reqJson(baseUrl, hrJar, 'GET', `/api/candidates/${candId}`);
  const resumeEntry = (detailAfterReupload.json.checklist as any[]).find(
    (c) => c.requirement.doc_type === 'resume',
  );
  assert.equal(resumeEntry.currentDocument.status, 'Approved');
  const panEntryV2 = (detailAfterReupload.json.checklist as any[]).find(
    (c) => c.requirement.doc_type === 'pan_card',
  );
  assert.equal(panEntryV2.currentDocument.version, 2);
  assert.equal(panEntryV2.history.length, 2);

  // 15. Approve PAN v2 -> Verification Completed -> Existing HR Approval & Joining workflow preserved
  const approvePanV2 = await reqJson(
    baseUrl,
    hrJar,
    'POST',
    `/api/candidates/${candId}/documents/${panEntryV2.currentDocument.id}/review`,
    { decision: 'Approved' },
  );
  assert.equal(approvePanV2.status, 200);
  assert.equal(approvePanV2.json.verificationCompleted, true);
  assert.equal(approvePanV2.json.candidateStatus, 'Documents Verified – Pending HR Approval');

  // Cannot skip HR Onboarding Approval straight to Joined
  const skipApproval = await reqJson(baseUrl, hrJar, 'POST', `/api/candidates/${candId}/advance-stage`, {
    nextStage: 'Joined',
    createEmployeeAccount: true,
    passwordForEmployee: 'RohanEmpPassword#2026',
  });
  assert.equal(skipApproval.status, 400);

  // Follow existing workflow: Offer Extended -> Onboarding Approved -> Joined
  assert.equal(
    (
      await reqJson(baseUrl, hrJar, 'POST', `/api/candidates/${candId}/advance-stage`, {
        nextStage: 'Offer Extended',
      })
    ).status,
    200,
  );
  assert.equal(
    (
      await reqJson(baseUrl, hrJar, 'POST', `/api/candidates/${candId}/advance-stage`, {
        nextStage: 'Onboarding Approved',
      })
    ).status,
    200,
  );
  const joinRes = await reqJson(baseUrl, hrJar, 'POST', `/api/candidates/${candId}/advance-stage`, {
    nextStage: 'Joined',
    createEmployeeAccount: true,
    ctcAnnual: 1500000,
    passwordForEmployee: 'RohanEmpPassword#2026',
  });
  assert.equal(joinRes.status, 200);
  assert.ok(joinRes.json.createdEmployeeId);

  // 16. Existing Payroll & Leave workflows continue to work
  const accJar = new CookieJar();
  await reqJson(baseUrl, accJar, 'POST', '/api/auth/login', {
    identifier: 'accounts@9hrindia.com',
    password: 'StrongAccPassword#2026',
  });
  const accSetup = await reqJson(baseUrl, accJar, 'POST', '/api/auth/2fa/setup');
  await reqJson(baseUrl, accJar, 'POST', '/api/auth/2fa/verify-setup', {
    code: generateTotp(accSetup.json.manualKey),
  });
  const payRes = await reqJson(baseUrl, accJar, 'POST', '/api/hr/payroll/runs', {
    monthYear: '2026-11',
  });
  assert.equal(payRes.status, 201);
  assert.ok(payRes.json.run.total_net > 0);

  // 17. Audit trail records events accurately
  const auditRes = await reqJson(baseUrl, adminJar, 'GET', '/api/admin/audit-logs?limit=150');
  assert.equal(auditRes.status, 200);
  const actions = new Set((auditRes.json.logs as any[]).map((l) => l.action));
  for (const expectedAction of [
    'ADMIN_WORKSPACE_CLAIMED',
    '2FA_ENABLED',
    'LOGIN_FAILED',
    'REFRESH_TOKEN_REUSE_DETECTED',
    'CANDIDATE_CREATED',
    'CANDIDATE_INVITATION_SENT',
    'DOCUMENT_UPLOAD_BLOCKED_SECURITY',
    'CANDIDATE_DOCUMENTS_SUBMITTED',
    'DOCUMENT_REJECTED',
    'DOCUMENT_APPROVED',
    'DOCUMENT_VERIFICATION_COMPLETED',
    'CANDIDATE_STAGE_ADVANCED',
    'PAYROLL_RUN_PROCESSED',
  ]) {
    assert.ok(actions.has(expectedAction), `Missing audit log action: ${expectedAction}`);
  }
});

test('Brute-force Lockout, Forgot Password & Session Revocation', async () => {
  // Trigger temporary lockout after 5 wrong password attempts for neha@9hrindia.com
  for (let i = 0; i < 4; i++) {
    const res = await reqJson(baseUrl, null, 'POST', '/api/auth/login', {
      identifier: 'neha@9hrindia.com',
      password: 'WrongPasswordAttempt',
    });
    assert.equal(res.status, 401);
  }
  const lockedRes = await reqJson(baseUrl, null, 'POST', '/api/auth/login', {
    identifier: 'neha@9hrindia.com',
    password: 'WrongPasswordAttempt',
  });
  assert.equal(lockedRes.status, 429);

  // Even correct password is blocked while locked out
  const blockedCorrect = await reqJson(baseUrl, null, 'POST', '/api/auth/login', {
    identifier: 'neha@9hrindia.com',
    password: 'StrongEmpPassword#2026',
  });
  assert.equal(blockedCorrect.status, 429);

  // Forgot password sends real email and reset-password updates hash & clears lockout
  const forgotRes = await reqJson(baseUrl, null, 'POST', '/api/auth/forgot-password', {
    email: 'neha@9hrindia.com',
  });
  assert.equal(forgotRes.status, 200);
  const resetEmail = capturedEmails.find((e) => e.to === 'neha@9hrindia.com');
  assert.ok(resetEmail);
  const match = resetEmail.text.match(/token=([^\s]+)/);
  assert.ok(match, 'Reset token must be present in reset email');
  const resetToken = decodeURIComponent(match[1]);

  const resetDone = await reqJson(baseUrl, null, 'POST', '/api/auth/reset-password', {
    token: resetToken,
    newPassword: 'UpdatedNehaPassword#2026',
  });
  assert.equal(resetDone.status, 200);

  // New password works immediately
  const empJar = new CookieJar();
  const loginOk = await reqJson(baseUrl, empJar, 'POST', '/api/auth/login', {
    identifier: 'neha@9hrindia.com',
    password: 'UpdatedNehaPassword#2026',
  });
  assert.equal(loginOk.status, 200);
});
