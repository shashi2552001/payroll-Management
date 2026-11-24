import type Database from 'better-sqlite3';
import crypto from 'crypto';
import express from 'express';
import { recordAudit } from '../audit.ts';
import type { AppConfig } from '../config.ts';
import {
  decryptAtRest,
  encryptAtRest,
  generateRandomToken,
  generateRecoveryCodes,
  generateTotpEnrollment,
  hashPassword,
  signToken,
  sha256Hex,
  verifyAndConsumeRecoveryCode,
  verifyPassword,
  verifyToken,
  verifyTotpCode,
} from '../crypto.ts';
import type { UserRole } from '../db.ts';
import { buildPasswordResetEmail, type EmailService } from '../email.ts';
import {
  COOKIE_2FA_CHALLENGE,
  COOKIE_ACCESS,
  COOKIE_REFRESH,
  COOKIE_STEP_UP,
  clearSecureCookie,
  createAuthMiddleware,
  createRateLimiter,
  getClientIp,
  getRolePermissions,
  is2faMandatoryForRole,
  setSecureCookie,
} from '../middleware.ts';

interface DbUser {
  id: string;
  username: string;
  email: string;
  full_name: string;
  role: UserRole;
  department: string;
  designation: string;
  manager_id: string | null;
  password_hash: string;
  totp_secret_encrypted: string | null;
  totp_enabled: number;
  failed_login_attempts: number;
  locked_until: string | null;
  is_active: number;
}

function summarizeUserAgent(ua: string | undefined): string {
  if (!ua) return 'Unknown Client';
  if (ua.includes('Playwright') || ua.includes('Headless')) return 'Automated Browser';
  if (ua.includes('iPhone') || ua.includes('Android')) return 'Mobile Browser';
  if (ua.includes('Chrome')) return 'Chrome Desktop';
  if (ua.includes('Firefox')) return 'Firefox Desktop';
  if (ua.includes('Safari')) return 'Safari Desktop';
  return ua.slice(0, 48);
}

export function createAuthRouter(
  db: Database.Database,
  config: AppConfig,
  emailService: EmailService,
): express.Router {
  const router = express.Router();
  const { requireAuth, requireStepUp } = createAuthMiddleware(db, config);

  const loginLimiter = createRateLimiter({
    windowMs: 60_000,
    maxRequests: 20,
    keyPrefix: 'login',
  });
  const totpLimiter = createRateLimiter({
    windowMs: 60_000,
    maxRequests: 15,
    keyPrefix: 'totp',
  });
  const resetLimiter = createRateLimiter({
    windowMs: 60_000,
    maxRequests: 8,
    keyPrefix: 'pwreset',
  });

  function issueFullSession(
    req: express.Request,
    res: express.Response,
    user: DbUser,
  ): { sessionId: string; accessToken: string } {
    const policy = db
      .prepare('SELECT session_timeout_minutes FROM security_policies WHERE id = 1')
      .get() as { session_timeout_minutes: number } | undefined;
    const sessionTimeoutMinutes = policy?.session_timeout_minutes || 480;

    const sessionId = `ses_${crypto.randomUUID()}`;
    const familyId = `fam_${crypto.randomUUID()}`;
    const accessJti = crypto.randomUUID();
    const rawRefreshToken = generateRandomToken(32);
    const refreshHash = sha256Hex(rawRefreshToken);

    const now = new Date();
    const expiresAt = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);

    db.prepare(`
      INSERT INTO user_sessions (
        id, user_id, token_family_id, refresh_token_hash, access_jti,
        ip_address, user_agent, device_label, created_at, last_active_at, expires_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      sessionId,
      user.id,
      familyId,
      refreshHash,
      accessJti,
      getClientIp(req),
      String(req.headers['user-agent'] || '').slice(0, 250),
      summarizeUserAgent(req.headers['user-agent']),
      now.toISOString(),
      now.toISOString(),
      expiresAt.toISOString(),
    );

    const accessTtlSeconds = Math.min(sessionTimeoutMinutes * 60, 15 * 60);
    const accessToken = signToken(
      {
        sub: user.id,
        typ: 'access',
        sid: sessionId,
        jti: accessJti,
        role: user.role,
      },
      accessTtlSeconds,
      config.sessionSecret,
    );

    setSecureCookie(req, res, COOKIE_ACCESS, accessToken, accessTtlSeconds * 1000);
    setSecureCookie(req, res, COOKIE_REFRESH, rawRefreshToken, 7 * 24 * 60 * 60 * 1000);
    clearSecureCookie(req, res, COOKIE_2FA_CHALLENGE);

    return { sessionId, accessToken };
  }

  router.get('/bootstrap-status', (_req, res) => {
    const row = db
      .prepare("SELECT COUNT(*) AS cnt FROM users WHERE role = 'Admin'")
      .get() as { cnt: number };
    res.json({
      needsBootstrap: row.cnt === 0,
      smtpConfigured: emailService.isConfigured(),
      envAdminPasswordConfigured: Boolean(config.adminBootstrapPassword),
    });
  });

  router.post('/bootstrap', async (req, res) => {
    const existingAdmin = db
      .prepare("SELECT COUNT(*) AS cnt FROM users WHERE role = 'Admin'")
      .get() as { cnt: number };
    if (existingAdmin.cnt > 0) {
      res.status(403).json({ error: 'Workspace administrator has already been claimed.' });
      return;
    }

    const { fullName, email, username, password } = req.body as {
      fullName?: string;
      email?: string;
      username?: string;
      password?: string;
    };

    const effectivePassword = config.adminBootstrapPassword || password || '';
    if (!fullName?.trim() || !email?.trim() || !username?.trim() || effectivePassword.length < 10) {
      res.status(400).json({
        error: 'Provide full name, valid email, username, and a strong password (minimum 10 characters).',
      });
      return;
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())) {
      res.status(400).json({ error: 'Invalid email address format.' });
      return;
    }

    const userId = `usr_${crypto.randomUUID()}`;
    const empId = `emp_${crypto.randomUUID()}`;
    const now = new Date().toISOString();
    const pwHash = await hashPassword(effectivePassword);

    try {
      const tx = db.transaction(() => {
        const recheck = db
          .prepare("SELECT COUNT(*) AS cnt FROM users WHERE role = 'Admin'")
          .get() as { cnt: number };
        if (recheck.cnt > 0) {
          throw new Error('ALREADY_CLAIMED');
        }

        db.prepare(`
          INSERT INTO users (
            id, username, email, full_name, role, department, designation,
            password_hash, totp_enabled, is_active, created_at, updated_at
          ) VALUES (?, ?, ?, ?, 'Admin', 'Administration', 'System Administrator', ?, 0, 1, ?, ?)
        `).run(userId, username.trim(), email.trim().toLowerCase(), fullName.trim(), pwHash, now, now);

        db.prepare(`
          INSERT INTO employees (
            id, user_id, employee_code, full_name, email, department, designation,
            joining_date, employment_status, ctc_annual, basic_salary, hra, allowances,
            created_at, updated_at
          ) VALUES (?, ?, '9HR-0001', ?, ?, 'Administration', 'System Administrator', ?, 'Active', 0, 0, 0, 0, ?, ?)
        `).run(empId, userId, fullName.trim(), email.trim().toLowerCase(), now.slice(0, 10), now, now);

        recordAudit(db, {
          actorUserId: userId,
          actorLabel: email.trim().toLowerCase(),
          actorRole: 'Admin',
          action: 'ADMIN_WORKSPACE_CLAIMED',
          entityType: 'user',
          entityId: userId,
          ipAddress: getClientIp(req),
          userAgent: req.headers['user-agent'] || null,
        });
      });
      tx();
    } catch (err) {
      if (err instanceof Error && err.message === 'ALREADY_CLAIMED') {
        res.status(403).json({ error: 'Workspace administrator has already been claimed.' });
        return;
      }
      res.status(409).json({ error: 'Unable to claim workspace administrator account.' });
      return;
    }

    // Admin has mandatory 2FA -> issue 2FA_SETUP_REQUIRED challenge cookie
    const challengeToken = signToken(
      { sub: userId, typ: '2fa_setup_challenge' },
      15 * 60,
      config.sessionSecret,
    );
    setSecureCookie(req, res, COOKIE_2FA_CHALLENGE, challengeToken, 15 * 60 * 1000);

    res.status(201).json({
      status: '2FA_SETUP_REQUIRED',
      user: {
        id: userId,
        email: email.trim().toLowerCase(),
        fullName: fullName.trim(),
        role: 'Admin',
      },
    });
  });

  router.post('/login', loginLimiter, async (req, res) => {
    const { identifier, password } = req.body as {
      identifier?: string;
      password?: string;
    };

    if (!identifier?.trim() || !password) {
      res.status(400).json({ error: 'Username/email and password are required.' });
      return;
    }

    const cleanId = identifier.trim().toLowerCase();
    const user = db
      .prepare('SELECT * FROM users WHERE lower(email) = ? OR lower(username) = ?')
      .get(cleanId, cleanId) as DbUser | undefined;

    const policy = db
      .prepare('SELECT lockout_threshold, lockout_duration_minutes FROM security_policies WHERE id = 1')
      .get() as { lockout_threshold: number; lockout_duration_minutes: number } | undefined;
    const lockoutThreshold = policy?.lockout_threshold || 5;
    const lockoutMinutes = policy?.lockout_duration_minutes || 15;

    if (!user || !user.is_active) {
      // Constant-ish time dummy check to avoid timing leak
      await verifyPassword(
        '$argon2id$v=19$m=65536,t=3,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        password,
      );
      recordAudit(db, {
        actorLabel: cleanId,
        actorRole: 'Anonymous',
        action: 'LOGIN_FAILED',
        entityType: 'auth',
        ipAddress: getClientIp(req),
        userAgent: req.headers['user-agent'] || null,
        metadata: { reason: 'invalid_credentials' },
      });
      res.status(401).json({ error: 'Invalid credentials.' });
      return;
    }

    if (user.locked_until && new Date(user.locked_until).getTime() > Date.now()) {
      recordAudit(db, {
        actorUserId: user.id,
        actorLabel: user.email,
        actorRole: user.role,
        action: 'LOGIN_BLOCKED_LOCKED',
        entityType: 'user',
        entityId: user.id,
        ipAddress: getClientIp(req),
        userAgent: req.headers['user-agent'] || null,
      });
      res.status(429).json({
        error: 'Authentication temporarily unavailable due to multiple failed attempts. Please try again later.',
      });
      return;
    }

    const valid = await verifyPassword(user.password_hash, password);
    if (!valid) {
      const nextAttempts = user.failed_login_attempts + 1;
      const shouldLock = nextAttempts >= lockoutThreshold;
      const lockedUntil = shouldLock
        ? new Date(Date.now() + lockoutMinutes * 60 * 1000).toISOString()
        : null;

      db.prepare(`
        UPDATE users
        SET failed_login_attempts = ?, locked_until = ?, updated_at = ?
        WHERE id = ?
      `).run(shouldLock ? 0 : nextAttempts, lockedUntil, new Date().toISOString(), user.id);

      recordAudit(db, {
        actorUserId: user.id,
        actorLabel: user.email,
        actorRole: user.role,
        action: shouldLock ? 'ACCOUNT_LOCKED' : 'LOGIN_FAILED',
        entityType: 'user',
        entityId: user.id,
        ipAddress: getClientIp(req),
        userAgent: req.headers['user-agent'] || null,
        metadata: { failedAttempts: nextAttempts },
      });

      res.status(shouldLock ? 429 : 401).json({
        error: shouldLock
          ? 'Authentication temporarily unavailable due to multiple failed attempts. Please try again later.'
          : 'Invalid credentials.',
      });
      return;
    }

    // Reset failed counter on valid password
    db.prepare(`
      UPDATE users SET failed_login_attempts = 0, locked_until = NULL, updated_at = ? WHERE id = ?
    `).run(new Date().toISOString(), user.id);

    const mandatory2fa = is2faMandatoryForRole(db, user.role);

    if (user.totp_enabled) {
      const challengeToken = signToken(
        { sub: user.id, typ: '2fa_verify_challenge' },
        10 * 60,
        config.sessionSecret,
      );
      setSecureCookie(req, res, COOKIE_2FA_CHALLENGE, challengeToken, 10 * 60 * 1000);
      res.json({
        status: '2FA_REQUIRED',
        role: user.role,
        fullName: user.full_name,
      });
      return;
    }

    if (mandatory2fa) {
      const setupChallenge = signToken(
        { sub: user.id, typ: '2fa_setup_challenge' },
        15 * 60,
        config.sessionSecret,
      );
      setSecureCookie(req, res, COOKIE_2FA_CHALLENGE, setupChallenge, 15 * 60 * 1000);
      res.json({
        status: '2FA_SETUP_REQUIRED',
        role: user.role,
        fullName: user.full_name,
      });
      return;
    }

    // Employee with optional 2FA disabled
    const { sessionId } = issueFullSession(req, res, user);
    recordAudit(db, {
      actorUserId: user.id,
      actorLabel: user.email,
      actorRole: user.role,
      action: 'LOGIN_SUCCESS',
      entityType: 'user_session',
      entityId: sessionId,
      ipAddress: getClientIp(req),
      userAgent: req.headers['user-agent'] || null,
    });

    res.json({
      status: 'AUTHENTICATED',
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        fullName: user.full_name,
        role: user.role,
        department: user.department,
        designation: user.designation,
        totpEnabled: false,
        permissions: getRolePermissions(db, user.role),
      },
    });
  });

  function resolve2faTargetUser(
    req: express.Request,
    expectedTypes: string[],
  ): { user: DbUser; challengeType: string } | null {
    const challengeCookie = req.cookies?.[COOKIE_2FA_CHALLENGE];
    if (challengeCookie) {
      for (const t of expectedTypes) {
        const payload = verifyToken(challengeCookie, config.sessionSecret, t);
        if (payload) {
          const user = db.prepare('SELECT * FROM users WHERE id = ? AND is_active = 1').get(payload.sub) as
            | DbUser
            | undefined;
          if (user) return { user, challengeType: t };
        }
      }
    }

    // Also allow already authenticated user enabling optional 2FA from Security Settings
    if (expectedTypes.includes('authenticated_optional')) {
      const accessCookie = req.cookies?.[COOKIE_ACCESS];
      if (accessCookie) {
        const payload = verifyToken(accessCookie, config.sessionSecret, 'access');
        if (payload?.sid) {
          const ses = db
            .prepare('SELECT revoked_at, expires_at FROM user_sessions WHERE id = ?')
            .get(payload.sid) as { revoked_at: string | null; expires_at: string } | undefined;
          if (ses && !ses.revoked_at && new Date(ses.expires_at).getTime() > Date.now()) {
            const user = db.prepare('SELECT * FROM users WHERE id = ? AND is_active = 1').get(payload.sub) as
              | DbUser
              | undefined;
            if (user) return { user, challengeType: 'authenticated_optional' };
          }
        }
      }
    }

    return null;
  }

  router.post('/2fa/setup', totpLimiter, async (req, res) => {
    const resolved = resolve2faTargetUser(req, ['2fa_setup_challenge', 'authenticated_optional']);
    if (!resolved) {
      res.status(401).json({ error: 'Valid login challenge or active session required for 2FA setup.' });
      return;
    }

    const { user } = resolved;
    if (user.totp_enabled) {
      res.status(400).json({ error: 'Two-factor authentication is already enabled on this account.' });
      return;
    }

    const enrollment = await generateTotpEnrollment(user.email);
    const encryptedSecret = encryptAtRest(enrollment.secretBase32, config.sessionSecret);

    db.prepare('UPDATE users SET totp_secret_encrypted = ?, updated_at = ? WHERE id = ?').run(
      encryptedSecret,
      new Date().toISOString(),
      user.id,
    );

    recordAudit(db, {
      actorUserId: user.id,
      actorLabel: user.email,
      actorRole: user.role,
      action: '2FA_SETUP_INITIATED',
      entityType: 'user',
      entityId: user.id,
      ipAddress: getClientIp(req),
      userAgent: req.headers['user-agent'] || null,
    });

    res.json({
      qrDataUrl: enrollment.qrDataUrl,
      manualKey: enrollment.secretBase32,
      otpauthUri: enrollment.otpauthUri,
      accountEmail: user.email,
    });
  });

  router.post('/2fa/verify-setup', totpLimiter, async (req, res) => {
    const { code } = req.body as { code?: string };
    const resolved = resolve2faTargetUser(req, ['2fa_setup_challenge', 'authenticated_optional']);
    if (!resolved) {
      res.status(401).json({ error: 'Valid login challenge or active session required.' });
      return;
    }

    const { user } = resolved;
    if (!user.totp_secret_encrypted) {
      res.status(400).json({ error: '2FA enrollment has not been initiated yet.' });
      return;
    }

    const secretBase32 = decryptAtRest(user.totp_secret_encrypted, config.sessionSecret);
    if (!code || !verifyTotpCode(secretBase32, code)) {
      recordAudit(db, {
        actorUserId: user.id,
        actorLabel: user.email,
        actorRole: user.role,
        action: '2FA_SETUP_VERIFICATION_FAILED',
        entityType: 'user',
        entityId: user.id,
        ipAddress: getClientIp(req),
      });
      res.status(400).json({ error: 'Invalid 6-digit authenticator code. Please try again.' });
      return;
    }

    const { plaintextCodes, hashedCodes } = await generateRecoveryCodes(8);
    const now = new Date().toISOString();

    const tx = db.transaction(() => {
      db.prepare(`
        UPDATE users SET totp_enabled = 1, totp_verified_at = ?, updated_at = ? WHERE id = ?
      `).run(now, now, user.id);

      db.prepare('DELETE FROM recovery_codes WHERE user_id = ?').run(user.id);
      const insertCode = db.prepare(`
        INSERT INTO recovery_codes (id, user_id, code_hash, created_at) VALUES (?, ?, ?, ?)
      `);
      for (const h of hashedCodes) {
        insertCode.run(`rec_${crypto.randomUUID()}`, user.id, h, now);
      }

      recordAudit(db, {
        actorUserId: user.id,
        actorLabel: user.email,
        actorRole: user.role,
        action: '2FA_ENABLED',
        entityType: 'user',
        entityId: user.id,
        ipAddress: getClientIp(req),
        userAgent: req.headers['user-agent'] || null,
      });
    });
    tx();

    const updatedUser = db.prepare('SELECT * FROM users WHERE id = ?').get(user.id) as DbUser;
    if (resolved.challengeType === '2fa_setup_challenge') {
      issueFullSession(req, res, updatedUser);
    }

    res.json({
      status: '2FA_ENABLED',
      recoveryCodes: plaintextCodes,
      user: {
        id: updatedUser.id,
        username: updatedUser.username,
        email: updatedUser.email,
        fullName: updatedUser.full_name,
        role: updatedUser.role,
        department: updatedUser.department,
        designation: updatedUser.designation,
        totpEnabled: true,
        permissions: getRolePermissions(db, updatedUser.role),
      },
    });
  });

  router.post('/2fa/verify', totpLimiter, async (req, res) => {
    const { code, isRecoveryCode } = req.body as {
      code?: string;
      isRecoveryCode?: boolean;
    };
    const resolved = resolve2faTargetUser(req, ['2fa_verify_challenge']);
    if (!resolved) {
      res.status(401).json({ error: 'Two-factor authentication challenge expired. Please sign in again.' });
      return;
    }

    const { user } = resolved;
    if (!user.totp_enabled || !user.totp_secret_encrypted) {
      res.status(400).json({ error: '2FA is not configured on this account.' });
      return;
    }

    if (!code?.trim()) {
      res.status(400).json({ error: 'Verification code is required.' });
      return;
    }

    let verified = false;
    let usedRecoveryId: string | null = null;

    if (isRecoveryCode) {
      const unusedCodes = db
        .prepare('SELECT id, code_hash FROM recovery_codes WHERE user_id = ? AND used_at IS NULL')
        .all(user.id) as Array<{ id: string; code_hash: string }>;
      usedRecoveryId = await verifyAndConsumeRecoveryCode(unusedCodes, code);
      verified = Boolean(usedRecoveryId);
    } else {
      const secretBase32 = decryptAtRest(user.totp_secret_encrypted, config.sessionSecret);
      verified = verifyTotpCode(secretBase32, code);
    }

    if (!verified) {
      recordAudit(db, {
        actorUserId: user.id,
        actorLabel: user.email,
        actorRole: user.role,
        action: '2FA_VERIFICATION_FAILED',
        entityType: 'user',
        entityId: user.id,
        ipAddress: getClientIp(req),
        metadata: { method: isRecoveryCode ? 'recovery_code' : 'totp' },
      });
      res.status(401).json({ error: 'Invalid verification code.' });
      return;
    }

    if (usedRecoveryId) {
      db.prepare('UPDATE recovery_codes SET used_at = ? WHERE id = ?').run(
        new Date().toISOString(),
        usedRecoveryId,
      );
    }

    const { sessionId } = issueFullSession(req, res, user);

    recordAudit(db, {
      actorUserId: user.id,
      actorLabel: user.email,
      actorRole: user.role,
      action: usedRecoveryId ? '2FA_RECOVERY_CODE_USED' : '2FA_VERIFIED_LOGIN',
      entityType: 'user_session',
      entityId: sessionId,
      ipAddress: getClientIp(req),
      userAgent: req.headers['user-agent'] || null,
    });

    res.json({
      status: 'AUTHENTICATED',
      usedRecoveryCode: Boolean(usedRecoveryId),
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        fullName: user.full_name,
        role: user.role,
        department: user.department,
        designation: user.designation,
        totpEnabled: true,
        permissions: getRolePermissions(db, user.role),
      },
    });
  });

  router.post('/refresh', (req, res) => {
    const rawRefresh = req.cookies?.[COOKIE_REFRESH];
    if (!rawRefresh) {
      res.status(401).json({ error: 'Refresh token missing.' });
      return;
    }

    const refreshHash = sha256Hex(rawRefresh);
    const session = db
      .prepare('SELECT * FROM user_sessions WHERE refresh_token_hash = ?')
      .get(refreshHash) as
      | {
          id: string;
          user_id: string;
          token_family_id: string;
          expires_at: string;
          revoked_at: string | null;
        }
      | undefined;

    if (!session) {
      res.status(401).json({ error: 'Invalid refresh token.' });
      return;
    }

    if (session.revoked_at) {
      // Refresh token reuse detected -> revoke entire token family
      db.prepare(`
        UPDATE user_sessions SET revoked_at = ?, revoke_reason = 'refresh_token_reuse_detected'
        WHERE token_family_id = ? AND revoked_at IS NULL
      `).run(new Date().toISOString(), session.token_family_id);

      recordAudit(db, {
        actorUserId: session.user_id,
        actorLabel: session.user_id,
        actorRole: 'System',
        action: 'REFRESH_TOKEN_REUSE_DETECTED',
        entityType: 'user_session',
        entityId: session.id,
        ipAddress: getClientIp(req),
      });

      clearSecureCookie(req, res, COOKIE_ACCESS);
      clearSecureCookie(req, res, COOKIE_REFRESH);
      res.status(401).json({ error: 'Session revoked due to token reuse detection.' });
      return;
    }

    if (new Date(session.expires_at).getTime() <= Date.now()) {
      res.status(401).json({ error: 'Refresh token expired.' });
      return;
    }

    const user = db.prepare('SELECT * FROM users WHERE id = ? AND is_active = 1').get(session.user_id) as
      | DbUser
      | undefined;
    if (!user) {
      res.status(401).json({ error: 'User account unavailable.' });
      return;
    }

    const newRefreshRaw = generateRandomToken(32);
    const newRefreshHash = sha256Hex(newRefreshRaw);
    const newSessionId = `ses_${crypto.randomUUID()}`;
    const newAccessJti = crypto.randomUUID();
    const now = new Date();
    const newExpires = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);

    const tx = db.transaction(() => {
      db.prepare(`
        UPDATE user_sessions SET revoked_at = ?, revoke_reason = 'rotated' WHERE id = ?
      `).run(now.toISOString(), session.id);

      db.prepare(`
        INSERT INTO user_sessions (
          id, user_id, token_family_id, refresh_token_hash, access_jti,
          ip_address, user_agent, device_label, created_at, last_active_at, expires_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        newSessionId,
        user.id,
        session.token_family_id,
        newRefreshHash,
        newAccessJti,
        getClientIp(req),
        String(req.headers['user-agent'] || '').slice(0, 250),
        summarizeUserAgent(req.headers['user-agent']),
        now.toISOString(),
        now.toISOString(),
        newExpires.toISOString(),
      );
    });
    tx();

    const accessToken = signToken(
      {
        sub: user.id,
        typ: 'access',
        sid: newSessionId,
        jti: newAccessJti,
        role: user.role,
      },
      15 * 60,
      config.sessionSecret,
    );

    setSecureCookie(req, res, COOKIE_ACCESS, accessToken, 15 * 60 * 1000);
    setSecureCookie(req, res, COOKIE_REFRESH, newRefreshRaw, 7 * 24 * 60 * 60 * 1000);

    res.json({ rotated: true });
  });

  router.post('/logout', (req, res) => {
    const accessCookie = req.cookies?.[COOKIE_ACCESS];
    const payload = accessCookie ? verifyToken(accessCookie, config.sessionSecret, 'access') : null;
    if (payload?.sid) {
      db.prepare(`
        UPDATE user_sessions SET revoked_at = ?, revoke_reason = 'user_logout' WHERE id = ?
      `).run(new Date().toISOString(), payload.sid);

      recordAudit(db, {
        actorUserId: payload.sub,
        actorLabel: payload.sub,
        actorRole: payload.role || 'User',
        action: 'LOGOUT',
        entityType: 'user_session',
        entityId: payload.sid,
        ipAddress: getClientIp(req),
      });
    }

    clearSecureCookie(req, res, COOKIE_ACCESS);
    clearSecureCookie(req, res, COOKIE_REFRESH);
    clearSecureCookie(req, res, COOKIE_2FA_CHALLENGE);
    clearSecureCookie(req, res, COOKIE_STEP_UP);
    res.json({ ok: true });
  });

  router.get('/me', requireAuth, (req, res) => {
    const u = req.authUser!;
    const remainingRecovery = db
      .prepare('SELECT COUNT(*) AS cnt FROM recovery_codes WHERE user_id = ? AND used_at IS NULL')
      .get(u.id) as { cnt: number };

    res.json({
      user: {
        ...u,
        remainingRecoveryCodes: remainingRecovery.cnt,
        mandatory2fa: is2faMandatoryForRole(db, u.role),
      },
    });
  });

  router.post('/step-up', requireAuth, totpLimiter, async (req, res) => {
    const { password, totpCode } = req.body as { password?: string; totpCode?: string };
    const authUser = req.authUser!;

    const dbUser = db.prepare('SELECT * FROM users WHERE id = ?').get(authUser.id) as DbUser;
    if (!password || !(await verifyPassword(dbUser.password_hash, password))) {
      recordAudit(db, {
        actorUserId: authUser.id,
        actorLabel: authUser.email,
        actorRole: authUser.role,
        action: 'STEP_UP_AUTH_FAILED',
        entityType: 'user',
        entityId: authUser.id,
        ipAddress: getClientIp(req),
      });
      res.status(401).json({ error: 'Re-authentication failed: invalid credentials.' });
      return;
    }

    if (dbUser.totp_enabled && dbUser.totp_secret_encrypted) {
      const secretBase32 = decryptAtRest(dbUser.totp_secret_encrypted, config.sessionSecret);
      if (!totpCode || !verifyTotpCode(secretBase32, totpCode)) {
        res.status(401).json({ error: 'Re-authentication failed: valid 6-digit authenticator code required.' });
        return;
      }
    }

    const stepUpToken = signToken(
      { sub: authUser.id, sid: authUser.sessionId, typ: 'step_up' },
      5 * 60,
      config.sessionSecret,
    );
    setSecureCookie(req, res, COOKIE_STEP_UP, stepUpToken, 5 * 60 * 1000);

    recordAudit(db, {
      actorUserId: authUser.id,
      actorLabel: authUser.email,
      actorRole: authUser.role,
      action: 'STEP_UP_AUTH_VERIFIED',
      entityType: 'user_session',
      entityId: authUser.sessionId,
      ipAddress: getClientIp(req),
    });

    res.json({
      stepUpVerified: true,
      expiresInSeconds: 300,
    });
  });

  router.post('/2fa/regenerate-recovery-codes', requireAuth, requireStepUp, async (req, res) => {
    const authUser = req.authUser!;
    if (!authUser.totpEnabled) {
      res.status(400).json({ error: 'Enable 2FA before regenerating recovery codes.' });
      return;
    }

    const { plaintextCodes, hashedCodes } = await generateRecoveryCodes(8);
    const now = new Date().toISOString();

    const tx = db.transaction(() => {
      db.prepare('DELETE FROM recovery_codes WHERE user_id = ?').run(authUser.id);
      const insert = db.prepare(`
        INSERT INTO recovery_codes (id, user_id, code_hash, created_at) VALUES (?, ?, ?, ?)
      `);
      for (const h of hashedCodes) {
        insert.run(`rec_${crypto.randomUUID()}`, authUser.id, h, now);
      }
      recordAudit(db, {
        actorUserId: authUser.id,
        actorLabel: authUser.email,
        actorRole: authUser.role,
        action: '2FA_RECOVERY_CODES_REGENERATED',
        entityType: 'user',
        entityId: authUser.id,
        ipAddress: getClientIp(req),
      });
    });
    tx();

    res.json({ recoveryCodes: plaintextCodes });
  });

  router.get('/sessions', requireAuth, (req, res) => {
    const authUser = req.authUser!;
    const sessions = db
      .prepare(`
        SELECT id, ip_address, device_label, user_agent, created_at, last_active_at, expires_at, revoked_at, revoke_reason
        FROM user_sessions
        WHERE user_id = ? AND revoked_at IS NULL AND expires_at > ?
        ORDER BY last_active_at DESC
      `)
      .all(authUser.id, new Date().toISOString()) as Array<Record<string, unknown>>;

    res.json({
      sessions: sessions.map((s) => ({
        ...s,
        isCurrent: s.id === authUser.sessionId,
      })),
    });
  });

  router.delete('/sessions/:id', requireAuth, (req, res) => {
    const authUser = req.authUser!;
    const targetId = req.params.id;
    const row = db
      .prepare('SELECT id, user_id FROM user_sessions WHERE id = ?')
      .get(targetId) as { id: string; user_id: string } | undefined;

    if (!row || row.user_id !== authUser.id) {
      res.status(404).json({ error: 'Session not found.' });
      return;
    }

    db.prepare(`
      UPDATE user_sessions SET revoked_at = ?, revoke_reason = 'revoked_by_user' WHERE id = ?
    `).run(new Date().toISOString(), targetId);

    recordAudit(db, {
      actorUserId: authUser.id,
      actorLabel: authUser.email,
      actorRole: authUser.role,
      action: 'SESSION_REVOKED',
      entityType: 'user_session',
      entityId: targetId,
      ipAddress: getClientIp(req),
    });

    if (targetId === authUser.sessionId) {
      clearSecureCookie(req, res, COOKIE_ACCESS);
      clearSecureCookie(req, res, COOKIE_REFRESH);
    }

    res.json({ ok: true });
  });

  router.post('/sessions/revoke-others', requireAuth, (req, res) => {
    const authUser = req.authUser!;
    const result = db
      .prepare(`
        UPDATE user_sessions
        SET revoked_at = ?, revoke_reason = 'revoked_other_devices'
        WHERE user_id = ? AND id != ? AND revoked_at IS NULL
      `)
      .run(new Date().toISOString(), authUser.id, authUser.sessionId);

    recordAudit(db, {
      actorUserId: authUser.id,
      actorLabel: authUser.email,
      actorRole: authUser.role,
      action: 'OTHER_SESSIONS_REVOKED',
      entityType: 'user',
      entityId: authUser.id,
      ipAddress: getClientIp(req),
      metadata: { revokedCount: result.changes },
    });

    res.json({ revokedCount: result.changes });
  });

  router.post('/forgot-password', resetLimiter, async (req, res) => {
    const { email } = req.body as { email?: string };
    const cleanEmail = email?.trim().toLowerCase() || '';

    // Always return identical generic message to prevent account enumeration
    const genericResponse = {
      message:
        'If an active account matches that email address, a password reset instruction has been queued for delivery.',
    };

    if (!cleanEmail || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) {
      res.json(genericResponse);
      return;
    }

    const user = db
      .prepare('SELECT id, email, full_name, role, is_active FROM users WHERE lower(email) = ?')
      .get(cleanEmail) as
      | { id: string; email: string; full_name: string; role: UserRole; is_active: number }
      | undefined;

    if (!user || !user.is_active) {
      recordAudit(db, {
        actorLabel: cleanEmail,
        actorRole: 'Anonymous',
        action: 'PASSWORD_RESET_REQUESTED_UNKNOWN',
        entityType: 'auth',
        ipAddress: getClientIp(req),
      });
      res.json(genericResponse);
      return;
    }

    const rawToken = generateRandomToken(32);
    const tokenHash = sha256Hex(rawToken);
    const now = new Date();
    const expiresAt = new Date(now.getTime() + 30 * 60 * 1000);

    db.prepare(`
      INSERT INTO password_reset_tokens (id, user_id, token_hash, expires_at, ip_address, created_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(
      `pwr_${crypto.randomUUID()}`,
      user.id,
      tokenHash,
      expiresAt.toISOString(),
      getClientIp(req),
      now.toISOString(),
    );

    const origin =
      (req.headers.origin as string | undefined) || config.appUrl;
    const resetLink = `${origin.replace(/\/+$/, '')}/reset-password?token=${encodeURIComponent(rawToken)}`;
    const tpl = buildPasswordResetEmail({
      fullName: user.full_name,
      resetLink,
      expiresMinutes: 30,
      supportEmail: config.supportEmail,
    });

    await emailService.sendEmail({
      to: user.email,
      subject: tpl.subject,
      text: tpl.text,
      html: tpl.html,
      templateName: 'password_reset',
      relatedEntityType: 'user',
      relatedEntityId: user.id,
    });

    recordAudit(db, {
      actorUserId: user.id,
      actorLabel: user.email,
      actorRole: user.role,
      action: 'PASSWORD_RESET_REQUESTED',
      entityType: 'user',
      entityId: user.id,
      ipAddress: getClientIp(req),
    });

    res.json(genericResponse);
  });

  router.post('/reset-password', resetLimiter, async (req, res) => {
    const { token, newPassword } = req.body as { token?: string; newPassword?: string };
    if (!token || !newPassword || newPassword.length < 10) {
      res.status(400).json({
        error: 'A valid reset token and a new password (minimum 10 characters) are required.',
      });
      return;
    }

    const tokenHash = sha256Hex(token.trim());
    const resetRow = db
      .prepare('SELECT * FROM password_reset_tokens WHERE token_hash = ?')
      .get(tokenHash) as
      | { id: string; user_id: string; expires_at: string; used_at: string | null }
      | undefined;

    if (!resetRow || resetRow.used_at || new Date(resetRow.expires_at).getTime() <= Date.now()) {
      res.status(400).json({ error: 'Password reset link is invalid or has expired.' });
      return;
    }

    const pwHash = await hashPassword(newPassword);
    const now = new Date().toISOString();

    const user = db.prepare('SELECT id, email, role FROM users WHERE id = ?').get(resetRow.user_id) as {
      id: string;
      email: string;
      role: UserRole;
    };

    const tx = db.transaction(() => {
      db.prepare(`
        UPDATE users SET password_hash = ?, failed_login_attempts = 0, locked_until = NULL, updated_at = ?
        WHERE id = ?
      `).run(pwHash, now, resetRow.user_id);

      db.prepare('UPDATE password_reset_tokens SET used_at = ? WHERE id = ?').run(now, resetRow.id);

      // Revoke all active sessions after password reset
      db.prepare(`
        UPDATE user_sessions SET revoked_at = ?, revoke_reason = 'password_reset'
        WHERE user_id = ? AND revoked_at IS NULL
      `).run(now, resetRow.user_id);

      recordAudit(db, {
        actorUserId: user.id,
        actorLabel: user.email,
        actorRole: user.role,
        action: 'PASSWORD_RESET_COMPLETED',
        entityType: 'user',
        entityId: user.id,
        ipAddress: getClientIp(req),
      });
    });
    tx();

    res.json({ message: 'Password updated successfully. All prior sessions have been revoked.' });
  });

  return router;
}
