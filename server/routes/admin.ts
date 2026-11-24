import type Database from 'better-sqlite3';
import crypto from 'crypto';
import express from 'express';
import path from 'path';
import { recordAudit } from '../audit.ts';
import type { AppConfig } from '../config.ts';
import { hashPassword } from '../crypto.ts';
import { ALL_ROLES, createDatabaseBackup, type UserRole } from '../db.ts';
import { createAuthMiddleware, getClientIp } from '../middleware.ts';

export function createAdminRouter(db: Database.Database, config: AppConfig): express.Router {
  const router = express.Router();
  const { requireAuth, requireRole, requireStepUp } = createAuthMiddleware(db, config);

  router.use(requireAuth);

  // List internal users (Admin & HR need user directory for assigning recruiters/managers)
  router.get('/users', requireRole('Admin', 'HR'), (req, res) => {
    const users = db
      .prepare(`
        SELECT id, username, email, full_name, role, department, designation,
               manager_id, totp_enabled, is_active, created_at, updated_at
        FROM users
        ORDER BY created_at DESC
      `)
      .all();
    res.json({ users });
  });

  // Create internal user (Admin only)
  router.post('/users', requireRole('Admin'), async (req, res) => {
    const actor = req.authUser!;
    const {
      username,
      email,
      fullName,
      role,
      department,
      designation,
      managerId,
      password,
      ctcAnnual,
    } = req.body as {
      username?: string;
      email?: string;
      fullName?: string;
      role?: UserRole;
      department?: string;
      designation?: string;
      managerId?: string | null;
      password?: string;
      ctcAnnual?: number;
    };

    if (!username?.trim() || !email?.trim() || !fullName?.trim() || !role || !password || password.length < 10) {
      res.status(400).json({
        error: 'Username, email, full name, role, and a password of at least 10 characters are required.',
      });
      return;
    }

    if (!ALL_ROLES.includes(role)) {
      res.status(400).json({ error: 'Invalid role specified.' });
      return;
    }

    const cleanEmail = email.trim().toLowerCase();
    const cleanUsername = username.trim().toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) {
      res.status(400).json({ error: 'Invalid email address.' });
      return;
    }

    const dup = db
      .prepare('SELECT id FROM users WHERE lower(email) = ? OR lower(username) = ?')
      .get(cleanEmail, cleanUsername);
    if (dup) {
      res.status(409).json({ error: 'A user with this email or username already exists.' });
      return;
    }

    const pwHash = await hashPassword(password);
    const userId = `usr_${crypto.randomUUID()}`;
    const empId = `emp_${crypto.randomUUID()}`;
    const now = new Date().toISOString();
    const annual = Number(ctcAnnual || 900000);
    const monthly = Math.round(annual / 12);
    const basic = Math.round(monthly * 0.5);
    const hra = Math.round(monthly * 0.25);
    const allowances = Math.max(0, monthly - basic - hra);
    const empCode = `9HR-${String(Math.floor(1000 + Math.random() * 9000))}`;

    const tx = db.transaction(() => {
      db.prepare(`
        INSERT INTO users (
          id, username, email, full_name, role, department, designation, manager_id,
          password_hash, totp_enabled, is_active, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 1, ?, ?)
      `).run(
        userId,
        cleanUsername,
        cleanEmail,
        fullName.trim(),
        role,
        (department || 'Operations').trim(),
        (designation || role).trim(),
        managerId || null,
        pwHash,
        now,
        now,
      );

      db.prepare(`
        INSERT INTO employees (
          id, user_id, employee_code, full_name, email, department, designation, manager_id,
          joining_date, employment_status, ctc_annual, basic_salary, hra, allowances,
          created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'Active', ?, ?, ?, ?, ?, ?)
      `).run(
        empId,
        userId,
        empCode,
        fullName.trim(),
        cleanEmail,
        (department || 'Operations').trim(),
        (designation || role).trim(),
        managerId || null,
        now.slice(0, 10),
        annual,
        basic,
        hra,
        allowances,
        now,
        now,
      );

      recordAudit(db, {
        actorUserId: actor.id,
        actorLabel: actor.email,
        actorRole: actor.role,
        action: 'USER_CREATED',
        entityType: 'user',
        entityId: userId,
        afterState: { email: cleanEmail, role, department: department || 'Operations' },
        ipAddress: getClientIp(req),
      });
    });
    tx();

    res.status(201).json({
      user: {
        id: userId,
        username: cleanUsername,
        email: cleanEmail,
        fullName: fullName.trim(),
        role,
        department: (department || 'Operations').trim(),
        designation: (designation || role).trim(),
      },
    });
  });

  // Update user role or activation status (Admin + Step-Up Auth)
  router.patch('/users/:id/role', requireRole('Admin'), requireStepUp, (req, res) => {
    const actor = req.authUser!;
    const targetId = req.params.id;
    const { role, isActive } = req.body as { role?: UserRole; isActive?: boolean };

    const target = db.prepare('SELECT * FROM users WHERE id = ?').get(targetId) as
      | { id: string; email: string; role: UserRole; is_active: number }
      | undefined;

    if (!target) {
      res.status(404).json({ error: 'User not found.' });
      return;
    }

    if (target.id === actor.id && isActive === false) {
      res.status(400).json({ error: 'You cannot deactivate your own active Admin account.' });
      return;
    }

    const nextRole = role && ALL_ROLES.includes(role) ? role : target.role;
    const nextActive = typeof isActive === 'boolean' ? (isActive ? 1 : 0) : target.is_active;
    const now = new Date().toISOString();

    const tx = db.transaction(() => {
      db.prepare('UPDATE users SET role = ?, is_active = ?, updated_at = ? WHERE id = ?').run(
        nextRole,
        nextActive,
        now,
        targetId,
      );

      if (nextRole !== target.role || nextActive === 0) {
        db.prepare(`
          UPDATE user_sessions SET revoked_at = ?, revoke_reason = 'role_or_status_changed'
          WHERE user_id = ? AND revoked_at IS NULL
        `).run(now, targetId);
      }

      recordAudit(db, {
        actorUserId: actor.id,
        actorLabel: actor.email,
        actorRole: actor.role,
        action: 'USER_ROLE_PERMISSION_CHANGED',
        entityType: 'user',
        entityId: targetId,
        beforeState: { role: target.role, isActive: Boolean(target.is_active) },
        afterState: { role: nextRole, isActive: Boolean(nextActive) },
        ipAddress: getClientIp(req),
      });
    });
    tx();

    res.json({ ok: true, role: nextRole, isActive: Boolean(nextActive) });
  });

  // Security Policy (Admin reads/updates; HR can read upload/expiry settings)
  router.get('/security-policy', requireRole('Admin', 'HR'), (_req, res) => {
    const policy = db.prepare('SELECT * FROM security_policies WHERE id = 1').get();
    res.json({ policy });
  });

  router.put('/security-policy', requireRole('Admin'), requireStepUp, (req, res) => {
    const actor = req.authUser!;
    const before = db.prepare('SELECT * FROM security_policies WHERE id = 1').get() as Record<string, unknown>;
    const {
      require2faForEmployees,
      candidateLinkExpiryHours,
      maxUploadSizeMb,
      lockoutThreshold,
      lockoutDurationMinutes,
      sessionTimeoutMinutes,
    } = req.body as Record<string, unknown>;

    const nextRequire2fa =
      typeof require2faForEmployees === 'boolean'
        ? require2faForEmployees
          ? 1
          : 0
        : Number(before.require_2fa_for_employees);
    const nextExpiry = Math.max(1, Math.min(720, Number(candidateLinkExpiryHours ?? before.candidate_link_expiry_hours)));
    const nextMaxUpload = Math.max(1, Math.min(25, Number(maxUploadSizeMb ?? before.max_upload_size_mb)));
    const nextThreshold = Math.max(3, Math.min(20, Number(lockoutThreshold ?? before.lockout_threshold)));
    const nextDuration = Math.max(5, Math.min(120, Number(lockoutDurationMinutes ?? before.lockout_duration_minutes)));
    const nextSessionTimeout = Math.max(15, Math.min(1440, Number(sessionTimeoutMinutes ?? before.session_timeout_minutes)));
    const now = new Date().toISOString();

    db.prepare(`
      UPDATE security_policies
      SET require_2fa_for_employees = ?,
          candidate_link_expiry_hours = ?,
          max_upload_size_mb = ?,
          lockout_threshold = ?,
          lockout_duration_minutes = ?,
          session_timeout_minutes = ?,
          updated_by = ?,
          updated_at = ?
      WHERE id = 1
    `).run(
      nextRequire2fa,
      nextExpiry,
      nextMaxUpload,
      nextThreshold,
      nextDuration,
      nextSessionTimeout,
      actor.email,
      now,
    );

    const after = db.prepare('SELECT * FROM security_policies WHERE id = 1').get();

    recordAudit(db, {
      actorUserId: actor.id,
      actorLabel: actor.email,
      actorRole: actor.role,
      action: 'SECURITY_POLICY_UPDATED',
      entityType: 'security_policy',
      entityId: '1',
      beforeState: before,
      afterState: after,
      ipAddress: getClientIp(req),
    });

    res.json({ policy: after });
  });

  // Role permissions matrix (Admin only)
  router.get('/role-permissions', requireRole('Admin'), (_req, res) => {
    const rows = db.prepare('SELECT * FROM role_permissions').all() as Array<{
      role: UserRole;
      permissions_json: string;
      updated_by: string;
      updated_at: string;
    }>;
    res.json({
      roles: rows.map((r) => ({
        role: r.role,
        permissions: JSON.parse(r.permissions_json) as string[],
        updatedBy: r.updated_by,
        updatedAt: r.updated_at,
      })),
    });
  });

  router.put('/role-permissions/:role', requireRole('Admin'), requireStepUp, (req, res) => {
    const actor = req.authUser!;
    const targetRole = req.params.role as UserRole;
    if (!ALL_ROLES.includes(targetRole)) {
      res.status(400).json({ error: 'Invalid role.' });
      return;
    }
    if (targetRole === 'Admin') {
      res.status(400).json({ error: 'Admin baseline permissions cannot be stripped.' });
      return;
    }

    const { permissions } = req.body as { permissions?: string[] };
    if (!Array.isArray(permissions)) {
      res.status(400).json({ error: 'permissions array is required.' });
      return;
    }

    const cleanPerms = Array.from(new Set(permissions.map((p) => String(p).trim()).filter(Boolean)));
    const before = db
      .prepare('SELECT permissions_json FROM role_permissions WHERE role = ?')
      .get(targetRole) as { permissions_json: string } | undefined;

    const now = new Date().toISOString();
    db.prepare(`
      UPDATE role_permissions SET permissions_json = ?, updated_by = ?, updated_at = ? WHERE role = ?
    `).run(JSON.stringify(cleanPerms), actor.email, now, targetRole);

    recordAudit(db, {
      actorUserId: actor.id,
      actorLabel: actor.email,
      actorRole: actor.role,
      action: 'ROLE_PERMISSIONS_UPDATED',
      entityType: 'role_permissions',
      entityId: targetRole,
      beforeState: before ? JSON.parse(before.permissions_json) : [],
      afterState: cleanPerms,
      ipAddress: getClientIp(req),
    });

    res.json({ role: targetRole, permissions: cleanPerms });
  });

  // Document checklist configuration (HR & Admin)
  router.get('/document-requirements', requireRole('HR', 'Admin'), (_req, res) => {
    const items = db
      .prepare('SELECT * FROM document_requirements ORDER BY sort_order ASC')
      .all();
    res.json({ requirements: items });
  });

  router.put('/document-requirements', requireRole('HR', 'Admin'), (req, res) => {
    const actor = req.authUser!;
    const { requirements } = req.body as {
      requirements?: Array<{
        id: string;
        is_mandatory: boolean | number;
        is_enabled: boolean | number;
        max_size_mb: number;
        description?: string;
      }>;
    };

    if (!Array.isArray(requirements)) {
      res.status(400).json({ error: 'requirements array is required.' });
      return;
    }

    const now = new Date().toISOString();
    const updateStmt = db.prepare(`
      UPDATE document_requirements
      SET is_mandatory = ?, is_enabled = ?, max_size_mb = ?, description = COALESCE(?, description),
          updated_by = ?, updated_at = ?
      WHERE id = ?
    `);

    const tx = db.transaction(() => {
      for (const item of requirements) {
        updateStmt.run(
          item.is_mandatory ? 1 : 0,
          item.is_enabled ? 1 : 0,
          Math.max(1, Math.min(25, Number(item.max_size_mb || 5))),
          item.description ?? null,
          actor.email,
          now,
          item.id,
        );
      }
      recordAudit(db, {
        actorUserId: actor.id,
        actorLabel: actor.email,
        actorRole: actor.role,
        action: 'DOCUMENT_CHECKLIST_CONFIG_UPDATED',
        entityType: 'document_requirements',
        afterState: requirements.map((r) => ({
          id: r.id,
          mandatory: Boolean(r.is_mandatory),
          enabled: Boolean(r.is_enabled),
          maxSizeMb: r.max_size_mb,
        })),
        ipAddress: getClientIp(req),
      });
    });
    tx();

    const updated = db.prepare('SELECT * FROM document_requirements ORDER BY sort_order ASC').all();
    res.json({ requirements: updated });
  });

  // Read-only Audit Logs (Admin only; no mutation routes exist)
  router.get('/audit-logs', requireRole('Admin'), (req, res) => {
    const limit = Math.min(200, Math.max(10, Number(req.query.limit || 100)));
    const actionFilter = typeof req.query.action === 'string' ? req.query.action.trim() : '';
    const logs = actionFilter
      ? db
          .prepare('SELECT * FROM audit_logs WHERE action LIKE ? ORDER BY created_at DESC LIMIT ?')
          .all(`%${actionFilter}%`, limit)
      : db.prepare('SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT ?').all(limit);

    res.json({ logs });
  });

  router.get('/email-deliveries', requireRole('Admin', 'HR'), (_req, res) => {
    const deliveries = db
      .prepare('SELECT * FROM email_deliveries ORDER BY created_at DESC LIMIT 100')
      .all();
    res.json({ deliveries });
  });

  router.post('/backup', requireRole('Admin'), requireStepUp, async (req, res) => {
    const actor = req.authUser!;
    const backupDir = path.resolve(config.privateStorageDir, 'backups');
    const dest = await createDatabaseBackup(db, backupDir);

    recordAudit(db, {
      actorUserId: actor.id,
      actorLabel: actor.email,
      actorRole: actor.role,
      action: 'DATABASE_BACKUP_CREATED',
      entityType: 'system',
      metadata: { filename: path.basename(dest) },
      ipAddress: getClientIp(req),
    });

    res.json({ ok: true, filename: path.basename(dest) });
  });

  return router;
}
