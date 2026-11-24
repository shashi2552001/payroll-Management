import type Database from 'better-sqlite3';
import crypto from 'crypto';
import express from 'express';
import { createNotification, recordAudit } from '../audit.ts';
import type { AppConfig } from '../config.ts';
import { encryptAtRest, maskBankAccount } from '../crypto.ts';
import { createAuthMiddleware, getClientIp } from '../middleware.ts';

export function createHrRouter(db: Database.Database, config: AppConfig): express.Router {
  const router = express.Router();
  const { requireAuth, requireRole, requireStepUp } = createAuthMiddleware(db, config);

  router.use(requireAuth);

  // RBAC-scoped employees view (prevents horizontal & vertical privilege escalation)
  router.get('/employees', (req, res) => {
    const actor = req.authUser!;

    if (actor.role === 'Employee') {
      const self = db
        .prepare(`
          SELECT id, user_id, employee_code, full_name, email, mobile, department, designation,
                 joining_date, employment_status, ctc_annual, basic_salary, hra, allowances,
                 pf_number, esi_number, pan_number, bank_name, bank_account_masked, ifsc_code
          FROM employees WHERE user_id = ?
        `)
        .all(actor.id);
      res.json({ employees: self });
      return;
    }

    if (actor.role === 'Manager') {
      const team = db
        .prepare(`
          SELECT id, user_id, employee_code, full_name, email, mobile, department, designation,
                 joining_date, employment_status
          FROM employees
          WHERE user_id = ? OR manager_id = ?
          ORDER BY full_name ASC
        `)
        .all(actor.id, actor.id);
      res.json({ employees: team });
      return;
    }

    if (actor.role === 'HR') {
      const all = db
        .prepare(`
          SELECT id, user_id, employee_code, full_name, email, mobile, department, designation,
                 manager_id, joining_date, employment_status, source_candidate_id
          FROM employees
          ORDER BY created_at DESC
        `)
        .all();
      res.json({ employees: all });
      return;
    }

    // Accounts & Admin can access payroll/statutory/masked bank fields
    const full = db
      .prepare(`
        SELECT id, user_id, employee_code, full_name, email, mobile, department, designation,
               manager_id, joining_date, employment_status, ctc_annual, basic_salary, hra, allowances,
               pf_number, esi_number, pan_number, bank_name, bank_account_masked, ifsc_code, source_candidate_id
        FROM employees
        ORDER BY created_at DESC
      `)
      .all();
    res.json({ employees: full });
  });

  // Update bank details (requires Step-Up Re-authentication + self OR Accounts/Admin)
  router.patch('/employees/:id/bank-details', requireStepUp, (req, res) => {
    const actor = req.authUser!;
    const targetId = req.params.id;
    const emp = db.prepare('SELECT * FROM employees WHERE id = ?').get(targetId) as
      | { id: string; user_id: string | null; full_name: string; bank_name: string; bank_account_masked: string; ifsc_code: string }
      | undefined;

    if (!emp) {
      res.status(404).json({ error: 'Employee record not found.' });
      return;
    }

    const isSelf = emp.user_id === actor.id;
    const isAuthorizedRole = actor.role === 'Accounts' || actor.role === 'Admin';
    if (!isSelf && !isAuthorizedRole) {
      res.status(403).json({ error: 'Forbidden: you cannot modify another employee’s bank details.' });
      return;
    }

    const { bankName, accountNumber, ifscCode } = req.body as {
      bankName?: string;
      accountNumber?: string;
      ifscCode?: string;
    };

    const cleanIfsc = (ifscCode || '').trim().toUpperCase();
    if (!bankName?.trim() || !accountNumber?.trim() || !/^[A-Z]{4}0[A-Z0-9]{6}$/.test(cleanIfsc)) {
      res.status(400).json({ error: 'Valid bank name, account number, and 11-character IFSC code are required.' });
      return;
    }

    const cleanAcc = accountNumber.replace(/\s+/g, '');
    const masked = maskBankAccount(cleanAcc);
    const encrypted = encryptAtRest(cleanAcc, config.sessionSecret);
    const now = new Date().toISOString();

    db.prepare(`
      UPDATE employees
      SET bank_name = ?, bank_account_masked = ?, bank_account_encrypted = ?, ifsc_code = ?, updated_at = ?
      WHERE id = ?
    `).run(bankName.trim(), masked, encrypted, cleanIfsc, now, targetId);

    recordAudit(db, {
      actorUserId: actor.id,
      actorLabel: actor.email,
      actorRole: actor.role,
      action: 'EMPLOYEE_BANK_DETAILS_UPDATED',
      entityType: 'employee',
      entityId: targetId,
      beforeState: { bankName: emp.bank_name, maskedAccount: emp.bank_account_masked, ifsc: emp.ifsc_code },
      afterState: { bankName: bankName.trim(), maskedAccount: masked, ifsc: cleanIfsc },
      ipAddress: getClientIp(req),
    });

    res.json({ ok: true, bankName: bankName.trim(), bankAccountMasked: masked, ifscCode: cleanIfsc });
  });

  // Update salary / statutory details (Accounts or Admin + Step-Up Auth)
  router.patch('/employees/:id/salary', requireRole('Accounts', 'Admin'), requireStepUp, (req, res) => {
    const actor = req.authUser!;
    const targetId = req.params.id;
    const emp = db.prepare('SELECT * FROM employees WHERE id = ?').get(targetId) as
      | { id: string; ctc_annual: number; basic_salary: number; hra: number; allowances: number; pf_number: string; pan_number: string }
      | undefined;

    if (!emp) {
      res.status(404).json({ error: 'Employee record not found.' });
      return;
    }

    const { ctcAnnual, pfNumber, esiNumber, panNumber } = req.body as {
      ctcAnnual?: number;
      pfNumber?: string;
      esiNumber?: string;
      panNumber?: string;
    };

    const annual = Math.max(0, Math.round(Number(ctcAnnual ?? emp.ctc_annual)));
    const monthly = Math.round(annual / 12);
    const basic = Math.round(monthly * 0.5);
    const hra = Math.round(monthly * 0.25);
    const allowances = Math.max(0, monthly - basic - hra);
    const now = new Date().toISOString();

    db.prepare(`
      UPDATE employees
      SET ctc_annual = ?, basic_salary = ?, hra = ?, allowances = ?,
          pf_number = COALESCE(?, pf_number), esi_number = COALESCE(?, esi_number),
          pan_number = COALESCE(?, pan_number), updated_at = ?
      WHERE id = ?
    `).run(annual, basic, hra, allowances, pfNumber ?? null, esiNumber ?? null, panNumber ?? null, now, targetId);

    recordAudit(db, {
      actorUserId: actor.id,
      actorLabel: actor.email,
      actorRole: actor.role,
      action: 'EMPLOYEE_SALARY_UPDATED',
      entityType: 'employee',
      entityId: targetId,
      beforeState: { ctcAnnual: emp.ctc_annual },
      afterState: { ctcAnnual: annual },
      ipAddress: getClientIp(req),
    });

    res.json({ ok: true, ctcAnnual: annual, basicSalary: basic, hra, allowances });
  });

  // Leave Management (ESS + Manager team approvals + HR approvals)
  router.get('/leaves', (req, res) => {
    const actor = req.authUser!;
    if (actor.role === 'Employee' || actor.role === 'Accounts') {
      const rows = db
        .prepare(`
          SELECT l.*, e.full_name AS employee_name, e.department
          FROM leave_requests l
          JOIN employees e ON e.id = l.employee_id
          WHERE e.user_id = ?
          ORDER BY l.created_at DESC
        `)
        .all(actor.id);
      res.json({ leaves: rows });
      return;
    }

    if (actor.role === 'Manager') {
      const rows = db
        .prepare(`
          SELECT l.*, e.full_name AS employee_name, e.department
          FROM leave_requests l
          JOIN employees e ON e.id = l.employee_id
          WHERE e.user_id = ? OR e.manager_id = ?
          ORDER BY l.created_at DESC
        `)
        .all(actor.id, actor.id);
      res.json({ leaves: rows });
      return;
    }

    const rows = db
      .prepare(`
        SELECT l.*, e.full_name AS employee_name, e.department
        FROM leave_requests l
        JOIN employees e ON e.id = l.employee_id
        ORDER BY l.created_at DESC
      `)
      .all();
    res.json({ leaves: rows });
  });

  router.post('/leaves', (req, res) => {
    const actor = req.authUser!;
    const emp = db.prepare('SELECT id, manager_id, full_name FROM employees WHERE user_id = ?').get(actor.id) as
      | { id: string; manager_id: string | null; full_name: string }
      | undefined;

    if (!emp) {
      res.status(400).json({ error: 'No employee profile linked to your user account.' });
      return;
    }

    const { leaveType, startDate, endDate, days, reason } = req.body as {
      leaveType?: string;
      startDate?: string;
      endDate?: string;
      days?: number;
      reason?: string;
    };

    if (!leaveType || !startDate || !endDate || !reason?.trim()) {
      res.status(400).json({ error: 'Leave type, start date, end date, and reason are required.' });
      return;
    }

    const id = `lv_${crypto.randomUUID()}`;
    const now = new Date().toISOString();
    db.prepare(`
      INSERT INTO leave_requests (id, employee_id, leave_type, start_date, end_date, days, reason, status, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, 'Pending', ?)
    `).run(id, emp.id, leaveType, startDate, endDate, Math.max(1, Number(days || 1)), reason.trim(), now);

    if (emp.manager_id) {
      createNotification(db, {
        recipientUserId: emp.manager_id,
        title: 'Leave Request Submitted',
        message: `${emp.full_name} requested ${leaveType} (${startDate} to ${endDate}).`,
        category: 'action',
        relatedEntityType: 'leave',
        relatedEntityId: id,
      });
    }

    res.status(201).json({ id, status: 'Pending' });
  });

  router.patch('/leaves/:id/review', requireRole('Manager', 'HR', 'Admin'), (req, res) => {
    const actor = req.authUser!;
    const { decision, note } = req.body as { decision?: 'Approved' | 'Rejected'; note?: string };
    if (decision !== 'Approved' && decision !== 'Rejected') {
      res.status(400).json({ error: 'Decision must be Approved or Rejected.' });
      return;
    }

    const row = db
      .prepare(`
        SELECT l.*, e.manager_id, e.user_id AS emp_user_id, e.full_name
        FROM leave_requests l
        JOIN employees e ON e.id = l.employee_id
        WHERE l.id = ?
      `)
      .get(req.params.id) as
      | { id: string; manager_id: string | null; emp_user_id: string | null; status: string; full_name: string }
      | undefined;

    if (!row) {
      res.status(404).json({ error: 'Leave request not found.' });
      return;
    }

    // Manager can ONLY approve their direct reports
    if (actor.role === 'Manager' && row.manager_id !== actor.id) {
      res.status(403).json({ error: 'Forbidden: Managers can only review direct reports.' });
      return;
    }

    const now = new Date().toISOString();
    db.prepare(`
      UPDATE leave_requests SET status = ?, reviewed_by = ?, reviewed_at = ?, review_note = ? WHERE id = ?
    `).run(decision, actor.id, now, note || '', row.id);

    if (row.emp_user_id) {
      createNotification(db, {
        recipientUserId: row.emp_user_id,
        title: `Leave Request ${decision}`,
        message: `Your leave request was ${decision.toLowerCase()} by ${actor.fullName}.`,
        category: decision === 'Approved' ? 'success' : 'warning',
        relatedEntityType: 'leave',
        relatedEntityId: row.id,
      });
    }

    res.json({ ok: true, status: decision });
  });

  // Payroll & Statutory (Accounts & Admin only)
  router.get('/payroll/runs', requireRole('Accounts', 'Admin'), (_req, res) => {
    const runs = db.prepare('SELECT * FROM payroll_runs ORDER BY month_year DESC').all();
    res.json({ runs });
  });

  router.post('/payroll/runs', requireRole('Accounts', 'Admin'), (req, res) => {
    const actor = req.authUser!;
    const { monthYear } = req.body as { monthYear?: string };
    if (!monthYear || !/^\d{4}-\d{2}$/.test(monthYear)) {
      res.status(400).json({ error: 'Provide monthYear in YYYY-MM format.' });
      return;
    }

    const existing = db.prepare('SELECT id FROM payroll_runs WHERE month_year = ?').get(monthYear);
    if (existing) {
      res.status(409).json({ error: `Payroll run for ${monthYear} already exists.` });
      return;
    }

    const activeEmployees = db
      .prepare("SELECT * FROM employees WHERE employment_status = 'Active' AND ctc_annual > 0")
      .all() as Array<{
      id: string;
      basic_salary: number;
      hra: number;
      allowances: number;
    }>;

    const runId = `pay_${crypto.randomUUID()}`;
    const now = new Date().toISOString();
    let totalGross = 0;
    let totalPf = 0;
    let totalEsi = 0;
    let totalPt = 0;
    let totalTds = 0;
    let totalNet = 0;

    const tx = db.transaction(() => {
      db.prepare(`
        INSERT INTO payroll_runs (
          id, month_year, total_gross, total_pf, total_esi, total_pt, total_tds,
          total_net, employee_count, status, processed_by, processed_at, created_at
        ) VALUES (?, ?, 0, 0, 0, 0, 0, 0, ?, 'Processed', ?, ?, ?)
      `).run(runId, monthYear, activeEmployees.length, actor.id, now, now);

      const insertSlip = db.prepare(`
        INSERT INTO payslips (
          id, payroll_run_id, employee_id, gross_pay, pf_deduction, esi_deduction,
          pt_deduction, tds_deduction, net_pay, status, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'Issued', ?)
      `);

      for (const e of activeEmployees) {
        const gross = e.basic_salary + e.hra + e.allowances;
        const pf = Math.round(Math.min(e.basic_salary, 15000) * 0.12);
        const esi = gross <= 21000 ? Math.round(gross * 0.0075) : 0;
        const pt = gross > 15000 ? 200 : 0;
        const tds = gross > 60000 ? Math.round((gross - 60000) * 0.1) : 0;
        const net = Math.max(0, gross - pf - esi - pt - tds);

        totalGross += gross;
        totalPf += pf;
        totalEsi += esi;
        totalPt += pt;
        totalTds += tds;
        totalNet += net;

        insertSlip.run(`ps_${crypto.randomUUID()}`, runId, e.id, gross, pf, esi, pt, tds, net, now);
      }

      db.prepare(`
        UPDATE payroll_runs
        SET total_gross = ?, total_pf = ?, total_esi = ?, total_pt = ?, total_tds = ?, total_net = ?
        WHERE id = ?
      `).run(totalGross, totalPf, totalEsi, totalPt, totalTds, totalNet, runId);

      recordAudit(db, {
        actorUserId: actor.id,
        actorLabel: actor.email,
        actorRole: actor.role,
        action: 'PAYROLL_RUN_PROCESSED',
        entityType: 'payroll_run',
        entityId: runId,
        afterState: { monthYear, employeeCount: activeEmployees.length, totalNet },
        ipAddress: getClientIp(req),
      });
    });
    tx();

    const run = db.prepare('SELECT * FROM payroll_runs WHERE id = ?').get(runId);
    res.status(201).json({ run });
  });

  router.get('/payroll/my-payslips', (req, res) => {
    const actor = req.authUser!;
    const payslips = db
      .prepare(`
        SELECT p.*, r.month_year
        FROM payslips p
        JOIN payroll_runs r ON r.id = p.payroll_run_id
        JOIN employees e ON e.id = p.employee_id
        WHERE e.user_id = ?
        ORDER BY r.month_year DESC
      `)
      .all(actor.id);
    res.json({ payslips });
  });

  // In-App Notification Centre
  router.get('/notifications', (req, res) => {
    const actor = req.authUser!;
    const notifications = db
      .prepare('SELECT * FROM notifications WHERE recipient_user_id = ? ORDER BY created_at DESC LIMIT 50')
      .all(actor.id);
    res.json({ notifications });
  });

  router.patch('/notifications/:id/read', (req, res) => {
    const actor = req.authUser!;
    db.prepare('UPDATE notifications SET is_read = 1 WHERE id = ? AND recipient_user_id = ?').run(
      req.params.id,
      actor.id,
    );
    res.json({ ok: true });
  });

  router.post('/notifications/read-all', (req, res) => {
    const actor = req.authUser!;
    db.prepare('UPDATE notifications SET is_read = 1 WHERE recipient_user_id = ?').run(actor.id);
    res.json({ ok: true });
  });

  return router;
}
