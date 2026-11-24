import Database from 'better-sqlite3';
import fs from 'fs';
import path from 'path';

export type UserRole = 'Employee' | 'Manager' | 'HR' | 'Accounts' | 'Admin';

export const ALL_ROLES: UserRole[] = ['Employee', 'Manager', 'HR', 'Accounts', 'Admin'];

export const MANDATORY_2FA_ROLES: ReadonlySet<UserRole> = new Set([
  'Admin',
  'HR',
  'Accounts',
  'Manager',
]);

export const DEFAULT_ROLE_PERMISSIONS: Record<UserRole, string[]> = {
  Employee: [
    'ess:read_self',
    'ess:submit_leave',
    'ess:update_own_bank',
    'payslip:read_self',
  ],
  Manager: [
    'ess:read_self',
    'ess:submit_leave',
    'ess:update_own_bank',
    'payslip:read_self',
    'team:read',
    'leave:approve_team',
    'recruitment:view_assigned',
  ],
  HR: [
    'ess:read_self',
    'ess:submit_leave',
    'payslip:read_self',
    'employees:read',
    'employees:manage',
    'leave:approve_any',
    'recruitment:manage',
    'candidates:manage',
    'candidates:verify_docs',
    'doc_requirements:configure',
    'onboarding:approve',
  ],
  Accounts: [
    'ess:read_self',
    'ess:submit_leave',
    'payslip:read_self',
    'employees:read_financial',
    'employees:update_bank_salary',
    'payroll:manage',
    'statutory:manage',
  ],
  Admin: [
    'ess:read_self',
    'ess:submit_leave',
    'payslip:read_self',
    'employees:read',
    'employees:manage',
    'employees:read_financial',
    'employees:update_bank_salary',
    'leave:approve_any',
    'recruitment:manage',
    'candidates:manage',
    'candidates:verify_docs',
    'doc_requirements:configure',
    'onboarding:approve',
    'payroll:manage',
    'statutory:manage',
    'admin:users',
    'admin:roles',
    'admin:security_policy',
    'admin:audit_read',
    'admin:backup',
  ],
};

export function initDatabase(dbPath: string): Database.Database {
  const dir = path.dirname(dbPath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }

  const db = new Database(dbPath);
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');
  db.pragma('busy_timeout = 5000');

  runMigrations(db);
  return db;
}

function runMigrations(db: Database.Database): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      id TEXT PRIMARY KEY,
      applied_at TEXT NOT NULL
    );
  `);

  const applied = new Set(
    (db.prepare('SELECT id FROM schema_migrations').all() as Array<{ id: string }>).map((r) => r.id),
  );

  if (!applied.has('001_initial_9hr_security_and_candidates')) {
    const migrate = db.transaction(() => {
      db.exec(`
        CREATE TABLE IF NOT EXISTS users (
          id TEXT PRIMARY KEY,
          username TEXT NOT NULL UNIQUE COLLATE NOCASE,
          email TEXT NOT NULL UNIQUE COLLATE NOCASE,
          full_name TEXT NOT NULL,
          role TEXT NOT NULL CHECK(role IN ('Employee', 'Manager', 'HR', 'Accounts', 'Admin')),
          department TEXT NOT NULL DEFAULT 'General',
          designation TEXT NOT NULL DEFAULT 'Staff',
          manager_id TEXT REFERENCES users(id) ON DELETE SET NULL,
          password_hash TEXT NOT NULL,
          totp_secret_encrypted TEXT,
          totp_enabled INTEGER NOT NULL DEFAULT 0,
          totp_verified_at TEXT,
          failed_login_attempts INTEGER NOT NULL DEFAULT 0,
          locked_until TEXT,
          is_active INTEGER NOT NULL DEFAULT 1,
          must_change_password INTEGER NOT NULL DEFAULT 0,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS recovery_codes (
          id TEXT PRIMARY KEY,
          user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          code_hash TEXT NOT NULL,
          used_at TEXT,
          created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS user_sessions (
          id TEXT PRIMARY KEY,
          user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          token_family_id TEXT NOT NULL,
          refresh_token_hash TEXT NOT NULL UNIQUE,
          access_jti TEXT NOT NULL,
          ip_address TEXT,
          user_agent TEXT,
          device_label TEXT,
          created_at TEXT NOT NULL,
          last_active_at TEXT NOT NULL,
          expires_at TEXT NOT NULL,
          revoked_at TEXT,
          revoke_reason TEXT
        );

        CREATE TABLE IF NOT EXISTS password_reset_tokens (
          id TEXT PRIMARY KEY,
          user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          token_hash TEXT NOT NULL UNIQUE,
          expires_at TEXT NOT NULL,
          used_at TEXT,
          ip_address TEXT,
          created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS security_policies (
          id INTEGER PRIMARY KEY CHECK(id = 1),
          require_2fa_for_employees INTEGER NOT NULL DEFAULT 0,
          candidate_link_expiry_hours INTEGER NOT NULL DEFAULT 72,
          max_upload_size_mb INTEGER NOT NULL DEFAULT 5,
          lockout_threshold INTEGER NOT NULL DEFAULT 5,
          lockout_duration_minutes INTEGER NOT NULL DEFAULT 15,
          session_timeout_minutes INTEGER NOT NULL DEFAULT 480,
          updated_by TEXT,
          updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS role_permissions (
          role TEXT PRIMARY KEY CHECK(role IN ('Employee', 'Manager', 'HR', 'Accounts', 'Admin')),
          permissions_json TEXT NOT NULL,
          updated_by TEXT,
          updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS employees (
          id TEXT PRIMARY KEY,
          user_id TEXT UNIQUE REFERENCES users(id) ON DELETE SET NULL,
          employee_code TEXT NOT NULL UNIQUE,
          full_name TEXT NOT NULL,
          email TEXT NOT NULL UNIQUE COLLATE NOCASE,
          mobile TEXT NOT NULL DEFAULT '',
          department TEXT NOT NULL,
          designation TEXT NOT NULL,
          manager_id TEXT REFERENCES users(id) ON DELETE SET NULL,
          joining_date TEXT NOT NULL,
          employment_status TEXT NOT NULL DEFAULT 'Active',
          ctc_annual INTEGER NOT NULL DEFAULT 0,
          basic_salary INTEGER NOT NULL DEFAULT 0,
          hra INTEGER NOT NULL DEFAULT 0,
          allowances INTEGER NOT NULL DEFAULT 0,
          pf_number TEXT NOT NULL DEFAULT '',
          esi_number TEXT NOT NULL DEFAULT '',
          pan_number TEXT NOT NULL DEFAULT '',
          bank_name TEXT NOT NULL DEFAULT '',
          bank_account_masked TEXT NOT NULL DEFAULT '',
          bank_account_encrypted TEXT NOT NULL DEFAULT '',
          ifsc_code TEXT NOT NULL DEFAULT '',
          source_candidate_id TEXT,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS leave_requests (
          id TEXT PRIMARY KEY,
          employee_id TEXT NOT NULL REFERENCES employees(id) ON DELETE CASCADE,
          leave_type TEXT NOT NULL,
          start_date TEXT NOT NULL,
          end_date TEXT NOT NULL,
          days INTEGER NOT NULL,
          reason TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'Pending' CHECK(status IN ('Pending', 'Approved', 'Rejected')),
          reviewed_by TEXT REFERENCES users(id) ON DELETE SET NULL,
          reviewed_at TEXT,
          review_note TEXT,
          created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS payroll_runs (
          id TEXT PRIMARY KEY,
          month_year TEXT NOT NULL UNIQUE,
          total_gross INTEGER NOT NULL,
          total_pf INTEGER NOT NULL,
          total_esi INTEGER NOT NULL,
          total_pt INTEGER NOT NULL,
          total_tds INTEGER NOT NULL,
          total_net INTEGER NOT NULL,
          employee_count INTEGER NOT NULL,
          status TEXT NOT NULL DEFAULT 'Processed' CHECK(status IN ('Draft', 'Processed', 'Disbursed')),
          processed_by TEXT REFERENCES users(id) ON DELETE SET NULL,
          processed_at TEXT NOT NULL,
          created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS payslips (
          id TEXT PRIMARY KEY,
          payroll_run_id TEXT NOT NULL REFERENCES payroll_runs(id) ON DELETE CASCADE,
          employee_id TEXT NOT NULL REFERENCES employees(id) ON DELETE CASCADE,
          gross_pay INTEGER NOT NULL,
          pf_deduction INTEGER NOT NULL,
          esi_deduction INTEGER NOT NULL,
          pt_deduction INTEGER NOT NULL,
          tds_deduction INTEGER NOT NULL,
          net_pay INTEGER NOT NULL,
          status TEXT NOT NULL DEFAULT 'Issued',
          created_at TEXT NOT NULL,
          UNIQUE(payroll_run_id, employee_id)
        );

        CREATE TABLE IF NOT EXISTS candidates (
          id TEXT PRIMARY KEY,
          full_name TEXT NOT NULL,
          email TEXT NOT NULL UNIQUE COLLATE NOCASE,
          mobile TEXT NOT NULL,
          job_position TEXT NOT NULL,
          department TEXT NOT NULL,
          assigned_recruiter_id TEXT NOT NULL REFERENCES users(id),
          experience_years REAL NOT NULL DEFAULT 0,
          expected_ctc TEXT NOT NULL DEFAULT '',
          notice_period_days INTEGER NOT NULL DEFAULT 30,
          notes TEXT NOT NULL DEFAULT '',
          email_confirmed_by_recruiter INTEGER NOT NULL DEFAULT 0,
          status TEXT NOT NULL DEFAULT 'New',
          doc_verification_status TEXT NOT NULL DEFAULT 'Not Started',
          hr_approved_by TEXT REFERENCES users(id) ON DELETE SET NULL,
          hr_approved_at TEXT,
          offer_letter_sent_at TEXT,
          created_by TEXT NOT NULL REFERENCES users(id),
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS document_requirements (
          id TEXT PRIMARY KEY,
          doc_type TEXT NOT NULL UNIQUE,
          label TEXT NOT NULL,
          description TEXT NOT NULL,
          is_mandatory INTEGER NOT NULL DEFAULT 1,
          is_enabled INTEGER NOT NULL DEFAULT 1,
          allowed_extensions TEXT NOT NULL DEFAULT 'pdf,jpg,jpeg,png',
          max_size_mb INTEGER NOT NULL DEFAULT 5,
          sort_order INTEGER NOT NULL DEFAULT 0,
          updated_by TEXT,
          updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS candidate_invitations (
          id TEXT PRIMARY KEY,
          candidate_id TEXT NOT NULL REFERENCES candidates(id) ON DELETE CASCADE,
          token_hash TEXT NOT NULL UNIQUE,
          purpose TEXT NOT NULL DEFAULT 'initial_upload' CHECK(purpose IN ('initial_upload', 'reupload')),
          target_doc_types_json TEXT,
          idempotency_key TEXT UNIQUE,
          expires_at TEXT NOT NULL,
          accepted_at TEXT,
          revoked_at TEXT,
          revoke_reason TEXT,
          sent_by TEXT NOT NULL REFERENCES users(id),
          sent_to_email TEXT NOT NULL,
          email_delivery_status TEXT NOT NULL DEFAULT 'pending',
          email_delivery_error TEXT,
          created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS candidate_upload_sessions (
          id TEXT PRIMARY KEY,
          candidate_id TEXT NOT NULL REFERENCES candidates(id) ON DELETE CASCADE,
          invitation_id TEXT NOT NULL REFERENCES candidate_invitations(id) ON DELETE CASCADE,
          session_token_hash TEXT NOT NULL UNIQUE,
          ip_address TEXT,
          user_agent TEXT,
          expires_at TEXT NOT NULL,
          revoked_at TEXT,
          submitted_at TEXT,
          created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS candidate_documents (
          id TEXT PRIMARY KEY,
          candidate_id TEXT NOT NULL REFERENCES candidates(id) ON DELETE CASCADE,
          requirement_id TEXT NOT NULL REFERENCES document_requirements(id),
          doc_type TEXT NOT NULL,
          original_filename TEXT NOT NULL,
          stored_filename TEXT NOT NULL,
          mime_type TEXT NOT NULL,
          file_size_bytes INTEGER NOT NULL,
          sha256_hash TEXT NOT NULL,
          malware_scan_status TEXT NOT NULL DEFAULT 'clean',
          malware_scan_detail TEXT NOT NULL DEFAULT '',
          status TEXT NOT NULL DEFAULT 'Uploaded' CHECK(status IN ('Pending', 'Uploaded', 'Approved', 'Rejected', 'Re-upload Required')),
          rejection_reason TEXT,
          reviewed_by TEXT REFERENCES users(id) ON DELETE SET NULL,
          reviewed_at TEXT,
          version INTEGER NOT NULL DEFAULT 1,
          is_current INTEGER NOT NULL DEFAULT 1,
          uploaded_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS notifications (
          id TEXT PRIMARY KEY,
          recipient_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          title TEXT NOT NULL,
          message TEXT NOT NULL,
          category TEXT NOT NULL DEFAULT 'info',
          related_entity_type TEXT,
          related_entity_id TEXT,
          is_read INTEGER NOT NULL DEFAULT 0,
          created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS email_deliveries (
          id TEXT PRIMARY KEY,
          recipient_email TEXT NOT NULL,
          subject TEXT NOT NULL,
          template_name TEXT NOT NULL,
          idempotency_key TEXT UNIQUE,
          attempts INTEGER NOT NULL DEFAULT 0,
          status TEXT NOT NULL,
          message_id TEXT,
          error_message TEXT,
          related_entity_type TEXT,
          related_entity_id TEXT,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS audit_logs (
          id TEXT PRIMARY KEY,
          actor_user_id TEXT,
          actor_label TEXT NOT NULL,
          actor_role TEXT NOT NULL,
          action TEXT NOT NULL,
          entity_type TEXT NOT NULL,
          entity_id TEXT,
          before_state_json TEXT,
          after_state_json TEXT,
          ip_address TEXT,
          user_agent TEXT,
          metadata_json TEXT,
          created_at TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_sessions_user ON user_sessions(user_id);
        CREATE INDEX IF NOT EXISTS idx_candidates_recruiter ON candidates(assigned_recruiter_id);
        CREATE INDEX IF NOT EXISTS idx_candidate_docs_cand ON candidate_documents(candidate_id, is_current);
        CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(recipient_user_id, is_read);
        CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at DESC);
      `);

      const now = new Date().toISOString();

      db.prepare(`
        INSERT OR IGNORE INTO security_policies (
          id, require_2fa_for_employees, candidate_link_expiry_hours, max_upload_size_mb,
          lockout_threshold, lockout_duration_minutes, session_timeout_minutes, updated_by, updated_at
        ) VALUES (1, 0, 72, 5, 5, 15, 480, 'system', ?)
      `).run(now);

      const insertRolePerm = db.prepare(`
        INSERT OR IGNORE INTO role_permissions (role, permissions_json, updated_by, updated_at)
        VALUES (?, ?, 'system', ?)
      `);
      for (const role of ALL_ROLES) {
        insertRolePerm.run(role, JSON.stringify(DEFAULT_ROLE_PERMISSIONS[role]), now);
      }

      const defaultDocs = [
        {
          id: 'req_resume',
          doc_type: 'resume',
          label: 'Resume / CV',
          description: 'Latest updated curriculum vitae in PDF format.',
          is_mandatory: 1,
          sort_order: 1,
        },
        {
          id: 'req_photo',
          doc_type: 'photograph',
          label: 'Passport Photograph',
          description: 'Recent clear colour photograph (JPG or PNG).',
          is_mandatory: 1,
          sort_order: 2,
        },
        {
          id: 'req_aadhaar',
          doc_type: 'aadhaar_card',
          label: 'Aadhaar Card',
          description: 'Masked or full Aadhaar card copy for identity & EPFO KYC.',
          is_mandatory: 1,
          sort_order: 3,
        },
        {
          id: 'req_pan',
          doc_type: 'pan_card',
          label: 'PAN Card',
          description: 'Permanent Account Number card for TDS & payroll compliance.',
          is_mandatory: 1,
          sort_order: 4,
        },
        {
          id: 'req_education',
          doc_type: 'educational_certificates',
          label: 'Educational Certificates',
          description: 'Highest degree / consolidated mark sheets.',
          is_mandatory: 1,
          sort_order: 5,
        },
        {
          id: 'req_prev_emp',
          doc_type: 'previous_employment',
          label: 'Previous Employment Documents',
          description: 'Last 3 months payslips or appointment letter (if experienced).',
          is_mandatory: 0,
          sort_order: 6,
        },
        {
          id: 'req_exp_letter',
          doc_type: 'experience_letter',
          label: 'Experience Letter',
          description: 'Service / experience certificate from previous employer.',
          is_mandatory: 0,
          sort_order: 7,
        },
        {
          id: 'req_relieving',
          doc_type: 'relieving_letter',
          label: 'Relieving Letter',
          description: 'Official relieving letter or resignation acceptance.',
          is_mandatory: 0,
          sort_order: 8,
        },
        {
          id: 'req_bank',
          doc_type: 'bank_proof',
          label: 'Bank Proof',
          description: 'Cancelled cheque or passbook front page showing IFSC.',
          is_mandatory: 1,
          sort_order: 9,
        },
        {
          id: 'req_other',
          doc_type: 'other_documents',
          label: 'Other Documents Requested by HR',
          description: 'Any supplementary declaration or verification form requested by HR.',
          is_mandatory: 0,
          sort_order: 10,
        },
      ];

      const insertDocReq = db.prepare(`
        INSERT OR IGNORE INTO document_requirements (
          id, doc_type, label, description, is_mandatory, is_enabled,
          allowed_extensions, max_size_mb, sort_order, updated_by, updated_at
        ) VALUES (?, ?, ?, ?, ?, 1, 'pdf,jpg,jpeg,png', 5, ?, 'system', ?)
      `);
      for (const doc of defaultDocs) {
        insertDocReq.run(
          doc.id,
          doc.doc_type,
          doc.label,
          doc.description,
          doc.is_mandatory,
          doc.sort_order,
          now,
        );
      }

      db.prepare('INSERT INTO schema_migrations (id, applied_at) VALUES (?, ?)').run(
        '001_initial_9hr_security_and_candidates',
        now,
      );
    });

    migrate();
  }
}

export async function createDatabaseBackup(db: Database.Database, backupDir: string): Promise<string> {
  if (!fs.existsSync(backupDir)) {
    fs.mkdirSync(backupDir, { recursive: true });
  }
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const destPath = path.resolve(backupDir, `9hr_backup_${timestamp}.db`);
  await db.backup(destPath);
  return destPath;
}
