import {
  DatabaseBackup,
  KeyRound,
  Laptop,
  Lock,
  Mail,
  QrCode,
  ShieldCheck,
  UserPlus,
  X,
} from 'lucide-react';
import React, { useCallback, useEffect, useState } from 'react';
import { apiFetch, ApiError } from '../lib/api';
import type {
  AuditLogRecord,
  AuthUser,
  DocumentRequirement,
  SecurityPolicy,
  SessionRecord,
  UserRole,
} from '../types';
import { StatusText } from './StatusText';

interface StepUpModalProps {
  open: boolean;
  totpEnabled: boolean;
  onClose: () => void;
  onVerified: () => void;
}

export function StepUpModal({ open, totpEnabled, onClose, onVerified }: StepUpModalProps) {
  const [password, setPassword] = useState('');
  const [totpCode, setTotpCode] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  if (!open) return null;

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      await apiFetch('/api/auth/step-up', {
        method: 'POST',
        body: JSON.stringify({ password, totpCode: totpEnabled ? totpCode : undefined }),
      });
      setPassword('');
      setTotpCode('');
      onVerified();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Re-authentication failed.');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="fixed inset-0 z-50 bg-slate-900/60 flex items-center justify-center p-4">
      <form
        onSubmit={handleSubmit}
        className="bg-white border border-slate-200 rounded-2xl max-w-md w-full p-6 space-y-4 spatial-card"
      >
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2 font-display font-bold text-slate-900">
            <Lock className="w-4 h-4 text-blue-700" />
            <span>Re-Authentication Required</span>
          </div>
          <button type="button" onClick={onClose}>
            <X className="w-4 h-4 text-slate-400" />
          </button>
        </div>
        <p className="text-xs text-slate-600">
          For your protection, sensitive changes to bank details, compensation, roles, recovery codes, or security policies require fresh verification.
        </p>

        {error && (
          <div className="p-3 rounded-lg bg-red-50 border border-red-200 text-xs text-red-800">
            {error}
          </div>
        )}

        <div>
          <label className="block text-xs font-medium text-slate-700 mb-1">Current Password</label>
          <input
            type="password"
            required
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="w-full px-3 py-2 text-sm border border-slate-300 rounded-lg"
          />
        </div>

        {totpEnabled && (
          <div>
            <label className="block text-xs font-medium text-slate-700 mb-1">
              6-Digit Authenticator Code
            </label>
            <input
              type="text"
              inputMode="numeric"
              required
              maxLength={6}
              value={totpCode}
              onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
              placeholder="000000"
              className="w-full px-3 py-2 text-sm border border-slate-300 rounded-lg font-mono-tabular tracking-[0.25em] text-center"
            />
          </div>
        )}

        <div className="flex justify-end gap-2 pt-1">
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-2 text-xs font-medium text-slate-700 bg-slate-100 rounded-lg"
          >
            Cancel
          </button>
          <button
            type="submit"
            disabled={loading}
            className="px-4 py-2 text-xs font-semibold text-white bg-blue-700 hover:bg-blue-800 rounded-lg disabled:opacity-60"
          >
            {loading ? 'Verifying...' : 'Confirm Identity'}
          </button>
        </div>
      </form>
    </div>
  );
}

export function SecuritySessionsPanel({
  user,
  onUserRefresh,
  onRequestStepUp,
}: {
  user: AuthUser;
  onUserRefresh: () => Promise<void>;
  onRequestStepUp: (cb: () => void) => void;
}) {
  const [sessions, setSessions] = useState<SessionRecord[]>([]);
  const [regenCodes, setRegenCodes] = useState<string[] | null>(null);
  const [qrUrl, setQrUrl] = useState('');
  const [manualKey, setManualKey] = useState('');
  const [totpSetupCode, setTotpSetupCode] = useState('');
  const [msg, setMsg] = useState('');
  const [error, setError] = useState('');

  const loadSessions = useCallback(async () => {
    try {
      const res = await apiFetch<{ sessions: SessionRecord[] }>('/api/auth/sessions');
      setSessions(res.sessions);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Unable to load active sessions.');
    }
  }, []);

  useEffect(() => {
    loadSessions();
  }, [loadSessions]);

  async function revokeSession(id: string) {
    setError('');
    try {
      await apiFetch(`/api/auth/sessions/${id}`, { method: 'DELETE' });
      await loadSessions();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to revoke session.');
    }
  }

  async function revokeOthers() {
    setError('');
    try {
      const res = await apiFetch<{ revokedCount: number }>('/api/auth/sessions/revoke-others', {
        method: 'POST',
      });
      setMsg(`Revoked ${res.revokedCount} other active session(s).`);
      await loadSessions();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to revoke other sessions.');
    }
  }

  async function regenerateRecoveryCodes() {
    setError('');
    setMsg('');
    try {
      const res = await apiFetch<{ recoveryCodes: string[] }>(
        '/api/auth/2fa/regenerate-recovery-codes',
        { method: 'POST' },
      );
      setRegenCodes(res.recoveryCodes);
      setMsg('New backup recovery codes generated. Previous codes are invalidated.');
      await onUserRefresh();
    } catch (err) {
      if (err instanceof ApiError && err.code === 'STEP_UP_REQUIRED') {
        onRequestStepUp(() => {
          void regenerateRecoveryCodes();
        });
        return;
      }
      setError(err instanceof ApiError ? err.message : 'Failed to regenerate recovery codes.');
    }
  }

  async function startOptional2fa() {
    setError('');
    try {
      const res = await apiFetch<{ qrDataUrl: string; manualKey: string }>('/api/auth/2fa/setup', {
        method: 'POST',
      });
      setQrUrl(res.qrDataUrl);
      setManualKey(res.manualKey);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Unable to start 2FA enrollment.');
    }
  }

  async function verifyOptional2fa(e: React.FormEvent) {
    e.preventDefault();
    setError('');
    try {
      const res = await apiFetch<{ recoveryCodes: string[] }>('/api/auth/2fa/verify-setup', {
        method: 'POST',
        body: JSON.stringify({ code: totpSetupCode }),
      });
      setQrUrl('');
      setRegenCodes(res.recoveryCodes);
      setMsg('Two-factor authentication is now enabled on your account.');
      await onUserRefresh();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Invalid authenticator code.');
    }
  }

  return (
    <div className="space-y-6">
      {error && <div className="p-3 rounded-xl bg-red-50 border border-red-200 text-red-800 text-sm">{error}</div>}
      {msg && <div className="p-3 rounded-xl bg-emerald-50 border border-emerald-200 text-emerald-900 text-sm">{msg}</div>}

      <div className="bg-white border border-slate-200 rounded-2xl p-6 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center gap-2 font-display font-bold text-slate-900">
            <KeyRound className="w-4 h-4 text-blue-700" />
            <span>Two-Factor Authentication &amp; Recovery Codes</span>
          </div>
          {user.totpEnabled ? (
            <button
              type="button"
              onClick={regenerateRecoveryCodes}
              className="px-3.5 py-2 bg-slate-900 text-white text-xs font-semibold rounded-lg whitespace-nowrap"
            >
              Regenerate Recovery Codes
            </button>
          ) : (
            <button
              type="button"
              onClick={startOptional2fa}
              className="inline-flex items-center gap-1.5 px-3.5 py-2 bg-blue-700 text-white text-xs font-semibold rounded-lg"
            >
              <QrCode className="w-3.5 h-3.5" />
              <span>Enable Authenticator 2FA</span>
            </button>
          )}
        </div>

        <div className="text-xs text-slate-600">
          Status: <strong>{user.totpEnabled ? 'Enabled (TOTP)' : 'Not Enabled'}</strong>
          {user.totpEnabled && (
            <>
              {' '}· Unused backup codes remaining:{' '}
              <span className="font-mono-tabular font-semibold">{user.remainingRecoveryCodes ?? 0}</span>
            </>
          )}
        </div>

        {qrUrl && (
          <form onSubmit={verifyOptional2fa} className="p-4 bg-slate-50 border border-slate-200 rounded-xl space-y-3 max-w-sm">
            <img src={qrUrl} alt="2FA QR Code" className="w-40 h-40 rounded bg-white p-1" />
            <div className="text-xs font-mono-tabular text-slate-700 break-all">Key: {manualKey}</div>
            <div className="flex gap-2">
              <input
                type="text"
                required
                maxLength={6}
                value={totpSetupCode}
                onChange={(e) => setTotpSetupCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                placeholder="6-digit code"
                className="flex-1 px-3 py-2 text-sm border border-slate-300 rounded-lg font-mono-tabular"
              />
              <button
                type="submit"
                className="px-3.5 py-2 bg-blue-700 text-white text-xs font-semibold rounded-lg"
              >
                Verify
              </button>
            </div>
          </form>
        )}

        {regenCodes && (
          <div className="p-4 bg-slate-50 border border-slate-200 rounded-xl space-y-2">
            <div className="text-xs font-semibold text-slate-900">
              New Single-Use Backup Recovery Codes (Store Securely)
            </div>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 font-mono-tabular text-xs">
              {regenCodes.map((c) => (
                <div key={c} className="px-2.5 py-1.5 bg-white border border-slate-200 rounded text-center font-semibold">
                  {c}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Active Sessions */}
      <div className="bg-white border border-slate-200 rounded-2xl p-6 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center gap-2 font-display font-bold text-slate-900">
            <Laptop className="w-4 h-4 text-blue-700" />
            <span>Active Device Sessions ({sessions.length})</span>
          </div>
          {sessions.length > 1 && (
            <button
              type="button"
              onClick={revokeOthers}
              className="px-3 py-1.5 bg-red-50 hover:bg-red-100 text-red-700 text-xs font-semibold rounded-lg"
            >
              Sign Out All Other Devices
            </button>
          )}
        </div>

        <div className="divide-y divide-slate-100 text-xs">
          {sessions.map((s) => (
            <div key={s.id} className="py-3 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <div>
                <div className="font-semibold text-slate-900">
                  {s.device_label || 'Web Session'} {s.isCurrent ? '· Current Session' : ''}
                </div>
                <div className="text-slate-500 font-mono-tabular mt-0.5">
                  IP: {s.ip_address || 'unknown'} · Last active {new Date(s.last_active_at).toLocaleString()}
                </div>
              </div>
              {!s.isCurrent && (
                <button
                  type="button"
                  onClick={() => revokeSession(s.id)}
                  className="px-3 py-1.5 text-red-700 bg-red-50 hover:bg-red-100 rounded-md font-medium self-start sm:self-center"
                >
                  Revoke
                </button>
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

export function ChecklistConfigPanel() {
  const [reqs, setReqs] = useState<DocumentRequirement[]>([]);
  const [msg, setMsg] = useState('');
  const [error, setError] = useState('');

  useEffect(() => {
    apiFetch<{ requirements: DocumentRequirement[] }>('/api/admin/document-requirements')
      .then((r) => setReqs(r.requirements))
      .catch((err) => setError(err instanceof ApiError ? err.message : 'Unable to load checklist config.'));
  }, []);

  async function saveConfig() {
    setError('');
    setMsg('');
    try {
      const res = await apiFetch<{ requirements: DocumentRequirement[] }>(
        '/api/admin/document-requirements',
        {
          method: 'PUT',
          body: JSON.stringify({ requirements: reqs }),
        },
      );
      setReqs(res.requirements);
      setMsg('Candidate document checklist requirements saved.');
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Save failed.');
    }
  }

  return (
    <div className="bg-white border border-slate-200 rounded-2xl p-6 space-y-4">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h2 className="font-display font-bold text-slate-900 text-lg">
            Candidate Document Checklist Policy
          </h2>
          <p className="text-xs text-slate-500">
            Configure mandatory and optional document types and per-file size limits for candidate uploads.
          </p>
        </div>
        <button
          type="button"
          onClick={saveConfig}
          className="px-4 py-2 bg-blue-700 hover:bg-blue-800 text-white text-xs font-semibold rounded-lg whitespace-nowrap"
        >
          Save Checklist Policy
        </button>
      </div>

      {error && <div className="p-3 rounded-lg bg-red-50 text-red-800 text-xs">{error}</div>}
      {msg && <div className="p-3 rounded-lg bg-emerald-50 text-emerald-900 text-xs">{msg}</div>}

      <div className="divide-y divide-slate-100">
        {reqs.map((item, idx) => (
          <div key={item.id} className="py-3 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div>
              <div className="text-sm font-semibold text-slate-900">{item.label}</div>
              <div className="text-xs text-slate-500">{item.description}</div>
            </div>
            <div className="flex items-center gap-4 text-xs shrink-0">
              <label className="flex items-center gap-1.5 cursor-pointer">
                <input
                  type="checkbox"
                  checked={Boolean(item.is_enabled)}
                  onChange={(e) => {
                    const next = [...reqs];
                    next[idx] = { ...item, is_enabled: e.target.checked ? 1 : 0 };
                    setReqs(next);
                  }}
                />
                <span>Enabled</span>
              </label>
              <label className="flex items-center gap-1.5 cursor-pointer">
                <input
                  type="checkbox"
                  checked={Boolean(item.is_mandatory)}
                  onChange={(e) => {
                    const next = [...reqs];
                    next[idx] = { ...item, is_mandatory: e.target.checked ? 1 : 0 };
                    setReqs(next);
                  }}
                />
                <span>Mandatory</span>
              </label>
              <div className="flex items-center gap-1">
                <input
                  type="number"
                  min={1}
                  max={25}
                  value={item.max_size_mb}
                  onChange={(e) => {
                    const next = [...reqs];
                    next[idx] = { ...item, max_size_mb: Number(e.target.value || 5) };
                    setReqs(next);
                  }}
                  className="w-14 px-2 py-1 border border-slate-300 rounded font-mono-tabular text-right"
                />
                <span className="text-slate-500">MB</span>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

export function AdminConsolePanel({
  onRequestStepUp,
}: {
  onRequestStepUp: (cb: () => void) => void;
}) {
  const [users, setUsers] = useState<
    Array<{
      id: string;
      username: string;
      email: string;
      full_name: string;
      role: UserRole;
      department: string;
      totp_enabled: number;
      is_active: number;
    }>
  >([]);
  const [policy, setPolicy] = useState<SecurityPolicy | null>(null);
  const [logs, setLogs] = useState<AuditLogRecord[]>([]);
  const [deliveries, setDeliveries] = useState<
    Array<{
      id: string;
      recipient_email: string;
      subject: string;
      status: string;
      error_message: string | null;
      attempts: number;
      created_at: string;
    }>
  >([]);
  const [actionFilter, setActionFilter] = useState('');

  // Create user form
  const [newFullName, setNewFullName] = useState('');
  const [newEmail, setNewEmail] = useState('');
  const [newUsername, setNewUsername] = useState('');
  const [newRole, setNewRole] = useState<UserRole>('HR');
  const [newDepartment, setNewDepartment] = useState('Human Resources');
  const [newPassword, setNewPassword] = useState('');

  const [msg, setMsg] = useState('');
  const [error, setError] = useState('');

  const loadAll = useCallback(async () => {
    try {
      const [uRes, pRes, aRes, eRes] = await Promise.all([
        apiFetch<{ users: typeof users }>('/api/admin/users'),
        apiFetch<{ policy: SecurityPolicy }>('/api/admin/security-policy'),
        apiFetch<{ logs: AuditLogRecord[] }>(
          `/api/admin/audit-logs?action=${encodeURIComponent(actionFilter)}`,
        ),
        apiFetch<{ deliveries: typeof deliveries }>('/api/admin/email-deliveries'),
      ]);
      setUsers(uRes.users);
      setPolicy(pRes.policy);
      setLogs(aRes.logs);
      setDeliveries(eRes.deliveries);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Unable to load admin console.');
    }
  }, [actionFilter]);

  useEffect(() => {
    loadAll();
  }, [loadAll]);

  async function handleCreateUser(e: React.FormEvent) {
    e.preventDefault();
    setError('');
    setMsg('');
    try {
      await apiFetch('/api/admin/users', {
        method: 'POST',
        body: JSON.stringify({
          fullName: newFullName,
          email: newEmail,
          username: newUsername,
          role: newRole,
          department: newDepartment,
          password: newPassword,
        }),
      });
      setNewFullName('');
      setNewEmail('');
      setNewUsername('');
      setNewPassword('');
      setMsg(`User account created for ${newEmail} (${newRole}).`);
      await loadAll();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Unable to create user.');
    }
  }

  async function changeUserRole(userId: string, role: UserRole) {
    setError('');
    setMsg('');
    try {
      await apiFetch(`/api/admin/users/${userId}/role`, {
        method: 'PATCH',
        body: JSON.stringify({ role }),
      });
      setMsg('User role updated and recorded in audit trail.');
      await loadAll();
    } catch (err) {
      if (err instanceof ApiError && err.code === 'STEP_UP_REQUIRED') {
        onRequestStepUp(() => {
          void changeUserRole(userId, role);
        });
        return;
      }
      setError(err instanceof ApiError ? err.message : 'Unable to update role.');
    }
  }

  async function saveSecurityPolicy(nextPolicy: SecurityPolicy) {
    setError('');
    setMsg('');
    try {
      await apiFetch('/api/admin/security-policy', {
        method: 'PUT',
        body: JSON.stringify({
          require2faForEmployees: Boolean(nextPolicy.require_2fa_for_employees),
          candidateLinkExpiryHours: nextPolicy.candidate_link_expiry_hours,
          maxUploadSizeMb: nextPolicy.max_upload_size_mb,
          lockoutThreshold: nextPolicy.lockout_threshold,
          lockoutDurationMinutes: nextPolicy.lockout_duration_minutes,
          sessionTimeoutMinutes: nextPolicy.session_timeout_minutes,
        }),
      });
      setMsg('Organization security policy updated.');
      await loadAll();
    } catch (err) {
      if (err instanceof ApiError && err.code === 'STEP_UP_REQUIRED') {
        onRequestStepUp(() => {
          void saveSecurityPolicy(nextPolicy);
        });
        return;
      }
      setError(err instanceof ApiError ? err.message : 'Failed to update security policy.');
    }
  }

  async function triggerBackup() {
    setError('');
    setMsg('');
    try {
      const res = await apiFetch<{ filename: string }>('/api/admin/backup', {
        method: 'POST',
      });
      setMsg(`Private database backup created: ${res.filename}`);
      await loadAll();
    } catch (err) {
      if (err instanceof ApiError && err.code === 'STEP_UP_REQUIRED') {
        onRequestStepUp(() => {
          void triggerBackup();
        });
        return;
      }
      setError(err instanceof ApiError ? err.message : 'Backup failed.');
    }
  }

  return (
    <div className="space-y-6">
      {error && <div className="p-3 rounded-xl bg-red-50 border border-red-200 text-red-800 text-sm">{error}</div>}
      {msg && <div className="p-3 rounded-xl bg-emerald-50 border border-emerald-200 text-emerald-900 text-sm">{msg}</div>}

      {/* Create Internal User + User Role Table */}
      <div className="grid grid-cols-1 xl:grid-cols-12 gap-6">
        <form
          onSubmit={handleCreateUser}
          className="xl:col-span-4 bg-white border border-slate-200 rounded-2xl p-6 space-y-3"
        >
          <div className="flex items-center gap-2 font-display font-bold text-slate-900">
            <UserPlus className="w-4 h-4 text-blue-700" />
            <span>Provision Internal User</span>
          </div>
          <input
            required
            placeholder="Full Name"
            value={newFullName}
            onChange={(e) => setNewFullName(e.target.value)}
            className="w-full px-3 py-2 text-sm border border-slate-300 rounded-lg"
          />
          <input
            type="email"
            required
            placeholder="Work Email"
            value={newEmail}
            onChange={(e) => setNewEmail(e.target.value)}
            className="w-full px-3 py-2 text-sm border border-slate-300 rounded-lg"
          />
          <input
            required
            placeholder="Username"
            value={newUsername}
            onChange={(e) => setNewUsername(e.target.value)}
            className="w-full px-3 py-2 text-sm border border-slate-300 rounded-lg"
          />
          <div className="grid grid-cols-2 gap-2">
            <select
              value={newRole}
              onChange={(e) => setNewRole(e.target.value as UserRole)}
              className="px-3 py-2 text-sm border border-slate-300 rounded-lg bg-white"
            >
              <option value="Employee">Employee</option>
              <option value="Manager">Manager</option>
              <option value="HR">HR</option>
              <option value="Accounts">Accounts</option>
              <option value="Admin">Admin</option>
            </select>
            <input
              required
              placeholder="Department"
              value={newDepartment}
              onChange={(e) => setNewDepartment(e.target.value)}
              className="px-3 py-2 text-sm border border-slate-300 rounded-lg"
            />
          </div>
          <input
            type="password"
            required
            minLength={10}
            placeholder="Temporary Password (min 10 chars)"
            value={newPassword}
            onChange={(e) => setNewPassword(e.target.value)}
            className="w-full px-3 py-2 text-sm border border-slate-300 rounded-lg"
          />
          <button
            type="submit"
            className="w-full py-2 px-4 bg-blue-700 hover:bg-blue-800 text-white text-xs font-semibold rounded-lg"
          >
            Create User Account
          </button>
        </form>

        <div className="xl:col-span-8 bg-white border border-slate-200 rounded-2xl p-6 overflow-x-auto">
          <h3 className="font-display font-bold text-slate-900 mb-3">
            Users &amp; Role Assignment ({users.length})
          </h3>
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-200 text-slate-500">
                <th className="py-2 font-medium">User</th>
                <th className="py-2 font-medium">Department</th>
                <th className="py-2 font-medium">2FA</th>
                <th className="py-2 font-medium">Role (Step-Up)</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {users.map((u) => (
                <tr key={u.id}>
                  <td className="py-2.5">
                    <div className="font-medium text-slate-900">{u.full_name}</div>
                    <div className="text-slate-500">{u.email}</div>
                  </td>
                  <td className="py-2.5 text-slate-700">{u.department}</td>
                  <td className="py-2.5">
                    <StatusText status={u.totp_enabled ? 'Verified' : 'Pending'} />
                  </td>
                  <td className="py-2.5">
                    <select
                      value={u.role}
                      onChange={(e) => changeUserRole(u.id, e.target.value as UserRole)}
                      className="px-2.5 py-1 border border-slate-300 rounded bg-white text-xs font-medium"
                    >
                      <option value="Employee">Employee</option>
                      <option value="Manager">Manager</option>
                      <option value="HR">HR</option>
                      <option value="Accounts">Accounts</option>
                      <option value="Admin">Admin</option>
                    </select>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Security Policy & Database Backup */}
      {policy && (
        <div className="bg-white border border-slate-200 rounded-2xl p-6 space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div className="flex items-center gap-2 font-display font-bold text-slate-900">
              <ShieldCheck className="w-4 h-4 text-blue-700" />
              <span>Security Policy &amp; Backup Governance</span>
            </div>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={triggerBackup}
                className="inline-flex items-center gap-1.5 px-3 py-2 bg-slate-100 hover:bg-slate-200 text-slate-800 text-xs font-semibold rounded-lg"
              >
                <DatabaseBackup className="w-3.5 h-3.5" />
                <span>Create DB Backup</span>
              </button>
              <button
                type="button"
                onClick={() => saveSecurityPolicy(policy)}
                className="px-4 py-2 bg-blue-700 hover:bg-blue-800 text-white text-xs font-semibold rounded-lg"
              >
                Save Policy
              </button>
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 text-xs">
            <label className="flex items-center gap-2 p-3 border border-slate-200 rounded-xl cursor-pointer">
              <input
                type="checkbox"
                checked={Boolean(policy.require_2fa_for_employees)}
                onChange={(e) =>
                  setPolicy({ ...policy, require_2fa_for_employees: e.target.checked ? 1 : 0 })
                }
              />
              <span className="font-medium text-slate-800">Require 2FA for Employees</span>
            </label>
            <div className="p-3 border border-slate-200 rounded-xl">
              <div className="text-slate-500 mb-1">Candidate Link Expiry (Hours)</div>
              <input
                type="number"
                value={policy.candidate_link_expiry_hours}
                onChange={(e) =>
                  setPolicy({ ...policy, candidate_link_expiry_hours: Number(e.target.value || 72) })
                }
                className="w-full px-2 py-1 border border-slate-300 rounded font-mono-tabular"
              />
            </div>
            <div className="p-3 border border-slate-200 rounded-xl">
              <div className="text-slate-500 mb-1">Max Upload Size (MB)</div>
              <input
                type="number"
                value={policy.max_upload_size_mb}
                onChange={(e) =>
                  setPolicy({ ...policy, max_upload_size_mb: Number(e.target.value || 5) })
                }
                className="w-full px-2 py-1 border border-slate-300 rounded font-mono-tabular"
              />
            </div>
            <div className="p-3 border border-slate-200 rounded-xl">
              <div className="text-slate-500 mb-1">Lockout Threshold (Attempts)</div>
              <input
                type="number"
                value={policy.lockout_threshold}
                onChange={(e) =>
                  setPolicy({ ...policy, lockout_threshold: Number(e.target.value || 5) })
                }
                className="w-full px-2 py-1 border border-slate-300 rounded font-mono-tabular"
              />
            </div>
          </div>
        </div>
      )}

      {/* Email Delivery Log */}
      <div className="bg-white border border-slate-200 rounded-2xl p-6 space-y-3">
        <div className="flex items-center gap-2 font-display font-bold text-slate-900">
          <Mail className="w-4 h-4 text-blue-700" />
          <span>SMTP Email Delivery Log</span>
        </div>
        {deliveries.length === 0 ? (
          <div className="text-xs text-slate-500">No email dispatches recorded yet.</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-slate-200 text-slate-500">
                  <th className="py-2 font-medium">Timestamp</th>
                  <th className="py-2 font-medium">Recipient</th>
                  <th className="py-2 font-medium">Subject</th>
                  <th className="py-2 font-medium">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {deliveries.slice(0, 15).map((d) => (
                  <tr key={d.id}>
                    <td className="py-2 font-mono-tabular text-slate-500">
                      {new Date(d.created_at).toLocaleString()}
                    </td>
                    <td className="py-2 text-slate-800">{d.recipient_email}</td>
                    <td className="py-2 text-slate-700">{d.subject}</td>
                    <td className="py-2">
                      <StatusText status={d.status} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Read-Only Immutable Audit Trail */}
      <div className="bg-white border border-slate-200 rounded-2xl p-6 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h3 className="font-display font-bold text-slate-900">
              Immutable Security &amp; Compliance Audit Trail (Read-Only)
            </h3>
            <p className="text-xs text-slate-500">
              Records authentication, 2FA, RBAC, invitation lifecycle, document scanning, and onboarding transitions.
            </p>
          </div>
          <input
            type="search"
            value={actionFilter}
            onChange={(e) => setActionFilter(e.target.value)}
            placeholder="Filter by action (e.g. 2FA, LOGIN, DOCUMENT)"
            className="px-3 py-1.5 text-xs border border-slate-300 rounded-lg sm:w-72"
          />
        </div>

        <div className="overflow-x-auto max-h-[420px]">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-200 text-slate-500">
                <th className="py-2 font-medium">Timestamp</th>
                <th className="py-2 font-medium">Actor</th>
                <th className="py-2 font-medium">Action</th>
                <th className="py-2 font-medium">Reference</th>
                <th className="py-2 font-medium">IP Address</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {logs.map((l) => (
                <tr key={l.id} className="hover:bg-slate-50">
                  <td className="py-2 font-mono-tabular text-slate-500 whitespace-nowrap">
                    {new Date(l.created_at).toLocaleString()}
                  </td>
                  <td className="py-2">
                    <span className="font-medium text-slate-900">{l.actor_label}</span>
                    <span className="text-slate-400 mx-1">·</span>
                    <span className="text-slate-600">{l.actor_role}</span>
                  </td>
                  <td className="py-2 font-mono-tabular font-semibold text-slate-800">{l.action}</td>
                  <td className="py-2 font-mono-tabular text-slate-600">
                    {l.entity_type}
                    {l.entity_id ? ` (${l.entity_id.slice(0, 12)})` : ''}
                  </td>
                  <td className="py-2 font-mono-tabular text-slate-500">{l.ip_address || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
