import { Building2, CalendarCheck, IndianRupee, Landmark, ShieldCheck } from 'lucide-react';
import React, { useCallback, useEffect, useState } from 'react';
import { apiFetch, ApiError } from '../lib/api';
import type {
  AuthUser,
  EmployeeRecord,
  LeaveRecord,
  PayrollRunRecord,
  PayslipRecord,
} from '../types';
import { StatusText } from './StatusText';

interface PanelCommonProps {
  user: AuthUser;
  onRequestStepUp: (afterStepUp: () => void) => void;
}

export function OverviewAndEssPanel({ user, onRequestStepUp }: PanelCommonProps) {
  const [selfEmployee, setSelfEmployee] = useState<EmployeeRecord | null>(null);
  const [leaves, setLeaves] = useState<LeaveRecord[]>([]);
  const [payslips, setPayslips] = useState<PayslipRecord[]>([]);

  // Leave submission form
  const [leaveType, setLeaveType] = useState('Casual Leave');
  const [startDate, setStartDate] = useState('');
  const [endDate, setEndDate] = useState('');
  const [days, setDays] = useState('1');
  const [reason, setReason] = useState('');

  // Bank update form (requires step-up re-authentication)
  const [bankName, setBankName] = useState('');
  const [accountNumber, setAccountNumber] = useState('');
  const [ifscCode, setIfscCode] = useState('');
  const [msg, setMsg] = useState('');
  const [error, setError] = useState('');

  const loadEss = useCallback(async () => {
    try {
      const [empRes, lvRes, slipRes] = await Promise.all([
        apiFetch<{ employees: EmployeeRecord[] }>('/api/hr/employees'),
        apiFetch<{ leaves: LeaveRecord[] }>('/api/hr/leaves'),
        apiFetch<{ payslips: PayslipRecord[] }>('/api/hr/payroll/my-payslips'),
      ]);
      const mine = empRes.employees.find((e) => e.user_id === user.id) || empRes.employees[0] || null;
      setSelfEmployee(mine);
      if (mine?.bank_name) setBankName(mine.bank_name);
      if (mine?.ifsc_code) setIfscCode(mine.ifsc_code);
      setLeaves(lvRes.leaves);
      setPayslips(slipRes.payslips);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Unable to load ESS data.');
    }
  }, [user.id]);

  useEffect(() => {
    loadEss();
  }, [loadEss]);

  async function handleSubmitLeave(e: React.FormEvent) {
    e.preventDefault();
    setError('');
    setMsg('');
    try {
      await apiFetch('/api/hr/leaves', {
        method: 'POST',
        body: JSON.stringify({
          leaveType,
          startDate,
          endDate,
          days: Number(days || 1),
          reason,
        }),
      });
      setReason('');
      setMsg('Leave request submitted for approval.');
      await loadEss();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Unable to submit leave request.');
    }
  }

  async function submitBankUpdate() {
    if (!selfEmployee) return;
    setError('');
    setMsg('');
    try {
      await apiFetch(`/api/hr/employees/${selfEmployee.id}/bank-details`, {
        method: 'PATCH',
        body: JSON.stringify({ bankName, accountNumber, ifscCode }),
      });
      setAccountNumber('');
      setMsg('Bank details updated securely and recorded in audit trail.');
      await loadEss();
    } catch (err) {
      if (err instanceof ApiError && err.code === 'STEP_UP_REQUIRED') {
        onRequestStepUp(() => {
          void submitBankUpdate();
        });
        return;
      }
      setError(err instanceof ApiError ? err.message : 'Bank details update failed.');
    }
  }

  return (
    <div className="space-y-6">
      {/* Identity & Role Summary Strip */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-white border border-slate-200 rounded-xl p-4">
          <div className="text-xs text-slate-500">Signed-In Role</div>
          <div className="font-display font-bold text-lg text-slate-900 mt-1">{user.role}</div>
          <div className="text-xs text-slate-500 mt-0.5">{user.department}</div>
        </div>
        <div className="bg-white border border-slate-200 rounded-xl p-4">
          <div className="text-xs text-slate-500">Two-Factor Security</div>
          <div className="font-display font-bold text-lg text-slate-900 mt-1">
            {user.totpEnabled ? 'Active (TOTP)' : 'Not Configured'}
          </div>
          <div className="text-xs text-slate-500 mt-0.5">
            {user.mandatory2fa ? 'Mandatory Policy' : 'Optional Policy'}
          </div>
        </div>
        <div className="bg-white border border-slate-200 rounded-xl p-4">
          <div className="text-xs text-slate-500">Employee Code</div>
          <div className="font-mono-tabular font-bold text-lg text-slate-900 mt-1">
            {selfEmployee?.employee_code || '—'}
          </div>
          <div className="text-xs text-slate-500 mt-0.5">{selfEmployee?.designation || user.designation}</div>
        </div>
        <div className="bg-white border border-slate-200 rounded-xl p-4">
          <div className="text-xs text-slate-500">Disbursed Payslips</div>
          <div className="font-mono-tabular font-bold text-lg text-slate-900 mt-1">
            {payslips.length}
          </div>
          <div className="text-xs text-slate-500 mt-0.5">Self-service statements</div>
        </div>
      </div>

      {error && (
        <div className="p-3.5 rounded-xl bg-red-50 border border-red-200 text-red-800 text-sm">
          {error}
        </div>
      )}
      {msg && (
        <div className="p-3.5 rounded-xl bg-emerald-50 border border-emerald-200 text-emerald-900 text-sm">
          {msg}
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Leave Application (ESS) */}
        <div className="bg-white border border-slate-200 rounded-2xl p-6 space-y-4">
          <div className="flex items-center gap-2 font-display font-bold text-slate-900">
            <CalendarCheck className="w-4 h-4 text-blue-700" />
            <span>Apply for Leave (ESS)</span>
          </div>
          <form onSubmit={handleSubmitLeave} className="space-y-3">
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-xs font-medium text-slate-700 mb-1">Leave Type</label>
                <select
                  value={leaveType}
                  onChange={(e) => setLeaveType(e.target.value)}
                  className="w-full px-3 py-2 text-sm border border-slate-300 rounded-lg bg-white"
                >
                  <option>Casual Leave</option>
                  <option>Sick Leave</option>
                  <option>Earned Leave</option>
                </select>
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-700 mb-1">Days</label>
                <input
                  type="number"
                  min={1}
                  value={days}
                  onChange={(e) => setDays(e.target.value)}
                  className="w-full px-3 py-2 text-sm border border-slate-300 rounded-lg font-mono-tabular"
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-700 mb-1">From Date</label>
                <input
                  type="date"
                  required
                  value={startDate}
                  onChange={(e) => setStartDate(e.target.value)}
                  className="w-full px-3 py-2 text-sm border border-slate-300 rounded-lg"
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-700 mb-1">To Date</label>
                <input
                  type="date"
                  required
                  value={endDate}
                  onChange={(e) => setEndDate(e.target.value)}
                  className="w-full px-3 py-2 text-sm border border-slate-300 rounded-lg"
                />
              </div>
            </div>
            <div>
              <label className="block text-xs font-medium text-slate-700 mb-1">Reason</label>
              <input
                required
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                placeholder="Brief reason for leave"
                className="w-full px-3 py-2 text-sm border border-slate-300 rounded-lg"
              />
            </div>
            <button
              type="submit"
              className="px-4 py-2 bg-blue-700 hover:bg-blue-800 text-white text-xs font-semibold rounded-lg"
            >
              Submit Leave Request
            </button>
          </form>

          {leaves.length > 0 && (
            <div className="pt-3 border-t border-slate-100 divide-y divide-slate-100">
              {leaves.slice(0, 4).map((l) => (
                <div key={l.id} className="py-2 flex items-center justify-between text-xs">
                  <div>
                    <span className="font-medium text-slate-800">{l.leave_type}</span>
                    <span className="text-slate-400 mx-1.5">·</span>
                    <span className="font-mono-tabular text-slate-500">
                      {l.start_date} to {l.end_date}
                    </span>
                  </div>
                  <StatusText status={l.status} />
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Step-Up Protected Bank Details */}
        <div className="bg-white border border-slate-200 rounded-2xl p-6 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 font-display font-bold text-slate-900">
              <Landmark className="w-4 h-4 text-blue-700" />
              <span>Salary Bank Account (Step-Up Protected)</span>
            </div>
            <span className="inline-flex items-center gap-1 text-xs text-slate-500">
              <ShieldCheck className="w-3.5 h-3.5 text-emerald-700" />
              <span>Re-auth required</span>
            </span>
          </div>

          {selfEmployee?.bank_account_masked && (
            <div className="p-3 rounded-lg bg-slate-50 border border-slate-200 text-xs text-slate-700">
              Current on file: <strong>{selfEmployee.bank_name}</strong> ·{' '}
              <span className="font-mono-tabular">{selfEmployee.bank_account_masked}</span> · IFSC{' '}
              <span className="font-mono-tabular">{selfEmployee.ifsc_code}</span>
            </div>
          )}

          <div className="space-y-3">
            <div>
              <label className="block text-xs font-medium text-slate-700 mb-1">Bank Name</label>
              <input
                value={bankName}
                onChange={(e) => setBankName(e.target.value)}
                placeholder="HDFC Bank"
                className="w-full px-3 py-2 text-sm border border-slate-300 rounded-lg"
              />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-xs font-medium text-slate-700 mb-1">Account Number</label>
                <input
                  value={accountNumber}
                  onChange={(e) => setAccountNumber(e.target.value)}
                  placeholder="Enter new account number"
                  className="w-full px-3 py-2 text-sm border border-slate-300 rounded-lg font-mono-tabular"
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-700 mb-1">IFSC Code</label>
                <input
                  value={ifscCode}
                  onChange={(e) => setIfscCode(e.target.value.toUpperCase())}
                  placeholder="HDFC0001234"
                  className="w-full px-3 py-2 text-sm border border-slate-300 rounded-lg font-mono-tabular"
                />
              </div>
            </div>
            <button
              type="button"
              disabled={!selfEmployee || !bankName || !accountNumber || !ifscCode}
              onClick={submitBankUpdate}
              className="px-4 py-2 bg-slate-900 hover:bg-slate-800 text-white text-xs font-semibold rounded-lg disabled:opacity-50"
            >
              Update Bank Details
            </button>
          </div>
        </div>
      </div>

      {/* Own Payslips */}
      <div className="bg-white border border-slate-200 rounded-2xl p-6">
        <h3 className="font-display font-bold text-slate-900 text-sm mb-3">My Payslips</h3>
        {payslips.length === 0 ? (
          <div className="text-xs text-slate-500">No payslips generated for your account yet.</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-slate-200 text-slate-500">
                  <th className="py-2 font-medium">Month</th>
                  <th className="py-2 font-medium text-right">Gross</th>
                  <th className="py-2 font-medium text-right">PF</th>
                  <th className="py-2 font-medium text-right">PT</th>
                  <th className="py-2 font-medium text-right">TDS</th>
                  <th className="py-2 font-medium text-right">Net Pay</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 font-mono-tabular">
                {payslips.map((p) => (
                  <tr key={p.id}>
                    <td className="py-2.5 font-medium text-slate-900">{p.month_year}</td>
                    <td className="py-2.5 text-right">{p.gross_pay.toLocaleString('en-IN')}</td>
                    <td className="py-2.5 text-right">{p.pf_deduction.toLocaleString('en-IN')}</td>
                    <td className="py-2.5 text-right">{p.pt_deduction.toLocaleString('en-IN')}</td>
                    <td className="py-2.5 text-right">{p.tds_deduction.toLocaleString('en-IN')}</td>
                    <td className="py-2.5 text-right font-semibold text-emerald-700">
                      {p.net_pay.toLocaleString('en-IN')}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

export function TeamApprovalsPanel() {
  const [leaves, setLeaves] = useState<LeaveRecord[]>([]);
  const [employees, setEmployees] = useState<EmployeeRecord[]>([]);
  const [error, setError] = useState('');

  const load = useCallback(async () => {
    try {
      const [lv, emp] = await Promise.all([
        apiFetch<{ leaves: LeaveRecord[] }>('/api/hr/leaves'),
        apiFetch<{ employees: EmployeeRecord[] }>('/api/hr/employees'),
      ]);
      setLeaves(lv.leaves);
      setEmployees(emp.employees);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Unable to load team data.');
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  async function reviewLeave(id: string, decision: 'Approved' | 'Rejected') {
    setError('');
    try {
      await apiFetch(`/api/hr/leaves/${id}/review`, {
        method: 'PATCH',
        body: JSON.stringify({ decision }),
      });
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Unable to review leave.');
    }
  }

  return (
    <div className="space-y-6">
      {error && (
        <div className="p-3 rounded-xl bg-red-50 border border-red-200 text-red-800 text-sm">
          {error}
        </div>
      )}

      <div className="bg-white border border-slate-200 rounded-2xl p-6">
        <h2 className="font-display font-bold text-slate-900 text-lg mb-4">
          Team Leave Approvals
        </h2>
        {leaves.length === 0 ? (
          <div className="text-sm text-slate-500">No leave requests in your team scope.</div>
        ) : (
          <div className="divide-y divide-slate-100">
            {leaves.map((l) => (
              <div key={l.id} className="py-3 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div>
                  <div className="text-sm font-semibold text-slate-900">
                    {l.employee_name} · {l.leave_type}
                  </div>
                  <div className="text-xs text-slate-500">
                    <span className="font-mono-tabular">{l.start_date} to {l.end_date}</span> ({l.days}d) — {l.reason}
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <StatusText status={l.status} />
                  {l.status === 'Pending' && (
                    <>
                      <button
                        type="button"
                        onClick={() => reviewLeave(l.id, 'Approved')}
                        className="px-3 py-1.5 bg-emerald-700 text-white text-xs font-semibold rounded-md"
                      >
                        Approve
                      </button>
                      <button
                        type="button"
                        onClick={() => reviewLeave(l.id, 'Rejected')}
                        className="px-3 py-1.5 bg-red-600 text-white text-xs font-semibold rounded-md"
                      >
                        Reject
                      </button>
                    </>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="bg-white border border-slate-200 rounded-2xl p-6">
        <h3 className="font-display font-bold text-slate-900 text-sm mb-3">
          Assigned Team Roster ({employees.length})
        </h3>
        <div className="divide-y divide-slate-100 text-sm">
          {employees.map((e) => (
            <div key={e.id} className="py-2.5 flex items-center justify-between">
              <div>
                <div className="font-medium text-slate-900">{e.full_name}</div>
                <div className="text-xs text-slate-500">{e.designation} · {e.department}</div>
              </div>
              <StatusText status={e.employment_status} />
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

export function EmployeeDirectoryPanel() {
  const [employees, setEmployees] = useState<EmployeeRecord[]>([]);
  const [error, setError] = useState('');

  useEffect(() => {
    apiFetch<{ employees: EmployeeRecord[] }>('/api/hr/employees')
      .then((r) => setEmployees(r.employees))
      .catch((err) => setError(err instanceof ApiError ? err.message : 'Unable to load directory.'));
  }, []);

  return (
    <div className="bg-white border border-slate-200 rounded-2xl p-6 space-y-4">
      <div className="flex items-center gap-2 font-display font-bold text-slate-900 text-lg">
        <Building2 className="w-5 h-5 text-blue-700" />
        <span>Employee Directory</span>
      </div>
      {error && <div className="text-sm text-red-700">{error}</div>}
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs">
          <thead>
            <tr className="border-b border-slate-200 text-slate-500">
              <th className="py-2.5 font-medium">Code</th>
              <th className="py-2.5 font-medium">Employee</th>
              <th className="py-2.5 font-medium">Department</th>
              <th className="py-2.5 font-medium">Designation</th>
              <th className="py-2.5 font-medium">Joined</th>
              <th className="py-2.5 font-medium">Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {employees.map((e) => (
              <tr key={e.id} className="hover:bg-slate-50">
                <td className="py-2.5 font-mono-tabular text-slate-700">{e.employee_code}</td>
                <td className="py-2.5">
                  <div className="font-medium text-slate-900">{e.full_name}</div>
                  <div className="text-slate-500">{e.email}</div>
                </td>
                <td className="py-2.5 text-slate-700">{e.department}</td>
                <td className="py-2.5 text-slate-700">{e.designation}</td>
                <td className="py-2.5 font-mono-tabular text-slate-600">{e.joining_date}</td>
                <td className="py-2.5">
                  <StatusText status={e.employment_status} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export function PayrollPanel({ onRequestStepUp }: { onRequestStepUp: (cb: () => void) => void }) {
  const [runs, setRuns] = useState<PayrollRunRecord[]>([]);
  const [employees, setEmployees] = useState<EmployeeRecord[]>([]);
  const [monthYear, setMonthYear] = useState(new Date().toISOString().slice(0, 7));
  const [editEmpId, setEditEmpId] = useState('');
  const [newCtc, setNewCtc] = useState('');
  const [error, setError] = useState('');
  const [msg, setMsg] = useState('');

  const load = useCallback(async () => {
    try {
      const [r, e] = await Promise.all([
        apiFetch<{ runs: PayrollRunRecord[] }>('/api/hr/payroll/runs'),
        apiFetch<{ employees: EmployeeRecord[] }>('/api/hr/employees'),
      ]);
      setRuns(r.runs);
      setEmployees(e.employees);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Unable to load payroll data.');
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  async function runPayroll(e: React.FormEvent) {
    e.preventDefault();
    setError('');
    setMsg('');
    try {
      await apiFetch('/api/hr/payroll/runs', {
        method: 'POST',
        body: JSON.stringify({ monthYear }),
      });
      setMsg(`Payroll run for ${monthYear} processed with PF, ESI, PT, and TDS.`);
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Payroll run failed.');
    }
  }

  async function updateSalary() {
    if (!editEmpId || !newCtc) return;
    setError('');
    setMsg('');
    try {
      await apiFetch(`/api/hr/employees/${editEmpId}/salary`, {
        method: 'PATCH',
        body: JSON.stringify({ ctcAnnual: Number(newCtc) }),
      });
      setMsg('Compensation updated securely and logged.');
      setEditEmpId('');
      setNewCtc('');
      await load();
    } catch (err) {
      if (err instanceof ApiError && err.code === 'STEP_UP_REQUIRED') {
        onRequestStepUp(() => {
          void updateSalary();
        });
        return;
      }
      setError(err instanceof ApiError ? err.message : 'Failed to update salary.');
    }
  }

  return (
    <div className="space-y-6">
      {error && <div className="p-3 rounded-xl bg-red-50 border border-red-200 text-red-800 text-sm">{error}</div>}
      {msg && <div className="p-3 rounded-xl bg-emerald-50 border border-emerald-200 text-emerald-900 text-sm">{msg}</div>}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <form onSubmit={runPayroll} className="bg-white border border-slate-200 rounded-2xl p-6 space-y-4">
          <div className="flex items-center gap-2 font-display font-bold text-slate-900">
            <IndianRupee className="w-4 h-4 text-blue-700" />
            <span>Process Monthly Payroll &amp; Statutory Run</span>
          </div>
          <p className="text-xs text-slate-500">
            Computes gross earnings, EPF (12%), ESI (0.75%), Professional Tax, and TDS for active employees.
          </p>
          <div className="flex items-center gap-3">
            <input
              type="month"
              required
              value={monthYear}
              onChange={(e) => setMonthYear(e.target.value)}
              className="px-3 py-2 text-sm border border-slate-300 rounded-lg font-mono-tabular"
            />
            <button
              type="submit"
              className="px-4 py-2 bg-blue-700 hover:bg-blue-800 text-white text-xs font-semibold rounded-lg"
            >
              Execute Payroll Run
            </button>
          </div>
        </form>

        <div className="bg-white border border-slate-200 rounded-2xl p-6 space-y-4">
          <div className="font-display font-bold text-slate-900">
            Update Compensation (Step-Up Protected)
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <select
              value={editEmpId}
              onChange={(e) => setEditEmpId(e.target.value)}
              className="px-3 py-2 text-sm border border-slate-300 rounded-lg bg-white"
            >
              <option value="">Select Employee</option>
              {employees.map((e) => (
                <option key={e.id} value={e.id}>
                  {e.full_name} (CTC: {(e.ctc_annual || 0).toLocaleString('en-IN')})
                </option>
              ))}
            </select>
            <input
              type="number"
              placeholder="Annual CTC (INR)"
              value={newCtc}
              onChange={(e) => setNewCtc(e.target.value)}
              className="px-3 py-2 text-sm border border-slate-300 rounded-lg font-mono-tabular"
            />
          </div>
          <button
            type="button"
            disabled={!editEmpId || !newCtc}
            onClick={updateSalary}
            className="px-4 py-2 bg-slate-900 text-white text-xs font-semibold rounded-lg disabled:opacity-50"
          >
            Update CTC
          </button>
        </div>
      </div>

      <div className="bg-white border border-slate-200 rounded-2xl p-6">
        <h3 className="font-display font-bold text-slate-900 text-sm mb-3">Payroll Run Ledger</h3>
        {runs.length === 0 ? (
          <div className="text-xs text-slate-500">No payroll runs executed yet.</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-slate-200 text-slate-500">
                  <th className="py-2 font-medium">Period</th>
                  <th className="py-2 font-medium text-right">Headcount</th>
                  <th className="py-2 font-medium text-right">Gross</th>
                  <th className="py-2 font-medium text-right">PF</th>
                  <th className="py-2 font-medium text-right">TDS</th>
                  <th className="py-2 font-medium text-right">Net Disbursed</th>
                  <th className="py-2 font-medium">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 font-mono-tabular">
                {runs.map((r) => (
                  <tr key={r.id}>
                    <td className="py-2.5 font-medium text-slate-900">{r.month_year}</td>
                    <td className="py-2.5 text-right">{r.employee_count}</td>
                    <td className="py-2.5 text-right">{r.total_gross.toLocaleString('en-IN')}</td>
                    <td className="py-2.5 text-right">{r.total_pf.toLocaleString('en-IN')}</td>
                    <td className="py-2.5 text-right">{r.total_tds.toLocaleString('en-IN')}</td>
                    <td className="py-2.5 text-right font-semibold text-emerald-700">
                      {r.total_net.toLocaleString('en-IN')}
                    </td>
                    <td className="py-2.5">
                      <StatusText status={r.status} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
