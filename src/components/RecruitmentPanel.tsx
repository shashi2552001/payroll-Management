import {
  AlertCircle,
  CheckCircle2,
  Download,
  Eye,
  FileCheck2,
  Link2,
  Mail,
  Plus,
  RefreshCw,
  Send,
  ShieldAlert,
  UserCheck,
  X,
  XCircle,
} from 'lucide-react';
import React, { useCallback, useEffect, useState } from 'react';
import { apiFetch, ApiError } from '../lib/api';
import type {
  AuthUser,
  CandidateChecklistEntry,
  CandidateDocumentRecord,
  CandidateInvitationRecord,
  CandidateSummary,
} from '../types';
import { StatusText } from './StatusText';

interface RecruitmentPanelProps {
  user: AuthUser;
  selectedCandidateIdFromNotification?: string | null;
  onClearNotificationSelection?: () => void;
}

interface InternalUserLite {
  id: string;
  full_name: string;
  email: string;
  role: string;
}

export function RecruitmentPanel({
  user,
  selectedCandidateIdFromNotification,
  onClearNotificationSelection,
}: RecruitmentPanelProps) {
  const [candidates, setCandidates] = useState<CandidateSummary[]>([]);
  const [recruiters, setRecruiters] = useState<InternalUserLite[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<{
    candidate: CandidateSummary;
    checklist: CandidateChecklistEntry[];
    invitations: CandidateInvitationRecord[];
  } | null>(null);

  const [showCreate, setShowCreate] = useState(false);
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');

  // Create candidate form
  const [fullName, setFullName] = useState('');
  const [email, setEmail] = useState('');
  const [mobile, setMobile] = useState('');
  const [jobPosition, setJobPosition] = useState('');
  const [department, setDepartment] = useState('Engineering');
  const [assignedRecruiterId, setAssignedRecruiterId] = useState(user.id);
  const [experienceYears, setExperienceYears] = useState('3');
  const [expectedCtc, setExpectedCtc] = useState('14 LPA');
  const [noticePeriodDays, setNoticePeriodDays] = useState('30');
  const [notes, setNotes] = useState('');

  // Email confirmation & send modal
  const [confirmEmailInput, setConfirmEmailInput] = useState('');
  const [emailConfirmedCheck, setEmailConfirmedCheck] = useState(false);
  const [showSendModal, setShowSendModal] = useState(false);
  const [lastInvitationNotice, setLastInvitationNotice] = useState<{
    delivered: boolean;
    status: string;
    error?: string;
    uploadLink?: string;
  } | null>(null);

  // Document preview & rejection modal
  const [previewDoc, setPreviewDoc] = useState<CandidateDocumentRecord | null>(null);
  const [rejectModalDoc, setRejectModalDoc] = useState<{
    docId: string;
    label: string;
    mode: 'Rejected' | 'Re-upload Required';
  } | null>(null);
  const [rejectionReason, setRejectionReason] = useState('');

  // Join / Create Employee modal (existing onboarding approval workflow)
  const [showJoinModal, setShowJoinModal] = useState(false);
  const [createEmpAccount, setCreateEmpAccount] = useState(true);
  const [empCtc, setEmpCtc] = useState('1200000');
  const [empPassword, setEmpPassword] = useState('');

  const [loading, setLoading] = useState(true);
  const [actionBusy, setActionBusy] = useState(false);
  const [error, setError] = useState('');
  const [banner, setBanner] = useState('');

  const canManageCandidates = user.role === 'HR' || user.role === 'Admin';

  const loadCandidates = useCallback(async () => {
    setLoading(true);
    try {
      const [candRes, usersRes] = await Promise.all([
        apiFetch<{ candidates: CandidateSummary[] }>('/api/candidates'),
        canManageCandidates
          ? apiFetch<{ users: InternalUserLite[] }>('/api/admin/users').catch(() => ({ users: [] }))
          : Promise.resolve({ users: [] }),
      ]);
      setCandidates(candRes.candidates);
      setRecruiters(usersRes.users);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to load candidates.');
    } finally {
      setLoading(false);
    }
  }, [canManageCandidates]);

  const loadDetail = useCallback(async (id: string) => {
    try {
      const res = await apiFetch<{
        candidate: CandidateSummary;
        checklist: CandidateChecklistEntry[];
        invitations: CandidateInvitationRecord[];
      }>(`/api/candidates/${id}`);
      setDetail(res);
      setConfirmEmailInput(res.candidate.email);
      setEmailConfirmedCheck(Boolean(res.candidate.email_confirmed_by_recruiter));
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Unable to load candidate record.');
    }
  }, []);

  useEffect(() => {
    loadCandidates();
  }, [loadCandidates]);

  useEffect(() => {
    if (selectedCandidateIdFromNotification) {
      setSelectedId(selectedCandidateIdFromNotification);
      loadDetail(selectedCandidateIdFromNotification);
      onClearNotificationSelection?.();
    }
  }, [selectedCandidateIdFromNotification, loadDetail, onClearNotificationSelection]);

  useEffect(() => {
    if (selectedId) {
      loadDetail(selectedId);
    }
  }, [selectedId, loadDetail]);

  async function handleCreateCandidate(e: React.FormEvent) {
    e.preventDefault();
    setError('');
    setBanner('');
    setActionBusy(true);
    try {
      const res = await apiFetch<{ candidate: CandidateSummary }>('/api/candidates', {
        method: 'POST',
        body: JSON.stringify({
          fullName,
          email,
          mobile,
          jobPosition,
          department,
          assignedRecruiterId,
          experienceYears: Number(experienceYears || 0),
          expectedCtc,
          noticePeriodDays: Number(noticePeriodDays || 30),
          notes,
        }),
      });
      setShowCreate(false);
      setFullName('');
      setEmail('');
      setMobile('');
      setJobPosition('');
      setNotes('');
      setBanner(`Candidate record created for ${res.candidate.full_name}. Confirm their email to send the upload link.`);
      await loadCandidates();
      setSelectedId(res.candidate.id);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to create candidate.');
    } finally {
      setActionBusy(false);
    }
  }

  async function handleConfirmAndSendLink(e: React.FormEvent) {
    e.preventDefault();
    if (!detail) return;
    setError('');
    setActionBusy(true);
    try {
      await apiFetch(`/api/candidates/${detail.candidate.id}/confirm-email`, {
        method: 'POST',
        body: JSON.stringify({ confirmedEmail: confirmEmailInput }),
      });

      const idempotencyKey = `inv_${detail.candidate.id}_${Date.now()}`;
      const res = await apiFetch<{
        emailDelivery: { delivered: boolean; status: string; error?: string };
        uploadLink?: string;
      }>(`/api/candidates/${detail.candidate.id}/send-invitation`, {
        method: 'POST',
        body: JSON.stringify({ idempotencyKey }),
      });

      setLastInvitationNotice({
        delivered: res.emailDelivery.delivered,
        status: res.emailDelivery.status,
        error: res.emailDelivery.error,
        uploadLink: res.uploadLink,
      });
      setShowSendModal(false);
      await Promise.all([loadCandidates(), loadDetail(detail.candidate.id)]);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Unable to send invitation link.');
    } finally {
      setActionBusy(false);
    }
  }

  async function handleResendInvitation() {
    if (!detail) return;
    setError('');
    setActionBusy(true);
    try {
      const res = await apiFetch<{
        emailDelivery: { delivered: boolean; status: string; error?: string };
        uploadLink?: string;
      }>(`/api/candidates/${detail.candidate.id}/resend-invitation`, {
        method: 'POST',
        body: JSON.stringify({ idempotencyKey: `resend_${detail.candidate.id}_${Date.now()}` }),
      });
      setLastInvitationNotice({
        delivered: res.emailDelivery.delivered,
        status: res.emailDelivery.status,
        error: res.emailDelivery.error,
        uploadLink: res.uploadLink,
      });
      await Promise.all([loadCandidates(), loadDetail(detail.candidate.id)]);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to resend link.');
    } finally {
      setActionBusy(false);
    }
  }

  async function handleRevokeInvitation() {
    if (!detail) return;
    setError('');
    setActionBusy(true);
    try {
      await apiFetch(`/api/candidates/${detail.candidate.id}/revoke-invitation`, {
        method: 'POST',
        body: JSON.stringify({ reason: 'Revoked by HR/Recruiter' }),
      });
      setBanner('Active candidate upload invitation and session have been revoked.');
      await loadDetail(detail.candidate.id);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to revoke link.');
    } finally {
      setActionBusy(false);
    }
  }

  async function handleApproveDoc(docId: string) {
    if (!detail) return;
    setError('');
    setActionBusy(true);
    try {
      const res = await apiFetch<{ verificationCompleted?: boolean }>(
        `/api/candidates/${detail.candidate.id}/documents/${docId}/review`,
        {
          method: 'POST',
          body: JSON.stringify({ decision: 'Approved' }),
        },
      );
      if (res.verificationCompleted) {
        setBanner('All mandatory documents approved! Candidate is now ready for existing HR Approval & Offer workflow.');
      } else {
        setBanner('Document marked as Approved.');
      }
      await Promise.all([loadCandidates(), loadDetail(detail.candidate.id)]);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Approval failed.');
    } finally {
      setActionBusy(false);
    }
  }

  async function handleRejectDocSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!detail || !rejectModalDoc) return;
    setError('');
    setActionBusy(true);
    try {
      const res = await apiFetch<{
        reuploadInvitation?: {
          emailDelivery?: { delivered: boolean; status: string; error?: string };
          uploadLink?: string;
        };
      }>(`/api/candidates/${detail.candidate.id}/documents/${rejectModalDoc.docId}/review`, {
        method: 'POST',
        body: JSON.stringify({
          decision: rejectModalDoc.mode,
          rejectionReason,
        }),
      });
      setRejectModalDoc(null);
      setRejectionReason('');
      setBanner('Document rejected with reason. Re-upload link issued to candidate.');
      if (res.reuploadInvitation?.uploadLink) {
        setLastInvitationNotice({
          delivered: Boolean(res.reuploadInvitation.emailDelivery?.delivered),
          status: res.reuploadInvitation.emailDelivery?.status || 'smtp_not_configured',
          error: res.reuploadInvitation.emailDelivery?.error,
          uploadLink: res.reuploadInvitation.uploadLink,
        });
      }
      await Promise.all([loadCandidates(), loadDetail(detail.candidate.id)]);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Rejection failed.');
    } finally {
      setActionBusy(false);
    }
  }

  async function handleAdvanceStage(
    nextStage: 'Offer Extended' | 'Onboarding Approved' | 'Joined' | 'Rejected',
  ) {
    if (!detail) return;
    setError('');
    setActionBusy(true);
    try {
      await apiFetch(`/api/candidates/${detail.candidate.id}/advance-stage`, {
        method: 'POST',
        body: JSON.stringify(
          nextStage === 'Joined'
            ? {
                nextStage,
                createEmployeeAccount: createEmpAccount,
                ctcAnnual: Number(empCtc || 0),
                passwordForEmployee: empPassword,
              }
            : { nextStage },
        ),
      });
      setShowJoinModal(false);
      setEmpPassword('');
      setBanner(`Candidate workflow updated to "${nextStage}".`);
      await Promise.all([loadCandidates(), loadDetail(detail.candidate.id)]);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Unable to advance stage.');
    } finally {
      setActionBusy(false);
    }
  }

  const filtered = candidates.filter((c) => {
    const q = search.toLowerCase();
    const matchesSearch =
      !q ||
      c.full_name.toLowerCase().includes(q) ||
      c.email.toLowerCase().includes(q) ||
      c.job_position.toLowerCase().includes(q) ||
      c.department.toLowerCase().includes(q);
    const matchesFilter =
      statusFilter === 'all' ||
      (statusFilter === 'pending_review' &&
        c.status.includes('Pending HR Verification')) ||
      (statusFilter === 'completed' && c.doc_verification_status === 'Completed');
    return matchesSearch && matchesFilter;
  });

  return (
    <div className="space-y-6">
      {/* Header Toolbar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="font-display text-xl font-bold text-slate-900">
            Recruitment &amp; Candidate Document Verification
          </h2>
          <p className="text-sm text-slate-500">
            Create candidate records, issue single-use upload invitations, verify documents, and progress HR onboarding approvals.
          </p>
        </div>
        {canManageCandidates && (
          <button
            type="button"
            onClick={() => {
              setError('');
              setShowCreate((v) => !v);
            }}
            className="inline-flex items-center gap-2 px-4 py-2.5 bg-blue-700 hover:bg-blue-800 text-white text-xs font-semibold rounded-lg tactile-btn whitespace-nowrap shrink-0"
          >
            <Plus className="w-4 h-4" />
            <span>New Candidate</span>
          </button>
        )}
      </div>

      {error && (
        <div className="p-3.5 rounded-xl bg-red-50 border border-red-200 text-red-800 text-sm flex items-start gap-2">
          <AlertCircle className="w-4 h-4 mt-0.5 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {banner && (
        <div className="p-3.5 rounded-xl bg-emerald-50 border border-emerald-200 text-emerald-900 text-sm flex items-start justify-between gap-2">
          <div className="flex items-start gap-2">
            <CheckCircle2 className="w-4 h-4 mt-0.5 shrink-0 text-emerald-700" />
            <span>{banner}</span>
          </div>
          <button type="button" onClick={() => setBanner('')} className="text-emerald-700">
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {lastInvitationNotice && (
        <div
          className={`p-4 rounded-xl border text-sm space-y-2 ${
            lastInvitationNotice.delivered
              ? 'bg-emerald-50 border-emerald-200 text-emerald-950'
              : 'bg-amber-50 border-amber-200 text-amber-950'
          }`}
        >
          <div className="font-semibold">
            {lastInvitationNotice.delivered
              ? 'Invitation Email Sent Successfully'
              : 'Invitation Link Created (SMTP Delivery Pending Configuration)'}
          </div>
          {lastInvitationNotice.error && (
            <p className="text-xs">{lastInvitationNotice.error}</p>
          )}
          {lastInvitationNotice.uploadLink && (
            <div className="p-2.5 bg-white border border-amber-200 rounded-lg flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <code className="text-xs font-mono-tabular break-all text-slate-800">
                {lastInvitationNotice.uploadLink}
              </code>
              <button
                type="button"
                onClick={() => navigator.clipboard.writeText(lastInvitationNotice.uploadLink!)}
                className="px-3 py-1.5 text-xs font-medium bg-slate-900 text-white rounded-md whitespace-nowrap shrink-0"
              >
                Copy Secure Link
              </button>
            </div>
          )}
        </div>
      )}

      {/* Create Candidate Form */}
      {showCreate && canManageCandidates && (
        <form
          onSubmit={handleCreateCandidate}
          className="bg-white border border-slate-200 rounded-2xl p-6 space-y-4 spatial-card"
        >
          <div className="flex items-center justify-between">
            <h3 className="font-display font-bold text-slate-900">
              Step 1: Create Candidate Record
            </h3>
            <button
              type="button"
              onClick={() => setShowCreate(false)}
              className="text-slate-400 hover:text-slate-700"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div>
              <label className="block text-xs font-medium text-slate-700 mb-1">Full Name</label>
              <input
                required
                value={fullName}
                onChange={(e) => setFullName(e.target.value)}
                placeholder="Rohan Verma"
                className="w-full px-3 py-2 text-sm border border-slate-300 rounded-lg"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-slate-700 mb-1">Email Address</label>
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="rohan.verma@example.com"
                className="w-full px-3 py-2 text-sm border border-slate-300 rounded-lg"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-slate-700 mb-1">Mobile Number</label>
              <input
                required
                value={mobile}
                onChange={(e) => setMobile(e.target.value)}
                placeholder="+91 98765 43210"
                className="w-full px-3 py-2 text-sm border border-slate-300 rounded-lg"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-slate-700 mb-1">Job Position</label>
              <input
                required
                value={jobPosition}
                onChange={(e) => setJobPosition(e.target.value)}
                placeholder="Senior Backend Engineer"
                className="w-full px-3 py-2 text-sm border border-slate-300 rounded-lg"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-slate-700 mb-1">Department</label>
              <input
                required
                value={department}
                onChange={(e) => setDepartment(e.target.value)}
                className="w-full px-3 py-2 text-sm border border-slate-300 rounded-lg"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-slate-700 mb-1">Assigned Recruiter</label>
              <select
                value={assignedRecruiterId}
                onChange={(e) => setAssignedRecruiterId(e.target.value)}
                className="w-full px-3 py-2 text-sm border border-slate-300 rounded-lg bg-white"
              >
                {recruiters.length === 0 ? (
                  <option value={user.id}>{user.fullName}</option>
                ) : (
                  recruiters.map((r) => (
                    <option key={r.id} value={r.id}>
                      {r.full_name} ({r.role})
                    </option>
                  ))
                )}
              </select>
            </div>
            <div>
              <label className="block text-xs font-medium text-slate-700 mb-1">Experience (Years)</label>
              <input
                type="number"
                step="0.5"
                value={experienceYears}
                onChange={(e) => setExperienceYears(e.target.value)}
                className="w-full px-3 py-2 text-sm border border-slate-300 rounded-lg"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-slate-700 mb-1">Expected CTC</label>
              <input
                value={expectedCtc}
                onChange={(e) => setExpectedCtc(e.target.value)}
                className="w-full px-3 py-2 text-sm border border-slate-300 rounded-lg"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-slate-700 mb-1">Notice Period (Days)</label>
              <input
                type="number"
                value={noticePeriodDays}
                onChange={(e) => setNoticePeriodDays(e.target.value)}
                className="w-full px-3 py-2 text-sm border border-slate-300 rounded-lg"
              />
            </div>
          </div>
          <div>
            <label className="block text-xs font-medium text-slate-700 mb-1">Recruiter Notes</label>
            <textarea
              rows={2}
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              className="w-full px-3 py-2 text-sm border border-slate-300 rounded-lg"
            />
          </div>
          <div className="flex justify-end gap-3">
            <button
              type="button"
              onClick={() => setShowCreate(false)}
              className="px-4 py-2 text-xs font-medium text-slate-700 bg-slate-100 rounded-lg"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={actionBusy}
              className="px-4 py-2 text-xs font-semibold text-white bg-blue-700 hover:bg-blue-800 rounded-lg disabled:opacity-60"
            >
              {actionBusy ? 'Saving...' : 'Save Candidate Record'}
            </button>
          </div>
        </form>
      )}

      {/* Split View: Candidate Pipeline Table + Document Verification Workspace */}
      <div className="grid grid-cols-1 xl:grid-cols-12 gap-6 items-start">
        <div className="xl:col-span-5 bg-white border border-slate-200 rounded-2xl overflow-hidden">
          <div className="p-4 border-b border-slate-200 space-y-3">
            <input
              type="search"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search candidate, email, role..."
              className="w-full px-3 py-2 text-sm border border-slate-200 rounded-lg"
            />
            <div className="flex items-center gap-1 p-1 bg-slate-100 rounded-lg">
              {[
                { key: 'all', label: 'All' },
                { key: 'pending_review', label: 'Pending Review' },
                { key: 'completed', label: 'Verified' },
              ].map((t) => (
                <button
                  key={t.key}
                  type="button"
                  onClick={() => setStatusFilter(t.key)}
                  className={`flex-1 py-1.5 px-2.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap ${
                    statusFilter === t.key
                      ? 'bg-white text-slate-900 shadow-sm'
                      : 'text-slate-600 hover:text-slate-900'
                  }`}
                >
                  {t.label}
                </button>
              ))}
            </div>
          </div>

          {loading ? (
            <div className="p-6 text-sm text-slate-500">Loading candidate pipeline...</div>
          ) : filtered.length === 0 ? (
            <div className="p-8 text-center text-sm text-slate-500">
              No candidates match the current filter.
            </div>
          ) : (
            <div className="divide-y divide-slate-100 max-h-[680px] overflow-y-auto">
              {filtered.map((c) => {
                const active = selectedId === c.id;
                return (
                  <button
                    key={c.id}
                    type="button"
                    onClick={() => setSelectedId(c.id)}
                    className={`w-full text-left p-4 transition-colors hover:bg-slate-50 ${
                      active ? 'bg-blue-50/70' : ''
                    }`}
                  >
                    <div className="flex items-start justify-between gap-2">
                      <div className="min-w-0">
                        <div className="font-display font-semibold text-sm text-slate-900 truncate">
                          {c.full_name}
                        </div>
                        <div className="text-xs text-slate-500 truncate mt-0.5">
                          {c.job_position} · {c.department}
                        </div>
                      </div>
                      <StatusText status={c.doc_verification_status} />
                    </div>
                    <div className="mt-2 flex flex-wrap items-center gap-2 text-xs text-slate-500">
                      <span className="truncate">{c.email}</span>
                      <span aria-hidden="true">·</span>
                      <span className="font-mono-tabular">
                        {c.docSummary?.approved_count || 0} approved / {c.docSummary?.uploaded_count || 0} awaiting
                      </span>
                    </div>
                    <div className="mt-1 text-xs font-medium text-slate-700 truncate">
                      Stage: {c.status}
                    </div>
                  </button>
                );
              })}
            </div>
          )}
        </div>

        {/* Right Column: Candidate Verification & Onboarding Stage */}
        <div className="xl:col-span-7 bg-white border border-slate-200 rounded-2xl p-6">
          {!detail ? (
            <div className="py-16 text-center space-y-2">
              <FileCheck2 className="w-8 h-8 text-slate-300 mx-auto" />
              <div className="text-sm font-medium text-slate-700">
                Select a candidate to manage document collection &amp; verification
              </div>
              <p className="text-xs text-slate-500">
                Send single-use upload links, inspect scanned files, approve or reject documents, and complete onboarding approvals.
              </p>
            </div>
          ) : (
            <div className="space-y-6">
              {/* Candidate Summary Header */}
              <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4 pb-5 border-b border-slate-200">
                <div>
                  <div className="text-xs text-slate-500">
                    {detail.candidate.department} · Assigned to {detail.candidate.recruiter_name || 'Recruiter'}
                  </div>
                  <h3 className="font-display text-xl font-bold text-slate-900 mt-0.5">
                    {detail.candidate.full_name}
                  </h3>
                  <div className="mt-1 text-xs text-slate-600 flex flex-wrap items-center gap-2">
                    <span>{detail.candidate.job_position}</span>
                    <span aria-hidden="true">·</span>
                    <span>{detail.candidate.email}</span>
                    <span aria-hidden="true">·</span>
                    <span className="font-mono-tabular">{detail.candidate.mobile}</span>
                  </div>
                  <div className="mt-2 flex flex-wrap items-center gap-3">
                    <StatusText status={detail.candidate.status} />
                    <span className="text-xs text-slate-400">|</span>
                    <span className="text-xs text-slate-600">
                      Verification: <strong>{detail.candidate.doc_verification_status}</strong>
                    </span>
                  </div>
                </div>

                {canManageCandidates && (
                  <div className="flex flex-wrap items-center gap-2 shrink-0">
                    <button
                      type="button"
                      onClick={() => setShowSendModal(true)}
                      className="inline-flex items-center gap-1.5 px-3.5 py-2 bg-blue-700 hover:bg-blue-800 text-white text-xs font-semibold rounded-lg whitespace-nowrap"
                    >
                      <Send className="w-3.5 h-3.5" />
                      <span>Send Document Upload Link</span>
                    </button>
                    {detail.invitations.length > 0 && (
                      <>
                        <button
                          type="button"
                          disabled={actionBusy || !detail.candidate.email_confirmed_by_recruiter}
                          onClick={handleResendInvitation}
                          className="inline-flex items-center gap-1.5 px-3 py-2 bg-slate-100 hover:bg-slate-200 text-slate-800 text-xs font-medium rounded-lg whitespace-nowrap disabled:opacity-50"
                        >
                          <RefreshCw className="w-3.5 h-3.5" />
                          <span>Resend</span>
                        </button>
                        <button
                          type="button"
                          disabled={actionBusy}
                          onClick={handleRevokeInvitation}
                          className="inline-flex items-center gap-1.5 px-3 py-2 bg-red-50 hover:bg-red-100 text-red-700 text-xs font-medium rounded-lg whitespace-nowrap"
                        >
                          <XCircle className="w-3.5 h-3.5" />
                          <span>Revoke Link</span>
                        </button>
                      </>
                    )}
                  </div>
                )}
              </div>

              {/* Document Checklist & Review Table */}
              <div>
                <h4 className="font-display font-semibold text-sm text-slate-900 mb-3">
                  Document Checklist &amp; Verification
                </h4>
                <div className="border border-slate-200 rounded-xl divide-y divide-slate-200">
                  {detail.checklist.map((entry) => {
                    const doc = entry.currentDocument;
                    return (
                      <div key={entry.requirement.id} className="p-4 space-y-2">
                        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                          <div>
                            <div className="text-sm font-semibold text-slate-900">
                              {entry.requirement.label}
                              <span className="ml-2 text-xs font-normal text-slate-500">
                                {entry.requirement.is_mandatory ? 'Mandatory' : 'Optional'}
                              </span>
                            </div>
                            {doc ? (
                              <div className="text-xs text-slate-500 mt-0.5 flex flex-wrap items-center gap-2">
                                <span>{doc.original_filename}</span>
                                <span aria-hidden="true">·</span>
                                <span className="font-mono-tabular">v{doc.version}</span>
                                <span aria-hidden="true">·</span>
                                <span className="font-mono-tabular">
                                  {new Date(doc.uploaded_at).toLocaleString()}
                                </span>
                                <span aria-hidden="true">·</span>
                                <span className="text-emerald-700">Scan: {doc.malware_scan_status}</span>
                              </div>
                            ) : (
                              <div className="text-xs text-slate-400 mt-0.5">
                                Not uploaded by candidate yet
                              </div>
                            )}
                          </div>

                          <div className="flex items-center gap-2 shrink-0">
                            <StatusText status={entry.status} />
                            {doc && doc.signedDownloadUrl && (
                              <>
                                <button
                                  type="button"
                                  onClick={() => setPreviewDoc(doc)}
                                  className="inline-flex items-center gap-1 px-2.5 py-1.5 text-xs font-medium text-slate-700 bg-slate-100 hover:bg-slate-200 rounded-md"
                                >
                                  <Eye className="w-3.5 h-3.5" />
                                  <span>Preview</span>
                                </button>
                                <a
                                  href={`${doc.signedDownloadUrl}&disposition=attachment`}
                                  className="inline-flex items-center gap-1 px-2.5 py-1.5 text-xs font-medium text-slate-700 bg-slate-100 hover:bg-slate-200 rounded-md"
                                >
                                  <Download className="w-3.5 h-3.5" />
                                </a>
                              </>
                            )}
                          </div>
                        </div>

                        {doc?.rejection_reason && (
                          <div className="text-xs text-red-800 bg-red-50 border border-red-200 rounded-lg px-3 py-2">
                            Rejection Reason: {doc.rejection_reason}
                            {doc.reviewer_name ? ` (Reviewed by ${doc.reviewer_name})` : ''}
                          </div>
                        )}

                        {doc && doc.status === 'Approved' && doc.reviewer_name && (
                          <div className="text-xs text-emerald-800">
                            Verified by {doc.reviewer_name} on{' '}
                            <span className="font-mono-tabular">
                              {doc.reviewed_at ? new Date(doc.reviewed_at).toLocaleString() : ''}
                            </span>
                          </div>
                        )}

                        {canManageCandidates && doc && doc.status === 'Uploaded' && (
                          <div className="pt-1 flex flex-wrap items-center gap-2">
                            <button
                              type="button"
                              disabled={actionBusy}
                              onClick={() => handleApproveDoc(doc.id)}
                              className="px-3 py-1.5 bg-emerald-700 hover:bg-emerald-800 text-white text-xs font-semibold rounded-md"
                            >
                              Approve / Verify
                            </button>
                            <button
                              type="button"
                              disabled={actionBusy}
                              onClick={() => {
                                setRejectionReason('');
                                setRejectModalDoc({
                                  docId: doc.id,
                                  label: entry.requirement.label,
                                  mode: 'Rejected',
                                });
                              }}
                              className="px-3 py-1.5 bg-red-600 hover:bg-red-700 text-white text-xs font-semibold rounded-md"
                            >
                              Reject
                            </button>
                            <button
                              type="button"
                              disabled={actionBusy}
                              onClick={() => {
                                setRejectionReason('');
                                setRejectModalDoc({
                                  docId: doc.id,
                                  label: entry.requirement.label,
                                  mode: 'Re-upload Required',
                                });
                              }}
                              className="px-3 py-1.5 bg-amber-600 hover:bg-amber-700 text-white text-xs font-semibold rounded-md"
                            >
                              Request Re-upload
                            </button>
                          </div>
                        )}

                        {entry.history.length > 1 && (
                          <div className="text-xs text-slate-500 pt-1">
                            Version History: {entry.history.map((h) => `v${h.version} (${h.status})`).join(' · ')}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Existing Recruitment & Onboarding Approval Workflow */}
              {canManageCandidates && (
                <div className="p-4 bg-slate-50 border border-slate-200 rounded-xl space-y-3">
                  <div className="flex items-center justify-between gap-2">
                    <div>
                      <div className="text-sm font-semibold text-slate-900">
                        Existing HR Onboarding &amp; Offer Workflow
                      </div>
                      <div className="text-xs text-slate-500">
                        Requires completed document verification and explicit HR approval before employee creation.
                      </div>
                    </div>
                  </div>
                  <div className="flex flex-wrap items-center gap-2">
                    <button
                      type="button"
                      disabled={
                        actionBusy ||
                        detail.candidate.doc_verification_status !== 'Completed' ||
                        detail.candidate.status === 'Offer Extended' ||
                        detail.candidate.status === 'Onboarding Approved' ||
                        detail.candidate.status === 'Joined'
                      }
                      onClick={() => handleAdvanceStage('Offer Extended')}
                      className="px-3.5 py-2 bg-white border border-slate-300 hover:bg-slate-100 text-slate-800 text-xs font-semibold rounded-lg disabled:opacity-50"
                    >
                      1. Issue Offer Letter
                    </button>
                    <button
                      type="button"
                      disabled={
                        actionBusy ||
                        detail.candidate.doc_verification_status !== 'Completed' ||
                        detail.candidate.status === 'Onboarding Approved' ||
                        detail.candidate.status === 'Joined'
                      }
                      onClick={() => handleAdvanceStage('Onboarding Approved')}
                      className="px-3.5 py-2 bg-white border border-slate-300 hover:bg-slate-100 text-slate-800 text-xs font-semibold rounded-lg disabled:opacity-50"
                    >
                      2. HR Onboarding Approval
                    </button>
                    <button
                      type="button"
                      disabled={
                        actionBusy ||
                        detail.candidate.status !== 'Onboarding Approved'
                      }
                      onClick={() => setShowJoinModal(true)}
                      className="inline-flex items-center gap-1.5 px-3.5 py-2 bg-emerald-700 hover:bg-emerald-800 text-white text-xs font-semibold rounded-lg disabled:opacity-50"
                    >
                      <UserCheck className="w-3.5 h-3.5" />
                      <span>3. Complete Joining &amp; Create Employee</span>
                    </button>
                  </div>
                </div>
              )}

              {/* Invitation History */}
              {detail.invitations.length > 0 && (
                <div>
                  <h4 className="font-display font-semibold text-sm text-slate-900 mb-2">
                    Invitation Link History
                  </h4>
                  <div className="border border-slate-200 rounded-xl divide-y divide-slate-100 text-xs">
                    {detail.invitations.map((inv) => (
                      <div key={inv.id} className="p-3 flex flex-wrap items-center justify-between gap-2">
                        <div>
                          <span className="font-medium text-slate-800">
                            {inv.purpose === 'reupload' ? 'Re-upload Invitation' : 'Initial Invitation'}
                          </span>
                          <span className="text-slate-400 mx-1.5">·</span>
                          <span className="text-slate-600">{inv.sent_to_email}</span>
                          <span className="text-slate-400 mx-1.5">·</span>
                          <span className="font-mono-tabular text-slate-500">
                            Expires {new Date(inv.expires_at).toLocaleString()}
                          </span>
                        </div>
                        <div className="flex items-center gap-3">
                          <StatusText
                            status={
                              inv.revoked_at
                                ? 'Revoked'
                                : inv.accepted_at
                                  ? 'Link Redeemed'
                                  : inv.email_delivery_status
                            }
                          />
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Confirm Email & Send Document Upload Link Modal */}
      {showSendModal && detail && (
        <div className="fixed inset-0 z-50 bg-slate-900/50 flex items-center justify-center p-4">
          <form
            onSubmit={handleConfirmAndSendLink}
            className="bg-white border border-slate-200 rounded-2xl max-w-md w-full p-6 space-y-4 spatial-card"
          >
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 font-display font-bold text-slate-900">
                <Mail className="w-4 h-4 text-blue-700" />
                <span>Confirm Candidate Email</span>
              </div>
              <button type="button" onClick={() => setShowSendModal(false)}>
                <X className="w-4 h-4 text-slate-400" />
              </button>
            </div>
            <p className="text-sm text-slate-600">
              Verify the candidate’s email address before dispatching a single-use 9HR India document upload link to{' '}
              <strong>{detail.candidate.full_name}</strong>.
            </p>
            <div>
              <label className="block text-xs font-medium text-slate-700 mb-1">
                Candidate Email Address
              </label>
              <input
                type="email"
                required
                value={confirmEmailInput}
                onChange={(e) => setConfirmEmailInput(e.target.value)}
                className="w-full px-3 py-2 text-sm border border-slate-300 rounded-lg"
              />
            </div>
            <label className="flex items-start gap-2.5 text-xs text-slate-700 cursor-pointer">
              <input
                type="checkbox"
                required
                checked={emailConfirmedCheck}
                onChange={(e) => setEmailConfirmedCheck(e.target.checked)}
                className="mt-0.5"
              />
              <span>
                I confirm this email address belongs to {detail.candidate.full_name} and authorize sending the secure upload invitation.
              </span>
            </label>
            <div className="flex justify-end gap-2 pt-2">
              <button
                type="button"
                onClick={() => setShowSendModal(false)}
                className="px-4 py-2 text-xs font-medium text-slate-700 bg-slate-100 rounded-lg"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={actionBusy || !emailConfirmedCheck}
                className="inline-flex items-center gap-1.5 px-4 py-2 text-xs font-semibold text-white bg-blue-700 hover:bg-blue-800 rounded-lg disabled:opacity-50"
              >
                <Link2 className="w-3.5 h-3.5" />
                <span>{actionBusy ? 'Sending...' : 'Confirm & Send Link'}</span>
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Mandatory Rejection Reason Modal */}
      {rejectModalDoc && (
        <div className="fixed inset-0 z-50 bg-slate-900/50 flex items-center justify-center p-4">
          <form
            onSubmit={handleRejectDocSubmit}
            className="bg-white border border-slate-200 rounded-2xl max-w-md w-full p-6 space-y-4 spatial-card"
          >
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 font-display font-bold text-slate-900">
                <ShieldAlert className="w-4 h-4 text-red-600" />
                <span>
                  {rejectModalDoc.mode === 'Rejected' ? 'Reject Document' : 'Request Re-upload'}
                </span>
              </div>
              <button type="button" onClick={() => setRejectModalDoc(null)}>
                <X className="w-4 h-4 text-slate-400" />
              </button>
            </div>
            <p className="text-sm text-slate-600">
              Provide a clear reason for rejecting <strong>{rejectModalDoc.label}</strong>. Only this document will require re-uploading; approved documents remain verified.
            </p>
            <div>
              <label className="block text-xs font-medium text-slate-700 mb-1">
                Mandatory Rejection Reason
              </label>
              <textarea
                required
                rows={3}
                value={rejectionReason}
                onChange={(e) => setRejectionReason(e.target.value)}
                placeholder="e.g., PAN card text is blurry/cropped. Please upload a clear scan."
                className="w-full px-3 py-2 text-sm border border-slate-300 rounded-lg"
              />
            </div>
            <div className="flex justify-end gap-2">
              <button
                type="button"
                onClick={() => setRejectModalDoc(null)}
                className="px-4 py-2 text-xs font-medium text-slate-700 bg-slate-100 rounded-lg"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={actionBusy || !rejectionReason.trim()}
                className="px-4 py-2 text-xs font-semibold text-white bg-red-600 hover:bg-red-700 rounded-lg disabled:opacity-50"
              >
                {actionBusy ? 'Sending...' : 'Confirm & Notify Candidate'}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Document Inline Preview Modal */}
      {previewDoc && previewDoc.signedDownloadUrl && (
        <div className="fixed inset-0 z-50 bg-slate-900/70 flex items-center justify-center p-4">
          <div className="bg-white border border-slate-200 rounded-2xl max-w-4xl w-full h-[85vh] flex flex-col overflow-hidden">
            <div className="px-6 py-4 border-b border-slate-200 flex items-center justify-between">
              <div>
                <div className="font-display font-bold text-slate-900 text-sm">
                  {previewDoc.original_filename}
                </div>
                <div className="text-xs text-slate-500 font-mono-tabular">
                  SHA-256: {previewDoc.sha256_hash.slice(0, 16)}... · v{previewDoc.version}
                </div>
              </div>
              <button
                type="button"
                onClick={() => setPreviewDoc(null)}
                className="p-1.5 text-slate-500 hover:text-slate-900"
              >
                <X className="w-5 h-5" />
              </button>
            </div>
            <div className="flex-1 bg-slate-100 p-4 overflow-auto flex items-center justify-center">
              {previewDoc.mime_type === 'application/pdf' ? (
                <iframe
                  src={previewDoc.signedDownloadUrl}
                  title={previewDoc.original_filename}
                  className="w-full h-full rounded-lg bg-white border border-slate-200"
                />
              ) : (
                <img
                  src={previewDoc.signedDownloadUrl}
                  alt={previewDoc.original_filename}
                  className="max-w-full max-h-full object-contain rounded-lg shadow"
                />
              )}
            </div>
          </div>
        </div>
      )}

      {/* Complete Joining & Employee Creation Modal */}
      {showJoinModal && detail && (
        <div className="fixed inset-0 z-50 bg-slate-900/50 flex items-center justify-center p-4">
          <div className="bg-white border border-slate-200 rounded-2xl max-w-md w-full p-6 space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="font-display font-bold text-slate-900">
                Complete Joining &amp; Onboarding
              </h3>
              <button type="button" onClick={() => setShowJoinModal(false)}>
                <X className="w-4 h-4 text-slate-400" />
              </button>
            </div>
            <p className="text-xs text-slate-600">
              HR Onboarding Approval is complete for <strong>{detail.candidate.full_name}</strong>.
            </p>
            <label className="flex items-center gap-2 text-xs font-medium text-slate-800">
              <input
                type="checkbox"
                checked={createEmpAccount}
                onChange={(e) => setCreateEmpAccount(e.target.checked)}
              />
              <span>Create Employee Profile &amp; ESS Login Account</span>
            </label>
            {createEmpAccount && (
              <div className="space-y-3">
                <div>
                  <label className="block text-xs font-medium text-slate-700 mb-1">
                    Annual CTC (INR)
                  </label>
                  <input
                    type="number"
                    value={empCtc}
                    onChange={(e) => setEmpCtc(e.target.value)}
                    className="w-full px-3 py-2 text-sm border border-slate-300 rounded-lg font-mono-tabular"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-slate-700 mb-1">
                    Initial Employee Password (min 10 characters)
                  </label>
                  <input
                    type="password"
                    minLength={10}
                    value={empPassword}
                    onChange={(e) => setEmpPassword(e.target.value)}
                    className="w-full px-3 py-2 text-sm border border-slate-300 rounded-lg"
                  />
                </div>
              </div>
            )}
            <div className="flex justify-end gap-2 pt-2">
              <button
                type="button"
                onClick={() => setShowJoinModal(false)}
                className="px-4 py-2 text-xs font-medium text-slate-700 bg-slate-100 rounded-lg"
              >
                Cancel
              </button>
              <button
                type="button"
                disabled={actionBusy || (createEmpAccount && empPassword.length < 10)}
                onClick={() => handleAdvanceStage('Joined')}
                className="px-4 py-2 text-xs font-semibold text-white bg-emerald-700 hover:bg-emerald-800 rounded-lg disabled:opacity-50"
              >
                {actionBusy ? 'Processing...' : 'Finalize Joining'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
