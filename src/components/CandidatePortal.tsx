import {
  AlertCircle,
  CheckCircle2,
  FileText,
  Lock,
  ShieldCheck,
  Upload,
} from 'lucide-react';
import { motion } from 'motion/react';
import React, { useCallback, useEffect, useState } from 'react';
import { apiFetch, ApiError } from '../lib/api';
import type { PortalChecklistItem } from '../types';
import { StatusText } from './StatusText';

interface PortalSessionData {
  candidate: {
    fullName: string;
    jobPosition: string;
    department: string;
    status: string;
    docVerificationStatus: string;
  };
  purpose: 'initial_upload' | 'reupload';
  supportEmail: string;
  checklist: PortalChecklistItem[];
}

export function CandidatePortal() {
  const [data, setData] = useState<PortalSessionData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [uploadingType, setUploadingType] = useState<string | null>(null);
  const [uploadError, setUploadError] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [submittedConfirmation, setSubmittedConfirmation] = useState<{
    status: string;
    submittedAt: string;
    documentCount: number;
    documents: Array<{ doc_type: string; original_filename: string; status: string; version: number }>;
  } | null>(null);

  const loadSession = useCallback(async () => {
    const res = await apiFetch<PortalSessionData>('/api/candidate-portal/session', {
      skipAutoRefresh: true,
    });
    setData(res);
  }, []);

  useEffect(() => {
    let active = true;
    async function init() {
      setLoading(true);
      setError('');
      try {
        const params = new URLSearchParams(window.location.search);
        const token = params.get('t');
        if (token) {
          await apiFetch('/api/candidate-portal/accept-invitation', {
            method: 'POST',
            body: JSON.stringify({ token }),
            skipAutoRefresh: true,
          });
          // Strip single-use invitation token from URL immediately
          window.history.replaceState({}, '', '/candidate-upload');
        }
        await loadSession();
      } catch (err) {
        if (active) {
          setError(
            err instanceof ApiError
              ? err.message
              : 'Unable to open candidate upload session.',
          );
        }
      } finally {
        if (active) setLoading(false);
      }
    }
    init();
    return () => {
      active = false;
    };
  }, [loadSession]);

  async function handleFileUpload(docType: string, file: File | undefined) {
    if (!file) return;
    setUploadError('');
    setUploadingType(docType);
    try {
      const form = new FormData();
      form.append('docType', docType);
      form.append('file', file);
      await apiFetch('/api/candidate-portal/upload', {
        method: 'POST',
        body: form,
        skipAutoRefresh: true,
      });
      await loadSession();
    } catch (err) {
      setUploadError(
        err instanceof ApiError ? err.message : 'Document upload failed validation.',
      );
    } finally {
      setUploadingType(null);
    }
  }

  async function handleFinalSubmit() {
    setUploadError('');
    setSubmitting(true);
    try {
      const res = await apiFetch<{
        submitted: boolean;
        status: string;
        submittedAt: string;
        documentCount: number;
        documents: Array<{ doc_type: string; original_filename: string; status: string; version: number }>;
      }>('/api/candidate-portal/submit', {
        method: 'POST',
        skipAutoRefresh: true,
      });
      setSubmittedConfirmation(res);
      await loadSession();
    } catch (err) {
      setUploadError(
        err instanceof ApiError ? err.message : 'Unable to submit documents.',
      );
    } finally {
      setSubmitting(false);
    }
  }

  if (loading) {
    return (
      <div className="min-h-screen bg-slate-50 flex items-center justify-center p-6">
        <div className="bg-white border border-slate-200 rounded-2xl p-8 max-w-md w-full text-center spatial-card">
          <div className="text-sm font-medium text-slate-700">
            Verifying your secure 9HR India upload link...
          </div>
        </div>
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="min-h-screen bg-slate-50 flex items-center justify-center p-6">
        <div className="bg-white border border-slate-200 rounded-2xl p-8 max-w-lg w-full spatial-card space-y-4">
          <div className="flex items-center gap-3">
            <img
              src="/assets/aistudio/image_0ecd2493.png"
              alt="9HR India"
              className="w-11 h-11 rounded-full object-contain"
            />
            <div>
              <div className="font-display font-bold text-slate-900">9HR India</div>
              <div className="text-xs text-slate-500">Candidate Document Portal</div>
            </div>
          </div>
          <div className="p-4 rounded-xl bg-red-50 border border-red-200 text-red-900 text-sm flex items-start gap-2.5">
            <AlertCircle className="w-5 h-5 text-red-600 shrink-0 mt-0.5" />
            <div>
              <div className="font-semibold">Upload Link Unavailable</div>
              <p className="mt-1 text-red-800">{error || 'Your session could not be verified.'}</p>
            </div>
          </div>
          <p className="text-xs text-slate-500">
            If you need a new secure link, please contact HR Support at{' '}
            <span className="font-medium text-slate-700">hr-support@9hrindia.com</span>.
          </p>
        </div>
      </div>
    );
  }

  const mandatoryItems = data.checklist.filter((i) => i.isMandatory);
  const completedMandatory = mandatoryItems.filter(
    (i) => i.status === 'Uploaded' || i.status === 'Approved',
  ).length;
  const progressPct =
    mandatoryItems.length > 0
      ? Math.round((completedMandatory / mandatoryItems.length) * 100)
      : 100;
  const allMandatoryReady = completedMandatory === mandatoryItems.length;

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900">
      <header className="bg-white border-b border-slate-200 px-4 sm:px-8 py-4">
        <div className="max-w-4xl mx-auto flex items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <img
              src="/assets/aistudio/image_0ecd2493.png"
              alt="9HR India"
              className="w-10 h-10 rounded-full object-contain"
            />
            <div>
              <div className="font-display font-bold text-slate-900">9HR India</div>
              <div className="text-xs text-slate-500">Secure Candidate Document Upload</div>
            </div>
          </div>
          <div className="hidden sm:flex items-center gap-1.5 text-xs text-slate-600">
            <Lock className="w-3.5 h-3.5 text-emerald-700" />
            <span>Private Encrypted Vault</span>
          </div>
        </div>
      </header>

      <main className="max-w-4xl mx-auto p-4 sm:p-8 space-y-6">
        {/* Candidate Welcome & Progress Card */}
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          className="bg-white border border-slate-200 rounded-2xl p-6 sm:p-8 spatial-card"
        >
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div>
              <div className="text-xs text-slate-500">
                {data.candidate.department} · {data.candidate.jobPosition}
              </div>
              <h1 className="font-display text-2xl font-bold text-slate-900 mt-1">
                Welcome, {data.candidate.fullName}
              </h1>
              <p className="text-sm text-slate-600 mt-1">
                {data.purpose === 'reupload'
                  ? 'Please re-upload the flagged document(s) below. Previously approved documents remain verified.'
                  : 'Upload your onboarding documents below. Allowed formats: PDF, JPG, PNG.'}
              </p>
            </div>
            <div className="sm:text-right shrink-0">
              <div className="text-xs text-slate-500">Mandatory Progress</div>
              <div className="font-mono-tabular text-2xl font-bold text-blue-700 mt-0.5">
                {completedMandatory} / {mandatoryItems.length}
              </div>
            </div>
          </div>

          <div className="mt-5 h-2.5 w-full bg-slate-100 rounded-full overflow-hidden">
            <div
              className="h-full bg-blue-700 transition-all duration-300"
              style={{ width: `${progressPct}%` }}
            />
          </div>
        </motion.div>

        {submittedConfirmation && (
          <div className="bg-emerald-50 border border-emerald-200 rounded-2xl p-6 space-y-3">
            <div className="flex items-start gap-3">
              <CheckCircle2 className="w-5 h-5 text-emerald-700 shrink-0 mt-0.5" />
              <div>
                <h2 className="font-display font-bold text-emerald-950 text-lg">
                  Documents Submitted Successfully
                </h2>
                <p className="text-sm text-emerald-900 mt-0.5">
                  Status: <strong>{submittedConfirmation.status}</strong> ·{' '}
                  {submittedConfirmation.documentCount} document(s) received on{' '}
                  <span className="font-mono-tabular">
                    {new Date(submittedConfirmation.submittedAt).toLocaleString()}
                  </span>
                </p>
              </div>
            </div>
            <div className="bg-white border border-emerald-200 rounded-xl divide-y divide-slate-100">
              {submittedConfirmation.documents.map((d) => (
                <div key={d.doc_type} className="px-4 py-2.5 flex items-center justify-between text-sm">
                  <span className="font-medium text-slate-800 truncate">{d.original_filename}</span>
                  <StatusText status={d.status} />
                </div>
              ))}
            </div>
          </div>
        )}

        {uploadError && (
          <div
            role="alert"
            className="p-4 rounded-xl bg-red-50 border border-red-200 text-red-900 text-sm flex items-start gap-2.5"
          >
            <AlertCircle className="w-4 h-4 text-red-600 shrink-0 mt-0.5" />
            <span>{uploadError}</span>
          </div>
        )}

        {/* Document Checklist */}
        <div className="bg-white border border-slate-200 rounded-2xl divide-y divide-slate-200">
          {data.checklist.map((item) => {
            const isUploading = uploadingType === item.docType;
            const isApproved = item.status === 'Approved';
            return (
              <div
                key={item.docType}
                className="p-5 sm:p-6 flex flex-col sm:flex-row sm:items-center justify-between gap-4"
              >
                <div className="space-y-1 min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-display font-semibold text-slate-900 text-sm sm:text-base">
                      {item.label}
                    </span>
                    <span className="text-xs text-slate-500">
                      · {item.isMandatory ? 'Mandatory' : 'Optional'} · Max {item.maxSizeMb} MB
                    </span>
                  </div>
                  <p className="text-xs sm:text-sm text-slate-600">{item.description}</p>

                  {item.rejectionReason && (
                    <div className="mt-2 p-2.5 rounded-lg bg-red-50 border border-red-200 text-xs text-red-800">
                      <strong>HR Feedback:</strong> {item.rejectionReason}
                    </div>
                  )}

                  {item.uploadedFile && (
                    <div className="pt-1 flex flex-wrap items-center gap-2 text-xs text-slate-500">
                      <FileText className="w-3.5 h-3.5 text-slate-400" />
                      <span className="font-medium text-slate-700 truncate max-w-[220px]">
                        {item.uploadedFile.filename}
                      </span>
                      <span aria-hidden="true">·</span>
                      <span className="font-mono-tabular">
                        {(item.uploadedFile.sizeBytes / 1024).toFixed(1)} KB
                      </span>
                      <span aria-hidden="true">·</span>
                      <span className="font-mono-tabular">v{item.uploadedFile.version}</span>
                    </div>
                  )}
                </div>

                <div className="flex items-center justify-between sm:justify-end gap-4 shrink-0">
                  <StatusText status={item.status} />

                  {isApproved ? (
                    <span className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium text-emerald-800 bg-emerald-50 border border-emerald-200 rounded-lg whitespace-nowrap">
                      <ShieldCheck className="w-3.5 h-3.5" />
                      <span>Verified</span>
                    </span>
                  ) : (
                    <label className="inline-flex items-center justify-center gap-2 px-4 py-2.5 min-h-[44px] text-xs font-semibold text-white bg-blue-700 hover:bg-blue-800 rounded-lg cursor-pointer tactile-btn whitespace-nowrap shrink-0">
                      <Upload className="w-3.5 h-3.5" />
                      <span>
                        {isUploading
                          ? 'Scanning & Uploading...'
                          : item.uploadedFile
                            ? 'Replace File'
                            : 'Upload File'}
                      </span>
                      <input
                        type="file"
                        accept=".pdf,.jpg,.jpeg,.png,application/pdf,image/jpeg,image/png"
                        disabled={isUploading}
                        className="sr-only"
                        onChange={(e) => {
                          const file = e.target.files?.[0];
                          e.target.value = '';
                          handleFileUpload(item.docType, file);
                        }}
                      />
                    </label>
                  )}
                </div>
              </div>
            );
          })}
        </div>

        {/* Submit Button */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-white border border-slate-200 rounded-2xl p-6">
          <div className="text-xs sm:text-sm text-slate-600">
            Need assistance? Contact{' '}
            <span className="font-medium text-slate-900">{data.supportEmail}</span>
          </div>
          <button
            type="button"
            disabled={!allMandatoryReady || submitting}
            onClick={handleFinalSubmit}
            className="px-6 py-3 min-h-[44px] bg-emerald-700 hover:bg-emerald-800 text-white text-sm font-semibold rounded-lg tactile-btn disabled:opacity-50 whitespace-nowrap"
          >
            {submitting ? 'Submitting to HR...' : 'Submit Documents for Verification'}
          </button>
        </div>
      </main>
    </div>
  );
}
