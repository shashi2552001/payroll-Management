import { AlertTriangle, CheckCircle2, Clock, ShieldAlert, XCircle } from 'lucide-react';

interface StatusTextProps {
  status: string;
}

export function StatusText({ status }: StatusTextProps) {
  const s = status.toLowerCase();

  if (
    s.includes('approved') ||
    s.includes('completed') ||
    s.includes('verified') ||
    s.includes('joined') ||
    s === 'sent' ||
    s === 'active' ||
    s === 'processed' ||
    s === 'issued'
  ) {
    return (
      <span className="inline-flex items-center gap-1.5 text-xs font-medium text-emerald-700 whitespace-nowrap shrink-0">
        <CheckCircle2 className="w-3.5 h-3.5 shrink-0" />
        <span>{status}</span>
      </span>
    );
  }

  if (
    s.includes('rejected') ||
    s.includes('re-upload') ||
    s.includes('failed') ||
    s.includes('revoked') ||
    s.includes('locked')
  ) {
    return (
      <span className="inline-flex items-center gap-1.5 text-xs font-medium text-red-700 whitespace-nowrap shrink-0">
        <XCircle className="w-3.5 h-3.5 shrink-0" />
        <span>{status}</span>
      </span>
    );
  }

  if (s.includes('action required') || s.includes('smtp_not_configured')) {
    return (
      <span className="inline-flex items-center gap-1.5 text-xs font-medium text-amber-700 whitespace-nowrap shrink-0">
        <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
        <span>{status === 'smtp_not_configured' ? 'SMTP Not Configured' : status}</span>
      </span>
    );
  }

  if (s.includes('uploaded') || s.includes('submitted') || s.includes('offer') || s.includes('sent')) {
    return (
      <span className="inline-flex items-center gap-1.5 text-xs font-medium text-blue-700 whitespace-nowrap shrink-0">
        <Clock className="w-3.5 h-3.5 shrink-0" />
        <span>{status}</span>
      </span>
    );
  }

  if (s.includes('pending')) {
    return (
      <span className="inline-flex items-center gap-1.5 text-xs font-medium text-amber-700 whitespace-nowrap shrink-0">
        <Clock className="w-3.5 h-3.5 shrink-0" />
        <span>{status}</span>
      </span>
    );
  }

  return (
    <span className="inline-flex items-center gap-1.5 text-xs font-medium text-slate-600 whitespace-nowrap shrink-0">
      <ShieldAlert className="w-3.5 h-3.5 shrink-0" />
      <span>{status}</span>
    </span>
  );
}
