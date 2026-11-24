import {
  AlertCircle,
  ArrowLeft,
  Check,
  CheckCircle2,
  Copy,
  Download,
  Eye,
  EyeOff,
  KeyRound,
  Lock,
  Mail,
  QrCode,
  ShieldCheck,
} from 'lucide-react';
import { motion } from 'motion/react';
import React, { useEffect, useState } from 'react';
import { apiFetch, ApiError } from '../lib/api';
import type { AuthUser } from '../types';

type AuthStage =
  | 'login'
  | 'bootstrap'
  | 'forgot'
  | '2fa_setup'
  | '2fa_recovery_ack'
  | '2fa_verify';

interface AuthViewsProps {
  needsBootstrap: boolean;
  envAdminPasswordConfigured: boolean;
  onAuthenticated: (user: AuthUser) => void;
}

export function AuthViews({
  needsBootstrap,
  envAdminPasswordConfigured,
  onAuthenticated,
}: AuthViewsProps) {
  const [stage, setStage] = useState<AuthStage>(needsBootstrap ? 'bootstrap' : 'login');
  const [tilt, setTilt] = useState({ rx: 0, ry: 0 });

  // Bootstrap state
  const [bsFullName, setBsFullName] = useState('');
  const [bsEmail, setBsEmail] = useState('');
  const [bsUsername, setBsUsername] = useState('');
  const [bsPassword, setBsPassword] = useState('');

  // Login state
  const [identifier, setIdentifier] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);

  // Forgot password state
  const [forgotEmail, setForgotEmail] = useState('');
  const [forgotSentMsg, setForgotSentMsg] = useState('');

  // 2FA setup state
  const [qrDataUrl, setQrDataUrl] = useState('');
  const [manualKey, setManualKey] = useState('');
  const [accountEmail, setAccountEmail] = useState('');
  const [setupCode, setSetupCode] = useState('');
  const [recoveryCodes, setRecoveryCodes] = useState<string[]>([]);
  const [recoveryAck, setRecoveryAck] = useState(false);
  const [copiedRecovery, setCopiedRecovery] = useState(false);
  const [pendingUserAfterSetup, setPendingUserAfterSetup] = useState<AuthUser | null>(null);

  // 2FA verify state
  const [verifyCode, setVerifyCode] = useState('');
  const [useRecoveryMode, setUseRecoveryMode] = useState(false);
  const [challengeLabel, setChallengeLabel] = useState('');

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    setStage(needsBootstrap ? 'bootstrap' : 'login');
  }, [needsBootstrap]);

  async function init2faSetup() {
    setError('');
    setLoading(true);
    try {
      const data = await apiFetch<{
        qrDataUrl: string;
        manualKey: string;
        accountEmail: string;
      }>('/api/auth/2fa/setup', { method: 'POST' });
      setQrDataUrl(data.qrDataUrl);
      setManualKey(data.manualKey);
      setAccountEmail(data.accountEmail);
      setStage('2fa_setup');
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Unable to initiate 2FA setup.');
    } finally {
      setLoading(false);
    }
  }

  async function handleBootstrap(e: React.FormEvent) {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      await apiFetch('/api/auth/bootstrap', {
        method: 'POST',
        body: JSON.stringify({
          fullName: bsFullName,
          email: bsEmail,
          username: bsUsername,
          password: envAdminPasswordConfigured ? undefined : bsPassword,
        }),
      });
      await init2faSetup();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to initialize admin account.');
    } finally {
      setLoading(false);
    }
  }

  async function handleLogin(e: React.FormEvent) {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      const res = await apiFetch<{
        status: 'AUTHENTICATED' | '2FA_REQUIRED' | '2FA_SETUP_REQUIRED';
        user?: AuthUser;
        fullName?: string;
      }>('/api/auth/login', {
        method: 'POST',
        body: JSON.stringify({ identifier, password }),
      });

      if (res.status === 'AUTHENTICATED' && res.user) {
        onAuthenticated(res.user);
        return;
      }
      if (res.status === '2FA_SETUP_REQUIRED') {
        setChallengeLabel(res.fullName || '');
        await init2faSetup();
        return;
      }
      if (res.status === '2FA_REQUIRED') {
        setChallengeLabel(res.fullName || '');
        setVerifyCode('');
        setUseRecoveryMode(false);
        setStage('2fa_verify');
      }
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Sign-in failed.');
    } finally {
      setLoading(false);
    }
  }

  async function handleVerify2faSetup(e: React.FormEvent) {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      const res = await apiFetch<{
        status: string;
        recoveryCodes: string[];
        user: AuthUser;
      }>('/api/auth/2fa/verify-setup', {
        method: 'POST',
        body: JSON.stringify({ code: setupCode }),
      });
      setRecoveryCodes(res.recoveryCodes);
      setPendingUserAfterSetup(res.user);
      setStage('2fa_recovery_ack');
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Invalid authenticator code.');
    } finally {
      setLoading(false);
    }
  }

  async function handleVerify2faLogin(e: React.FormEvent) {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      const res = await apiFetch<{ user: AuthUser }>('/api/auth/2fa/verify', {
        method: 'POST',
        body: JSON.stringify({
          code: verifyCode,
          isRecoveryCode: useRecoveryMode,
        }),
      });
      onAuthenticated(res.user);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Verification failed.');
    } finally {
      setLoading(false);
    }
  }

  async function handleForgotPassword(e: React.FormEvent) {
    e.preventDefault();
    setError('');
    setForgotSentMsg('');
    setLoading(true);
    try {
      const res = await apiFetch<{ message: string }>('/api/auth/forgot-password', {
        method: 'POST',
        body: JSON.stringify({ email: forgotEmail }),
      });
      setForgotSentMsg(res.message);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Unable to process request.');
    } finally {
      setLoading(false);
    }
  }

  function downloadRecoveryCodes() {
    const content = [
      '9HR India — Two-Factor Authentication Backup Recovery Codes',
      `Account: ${accountEmail}`,
      `Generated: ${new Date().toUTCString()}`,
      '',
      'Store these single-use recovery codes in a secure password manager.',
      'Each code can be used once if your authenticator device is unavailable.',
      '',
      ...recoveryCodes.map((c, idx) => `${String(idx + 1).padStart(2, '0')}. ${c}`),
    ].join('\n');

    const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = '9hr-india-recovery-codes.txt';
    a.click();
    URL.revokeObjectURL(url);
  }

  function handlePointerMove(e: React.PointerEvent<HTMLDivElement>) {
    const rect = e.currentTarget.getBoundingClientRect();
    const x = (e.clientX - rect.left) / rect.width - 0.5;
    const y = (e.clientY - rect.top) / rect.height - 0.5;
    setTilt({ rx: -y * 3.5, ry: x * 3.5 });
  }

  return (
    <div className="min-h-screen bg-slate-50 flex flex-col lg:flex-row">
      {/* Left Architectural Brand Panel */}
      <div className="lg:w-[46%] bg-[#0B131E] text-white p-8 lg:p-14 flex flex-col justify-between relative overflow-hidden">
        <div
          className="absolute inset-0 pointer-events-none opacity-25"
          style={{
            backgroundImage:
              'radial-gradient(circle at 20% 20%, rgba(13, 110, 253, 0.35), transparent 55%), radial-gradient(circle at 80% 85%, rgba(11, 138, 62, 0.25), transparent 50%)',
          }}
        />
        <div className="relative z-10 flex items-center gap-4">
          <img
            src="/assets/aistudio/image_0ecd2493.png"
            alt="9HR India — Your Trusted HR Partner"
            className="w-14 h-14 rounded-full bg-white p-0.5 object-contain shadow-md"
          />
          <div>
            <div className="font-display text-xl font-bold tracking-tight text-white">
              9HR India
            </div>
            <div className="text-xs text-slate-400">Your Trusted HR Partner</div>
          </div>
        </div>

        <div className="relative z-10 my-12 lg:my-0 max-w-md space-y-6">
          <h1 className="font-display text-3xl lg:text-4xl font-bold tracking-tight leading-tight text-white">
            Enterprise HR Operations &amp; Verified Onboarding
          </h1>
          <p className="text-slate-300 text-sm lg:text-base leading-relaxed">
            Role-based access control, mandatory authenticator two-factor security, statutory payroll compliance, and tamper-evident candidate document verification.
          </p>

          <div className="pt-4 border-t border-slate-800/80 grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs text-slate-300">
            <div>
              <div className="font-semibold text-white">Argon2id &amp; TOTP 2FA</div>
              <div className="text-slate-400 mt-0.5">Mandatory for Admin, HR, Accounts &amp; Managers</div>
            </div>
            <div>
              <div className="font-semibold text-white">Private Document Vault</div>
              <div className="text-slate-400 mt-0.5">Magic-byte validation, malware scan &amp; signed links</div>
            </div>
          </div>
        </div>

        <div className="relative z-10 text-xs text-slate-400 flex items-center gap-2">
          <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0" />
          <span>Protected by HTTP-only session cookies, refresh rotation &amp; immutable audit logging</span>
        </div>
      </div>

      {/* Right Interactive 3D Auth Vault */}
      <div className="flex-1 flex items-center justify-center p-6 sm:p-10 spatial-stage">
        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.25, ease: [0.16, 1, 0.3, 1] }}
          onPointerMove={handlePointerMove}
          onPointerLeave={() => setTilt({ rx: 0, ry: 0 })}
          style={{
            transform: `rotateX(${tilt.rx}deg) rotateY(${tilt.ry}deg)`,
          }}
          className="w-full max-w-md bg-white border border-slate-200 rounded-2xl p-8 spatial-card"
        >
          {error && (
            <div
              role="alert"
              className="mb-5 flex items-start gap-2.5 p-3.5 rounded-xl bg-red-50 border border-red-200 text-red-800 text-sm"
            >
              <AlertCircle className="w-4 h-4 mt-0.5 shrink-0 text-red-600" />
              <span>{error}</span>
            </div>
          )}

          {stage === 'bootstrap' && (
            <form onSubmit={handleBootstrap} className="space-y-4">
              <div>
                <div className="text-xs font-medium text-blue-700">Initial Workspace Setup</div>
                <h2 className="font-display text-2xl font-bold text-slate-900 mt-1">
                  Claim Primary Admin Account
                </h2>
                <p className="text-sm text-slate-500 mt-1">
                  Configure the first 9HR India administrator. Two-factor authentication will be enrolled immediately afterward.
                </p>
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-700 mb-1.5">Full Name</label>
                <input
                  type="text"
                  required
                  value={bsFullName}
                  onChange={(e) => setBsFullName(e.target.value)}
                  placeholder="e.g., Ananya Sharma"
                  className="w-full px-3.5 py-2.5 text-sm border border-slate-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-600/20 focus:border-blue-600"
                />
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-medium text-slate-700 mb-1.5">Work Email</label>
                  <input
                    type="email"
                    required
                    value={bsEmail}
                    onChange={(e) => setBsEmail(e.target.value)}
                    placeholder="admin@9hrindia.com"
                    className="w-full px-3.5 py-2.5 text-sm border border-slate-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-600/20 focus:border-blue-600"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-slate-700 mb-1.5">Username</label>
                  <input
                    type="text"
                    required
                    value={bsUsername}
                    onChange={(e) => setBsUsername(e.target.value)}
                    placeholder="ananya.admin"
                    className="w-full px-3.5 py-2.5 text-sm border border-slate-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-600/20 focus:border-blue-600"
                  />
                </div>
              </div>

              {!envAdminPasswordConfigured && (
                <div>
                  <label className="block text-xs font-medium text-slate-700 mb-1.5">
                    Admin Password (min 10 characters)
                  </label>
                  <input
                    type="password"
                    required
                    minLength={10}
                    value={bsPassword}
                    onChange={(e) => setBsPassword(e.target.value)}
                    placeholder="Create a strong passphrase"
                    className="w-full px-3.5 py-2.5 text-sm border border-slate-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-600/20 focus:border-blue-600"
                  />
                </div>
              )}

              <button
                type="submit"
                disabled={loading}
                className="w-full py-2.5 px-4 bg-blue-700 hover:bg-blue-800 text-white text-sm font-semibold rounded-lg tactile-btn disabled:opacity-60"
              >
                {loading ? 'Provisioning Admin...' : 'Create Admin & Continue to 2FA'}
              </button>
            </form>
          )}

          {stage === 'login' && (
            <form onSubmit={handleLogin} className="space-y-4">
              <div>
                <h2 className="font-display text-2xl font-bold text-slate-900">
                  Sign in to 9HR India
                </h2>
                <p className="text-sm text-slate-500 mt-1">
                  Enter your internal work email or username and password.
                </p>
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-700 mb-1.5">
                  Email or Username
                </label>
                <div className="relative">
                  <Mail className="w-4 h-4 text-slate-400 absolute left-3.5 top-3" />
                  <input
                    type="text"
                    required
                    autoComplete="username"
                    value={identifier}
                    onChange={(e) => setIdentifier(e.target.value)}
                    placeholder="name@9hrindia.com"
                    className="w-full pl-10 pr-3.5 py-2.5 text-sm border border-slate-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-600/20 focus:border-blue-600"
                  />
                </div>
              </div>

              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <label className="text-xs font-medium text-slate-700">Password</label>
                  <button
                    type="button"
                    onClick={() => {
                      setError('');
                      setForgotSentMsg('');
                      setStage('forgot');
                    }}
                    className="text-xs font-medium text-blue-700 hover:underline"
                  >
                    Forgot password?
                  </button>
                </div>
                <div className="relative">
                  <Lock className="w-4 h-4 text-slate-400 absolute left-3.5 top-3" />
                  <input
                    type={showPassword ? 'text' : 'password'}
                    required
                    autoComplete="current-password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="Enter your password"
                    className="w-full pl-10 pr-10 py-2.5 text-sm border border-slate-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-600/20 focus:border-blue-600"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword((v) => !v)}
                    aria-label={showPassword ? 'Hide password' : 'Show password'}
                    className="absolute right-3 top-2.5 text-slate-400 hover:text-slate-700"
                  >
                    {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
              </div>

              <button
                type="submit"
                disabled={loading}
                className="w-full py-2.5 px-4 bg-blue-700 hover:bg-blue-800 text-white text-sm font-semibold rounded-lg tactile-btn disabled:opacity-60"
              >
                {loading ? 'Verifying Credentials...' : 'Sign In'}
              </button>
            </form>
          )}

          {stage === 'forgot' && (
            <form onSubmit={handleForgotPassword} className="space-y-4">
              <button
                type="button"
                onClick={() => {
                  setError('');
                  setStage('login');
                }}
                className="inline-flex items-center gap-1.5 text-xs font-medium text-slate-600 hover:text-slate-900"
              >
                <ArrowLeft className="w-3.5 h-3.5" />
                <span>Back to Sign In</span>
              </button>

              <div>
                <h2 className="font-display text-2xl font-bold text-slate-900">
                  Reset Your Password
                </h2>
                <p className="text-sm text-slate-500 mt-1">
                  Enter your registered work email. A time-limited reset link will be sent via SMTP.
                </p>
              </div>

              {forgotSentMsg && (
                <div className="p-3.5 rounded-xl bg-emerald-50 border border-emerald-200 text-emerald-800 text-sm flex items-start gap-2">
                  <CheckCircle2 className="w-4 h-4 mt-0.5 shrink-0" />
                  <span>{forgotSentMsg}</span>
                </div>
              )}

              <div>
                <label className="block text-xs font-medium text-slate-700 mb-1.5">Work Email</label>
                <input
                  type="email"
                  required
                  value={forgotEmail}
                  onChange={(e) => setForgotEmail(e.target.value)}
                  placeholder="name@9hrindia.com"
                  className="w-full px-3.5 py-2.5 text-sm border border-slate-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-600/20 focus:border-blue-600"
                />
              </div>

              <button
                type="submit"
                disabled={loading}
                className="w-full py-2.5 px-4 bg-blue-700 hover:bg-blue-800 text-white text-sm font-semibold rounded-lg tactile-btn disabled:opacity-60"
              >
                {loading ? 'Sending...' : 'Send Reset Link'}
              </button>
            </form>
          )}

          {stage === '2fa_setup' && (
            <form onSubmit={handleVerify2faSetup} className="space-y-4">
              <div className="flex items-center gap-2 text-xs font-medium text-blue-700">
                <QrCode className="w-4 h-4" />
                <span>Mandatory Two-Factor Enrollment</span>
              </div>
              <div>
                <h2 className="font-display text-xl font-bold text-slate-900">
                  Link Authenticator App
                </h2>
                <p className="text-sm text-slate-500 mt-1">
                  {challengeLabel ? `${challengeLabel}, scan` : 'Scan'} this QR code in Google Authenticator, Microsoft Authenticator, or 1Password.
                </p>
              </div>

              {qrDataUrl && (
                <div className="flex flex-col items-center p-4 bg-slate-50 border border-slate-200 rounded-xl">
                  <img src={qrDataUrl} alt="TOTP 2FA QR Code" className="w-44 h-44 rounded-lg bg-white p-1" />
                  <div className="mt-3 text-center">
                    <div className="text-xs text-slate-500">Manual setup key</div>
                    <div className="font-mono-tabular text-xs font-semibold text-slate-900 mt-0.5 select-all break-all">
                      {manualKey}
                    </div>
                  </div>
                </div>
              )}

              <div>
                <label className="block text-xs font-medium text-slate-700 mb-1.5">
                  Enter 6-Digit Verification Code
                </label>
                <input
                  type="text"
                  inputMode="numeric"
                  pattern="\d{6}"
                  maxLength={6}
                  required
                  value={setupCode}
                  onChange={(e) => setSetupCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                  placeholder="000000"
                  className="w-full px-3.5 py-2.5 text-center text-lg font-mono-tabular tracking-[0.35em] border border-slate-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-600/20 focus:border-blue-600"
                />
              </div>

              <button
                type="submit"
                disabled={loading || setupCode.length !== 6}
                className="w-full py-2.5 px-4 bg-blue-700 hover:bg-blue-800 text-white text-sm font-semibold rounded-lg tactile-btn disabled:opacity-60"
              >
                {loading ? 'Verifying...' : 'Verify & Generate Recovery Codes'}
              </button>
            </form>
          )}

          {stage === '2fa_recovery_ack' && (
            <div className="space-y-4">
              <div>
                <div className="text-xs font-medium text-emerald-700">2FA Enabled Successfully</div>
                <h2 className="font-display text-xl font-bold text-slate-900 mt-1">
                  Save Backup Recovery Codes
                </h2>
                <p className="text-sm text-slate-500 mt-1">
                  These single-use codes are shown only once. Store them safely in case you lose your authenticator device.
                </p>
              </div>

              <div className="grid grid-cols-2 gap-2 p-3.5 bg-slate-50 border border-slate-200 rounded-xl font-mono-tabular text-xs text-slate-900">
                {recoveryCodes.map((c) => (
                  <div key={c} className="px-2.5 py-1.5 bg-white border border-slate-200 rounded text-center font-semibold">
                    {c}
                  </div>
                ))}
              </div>

              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={downloadRecoveryCodes}
                  className="flex-1 inline-flex items-center justify-center gap-1.5 py-2 px-3 text-xs font-medium text-slate-700 bg-slate-100 hover:bg-slate-200 rounded-lg"
                >
                  <Download className="w-3.5 h-3.5" />
                  <span>Download (.txt)</span>
                </button>
                <button
                  type="button"
                  onClick={() => {
                    navigator.clipboard.writeText(recoveryCodes.join('\n'));
                    setCopiedRecovery(true);
                    setTimeout(() => setCopiedRecovery(false), 2000);
                  }}
                  className="flex-1 inline-flex items-center justify-center gap-1.5 py-2 px-3 text-xs font-medium text-slate-700 bg-slate-100 hover:bg-slate-200 rounded-lg"
                >
                  {copiedRecovery ? <Check className="w-3.5 h-3.5 text-emerald-700" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copiedRecovery ? 'Copied' : 'Copy All'}</span>
                </button>
              </div>

              <label className="flex items-start gap-2.5 text-xs text-slate-700 cursor-pointer">
                <input
                  type="checkbox"
                  checked={recoveryAck}
                  onChange={(e) => setRecoveryAck(e.target.checked)}
                  className="mt-0.5 rounded border-slate-300"
                />
                <span>I have securely stored these backup recovery codes.</span>
              </label>

              <button
                type="button"
                disabled={!recoveryAck || !pendingUserAfterSetup}
                onClick={() => {
                  if (pendingUserAfterSetup) onAuthenticated(pendingUserAfterSetup);
                }}
                className="w-full py-2.5 px-4 bg-blue-700 hover:bg-blue-800 text-white text-sm font-semibold rounded-lg tactile-btn disabled:opacity-50"
              >
                Enter 9HR India Workspace
              </button>
            </div>
          )}

          {stage === '2fa_verify' && (
            <form onSubmit={handleVerify2faLogin} className="space-y-4">
              <div className="flex items-center gap-2 text-xs font-medium text-blue-700">
                <KeyRound className="w-4 h-4" />
                <span>Two-Factor Verification</span>
              </div>
              <div>
                <h2 className="font-display text-xl font-bold text-slate-900">
                  Confirm Your Identity
                </h2>
                <p className="text-sm text-slate-500 mt-1">
                  {challengeLabel ? `Welcome back, ${challengeLabel}. ` : ''}
                  {useRecoveryMode
                    ? 'Enter one of your unused backup recovery codes (XXXX-YYYY).'
                    : 'Enter the 6-digit code from your authenticator app.'}
                </p>
              </div>

              <div>
                <input
                  type="text"
                  required
                  value={verifyCode}
                  onChange={(e) =>
                    setVerifyCode(
                      useRecoveryMode
                        ? e.target.value.toUpperCase().slice(0, 12)
                        : e.target.value.replace(/\D/g, '').slice(0, 6),
                    )
                  }
                  placeholder={useRecoveryMode ? 'XXXX-YYYY' : '000000'}
                  className="w-full px-3.5 py-2.5 text-center text-lg font-mono-tabular tracking-[0.25em] border border-slate-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-600/20 focus:border-blue-600"
                />
              </div>

              <button
                type="submit"
                disabled={loading}
                className="w-full py-2.5 px-4 bg-blue-700 hover:bg-blue-800 text-white text-sm font-semibold rounded-lg tactile-btn disabled:opacity-60"
              >
                {loading ? 'Verifying...' : 'Verify & Sign In'}
              </button>

              <div className="flex items-center justify-between pt-1 text-xs">
                <button
                  type="button"
                  onClick={() => {
                    setError('');
                    setVerifyCode('');
                    setUseRecoveryMode((v) => !v);
                  }}
                  className="text-blue-700 hover:underline font-medium"
                >
                  {useRecoveryMode ? 'Use authenticator app instead' : 'Use a backup recovery code'}
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setError('');
                    setStage('login');
                  }}
                  className="text-slate-500 hover:text-slate-900"
                >
                  Cancel
                </button>
              </div>
            </form>
          )}
        </motion.div>
      </div>
    </div>
  );
}

export function ResetPasswordView({ onDone }: { onDone: () => void }) {
  const params = new URLSearchParams(window.location.search);
  const token = params.get('token') || '';
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError('');
    if (newPassword !== confirmPassword) {
      setError('Passwords do not match.');
      return;
    }
    setLoading(true);
    try {
      const res = await apiFetch<{ message: string }>('/api/auth/reset-password', {
        method: 'POST',
        body: JSON.stringify({ token, newPassword }),
      });
      setMessage(res.message);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Unable to reset password.');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen bg-slate-50 flex items-center justify-center p-6">
      <div className="w-full max-w-md bg-white border border-slate-200 rounded-2xl p-8 spatial-card">
        <div className="flex items-center gap-3 mb-6">
          <img
            src="/assets/aistudio/image_0ecd2493.png"
            alt="9HR India"
            className="w-10 h-10 rounded-full object-contain"
          />
          <div>
            <div className="font-display font-bold text-slate-900">9HR India</div>
            <div className="text-xs text-slate-500">Account Password Reset</div>
          </div>
        </div>

        {error && (
          <div className="mb-4 p-3 rounded-lg bg-red-50 border border-red-200 text-red-800 text-sm">
            {error}
          </div>
        )}

        {message ? (
          <div className="space-y-4">
            <div className="p-4 rounded-xl bg-emerald-50 border border-emerald-200 text-emerald-900 text-sm">
              {message}
            </div>
            <button
              type="button"
              onClick={onDone}
              className="w-full py-2.5 px-4 bg-blue-700 hover:bg-blue-800 text-white text-sm font-semibold rounded-lg"
            >
              Proceed to Login
            </button>
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-xs font-medium text-slate-700 mb-1.5">
                New Password (min 10 characters)
              </label>
              <input
                type="password"
                required
                minLength={10}
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                className="w-full px-3.5 py-2.5 text-sm border border-slate-300 rounded-lg"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-slate-700 mb-1.5">
                Confirm New Password
              </label>
              <input
                type="password"
                required
                minLength={10}
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                className="w-full px-3.5 py-2.5 text-sm border border-slate-300 rounded-lg"
              />
            </div>
            <button
              type="submit"
              disabled={loading || !token}
              className="w-full py-2.5 px-4 bg-blue-700 hover:bg-blue-800 text-white text-sm font-semibold rounded-lg disabled:opacity-60"
            >
              {loading ? 'Updating Password...' : 'Update Password'}
            </button>
          </form>
        )}
      </div>
    </div>
  );
}
