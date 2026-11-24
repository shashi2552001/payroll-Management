import type Database from 'better-sqlite3';
import type { NextFunction, Request, Response } from 'express';
import type { AppConfig } from './config.ts';
import { sha256Hex, verifyToken } from './crypto.ts';
import { MANDATORY_2FA_ROLES, type UserRole } from './db.ts';

export const COOKIE_ACCESS = '9hr_access';
export const COOKIE_REFRESH = '9hr_refresh';
export const COOKIE_2FA_CHALLENGE = '9hr_2fa_challenge';
export const COOKIE_STEP_UP = '9hr_step_up';
export const COOKIE_CANDIDATE_SESSION = '9hr_candidate_session';

export interface AuthenticatedUser {
  id: string;
  username: string;
  email: string;
  fullName: string;
  role: UserRole;
  department: string;
  designation: string;
  managerId: string | null;
  totpEnabled: boolean;
  sessionId: string;
  permissions: string[];
  stepUpVerified: boolean;
}

export interface CandidatePortalSession {
  sessionId: string;
  candidateId: string;
  invitationId: string;
  purpose: 'initial_upload' | 'reupload';
  targetDocTypes: string[] | null;
}

declare global {
  namespace Express {
    interface Request {
      authUser?: AuthenticatedUser;
      candidateSession?: CandidatePortalSession;
    }
  }
}

export function isRequestHttps(req: Request): boolean {
  const forwardedProto = req.headers['x-forwarded-proto'];
  if (typeof forwardedProto === 'string') {
    return forwardedProto.split(',')[0].trim() === 'https';
  }
  return req.secure;
}

export function setSecureCookie(
  req: Request,
  res: Response,
  name: string,
  value: string,
  maxAgeMs: number,
): void {
  const https = isRequestHttps(req);
  res.cookie(name, value, {
    httpOnly: true,
    secure: https,
    sameSite: https ? 'none' : 'lax',
    partitioned: https,
    path: '/',
    maxAge: maxAgeMs,
  });
}

export function clearSecureCookie(req: Request, res: Response, name: string): void {
  const https = isRequestHttps(req);
  res.clearCookie(name, {
    httpOnly: true,
    secure: https,
    sameSite: https ? 'none' : 'lax',
    partitioned: https,
    path: '/',
  });
}

export function getClientIp(req: Request): string {
  const fwd = req.headers['x-forwarded-for'];
  if (typeof fwd === 'string' && fwd.length > 0) {
    return fwd.split(',')[0].trim();
  }
  return req.ip || req.socket.remoteAddress || 'unknown';
}

// Sliding window rate limiter
export function createRateLimiter(options: {
  windowMs: number;
  maxRequests: number;
  keyPrefix: string;
}) {
  const buckets = new Map<string, number[]>();

  return (req: Request, res: Response, next: NextFunction) => {
    const now = Date.now();
    const key = `${options.keyPrefix}:${getClientIp(req)}`;
    const timestamps = (buckets.get(key) || []).filter((t) => now - t < options.windowMs);
    if (timestamps.length >= options.maxRequests) {
      res.status(429).json({
        error: 'Too many requests. Please wait before trying again.',
      });
      return;
    }
    timestamps.push(now);
    buckets.set(key, timestamps);
    next();
  };
}

// CSRF protection for cookie-authenticated mutations
export function csrfProtection(req: Request, res: Response, next: NextFunction): void {
  const method = req.method.toUpperCase();
  if (method === 'GET' || method === 'HEAD' || method === 'OPTIONS') {
    next();
    return;
  }

  const origin = req.headers.origin;
  const host = (req.headers['x-forwarded-host'] || req.headers.host || '') as string;
  const requestedWith = req.headers['x-requested-with'];

  // Allow non-browser API clients if they supply the custom header or Bearer token
  if (requestedWith === '9HR-Client' || req.headers.authorization?.startsWith('Bearer ')) {
    next();
    return;
  }

  if (origin && host) {
    try {
      const parsedOrigin = new URL(origin);
      const expectedHost = host.split(',')[0].trim().toLowerCase();
      if (parsedOrigin.host.toLowerCase() === expectedHost) {
        next();
        return;
      }
    } catch {
      // fall through to rejection
    }
  }

  res.status(403).json({
    error: 'CSRF verification failed: invalid origin or missing X-Requested-With header.',
  });
}

export function is2faMandatoryForRole(db: Database.Database, role: UserRole): boolean {
  if (MANDATORY_2FA_ROLES.has(role)) return true;
  const policy = db
    .prepare('SELECT require_2fa_for_employees FROM security_policies WHERE id = 1')
    .get() as { require_2fa_for_employees: number } | undefined;
  return Boolean(policy?.require_2fa_for_employees);
}

export function getRolePermissions(db: Database.Database, role: UserRole): string[] {
  const row = db
    .prepare('SELECT permissions_json FROM role_permissions WHERE role = ?')
    .get(role) as { permissions_json: string } | undefined;
  if (!row) return [];
  try {
    return JSON.parse(row.permissions_json) as string[];
  } catch {
    return [];
  }
}

export function createAuthMiddleware(db: Database.Database, config: AppConfig) {
  const requireAuth = (req: Request, res: Response, next: NextFunction): void => {
    const bearer = req.headers.authorization?.startsWith('Bearer ')
      ? req.headers.authorization.slice(7).trim()
      : null;
    const token = req.cookies?.[COOKIE_ACCESS] || bearer;

    if (!token) {
      res.status(401).json({ error: 'Authentication required.' });
      return;
    }

    const payload = verifyToken(token, config.sessionSecret, 'access');
    if (!payload || !payload.sid) {
      res.status(401).json({ error: 'Invalid or expired session.' });
      return;
    }

    const session = db
      .prepare('SELECT * FROM user_sessions WHERE id = ? AND user_id = ?')
      .get(payload.sid, payload.sub) as
      | {
          id: string;
          user_id: string;
          expires_at: string;
          revoked_at: string | null;
        }
      | undefined;

    if (!session || session.revoked_at || new Date(session.expires_at).getTime() <= Date.now()) {
      res.status(401).json({ error: 'Session has been revoked or expired.' });
      return;
    }

    const user = db
      .prepare('SELECT * FROM users WHERE id = ?')
      .get(payload.sub) as
      | {
          id: string;
          username: string;
          email: string;
          full_name: string;
          role: UserRole;
          department: string;
          designation: string;
          manager_id: string | null;
          totp_enabled: number;
          is_active: number;
        }
      | undefined;

    if (!user || !user.is_active) {
      res.status(401).json({ error: 'Account is inactive or unavailable.' });
      return;
    }

    // Never allow silent bypass of mandatory 2FA
    if (is2faMandatoryForRole(db, user.role) && !user.totp_enabled) {
      res.status(403).json({
        error: 'Two-factor authentication setup is mandatory for your role before accessing workspace resources.',
        code: '2FA_SETUP_REQUIRED',
      });
      return;
    }

    db.prepare('UPDATE user_sessions SET last_active_at = ? WHERE id = ?').run(
      new Date().toISOString(),
      session.id,
    );

    const stepUpCookie = req.cookies?.[COOKIE_STEP_UP];
    const stepUpHeader = req.headers['x-step-up-token'] as string | undefined;
    const stepUpPayload =
      (stepUpCookie && verifyToken(stepUpCookie, config.sessionSecret, 'step_up')) ||
      (stepUpHeader && verifyToken(stepUpHeader, config.sessionSecret, 'step_up'));
    const stepUpVerified = Boolean(
      stepUpPayload && stepUpPayload.sub === user.id && stepUpPayload.sid === session.id,
    );

    req.authUser = {
      id: user.id,
      username: user.username,
      email: user.email,
      fullName: user.full_name,
      role: user.role,
      department: user.department,
      designation: user.designation,
      managerId: user.manager_id,
      totpEnabled: Boolean(user.totp_enabled),
      sessionId: session.id,
      permissions: getRolePermissions(db, user.role),
      stepUpVerified,
    };

    next();
  };

  const requireRole = (...roles: UserRole[]) => {
    const allowed = new Set(roles);
    return (req: Request, res: Response, next: NextFunction): void => {
      if (!req.authUser) {
        res.status(401).json({ error: 'Authentication required.' });
        return;
      }
      if (!allowed.has(req.authUser.role)) {
        res.status(403).json({ error: 'Forbidden: insufficient role privileges.' });
        return;
      }
      next();
    };
  };

  const requirePermission = (permission: string) => {
    return (req: Request, res: Response, next: NextFunction): void => {
      if (!req.authUser) {
        res.status(401).json({ error: 'Authentication required.' });
        return;
      }
      if (req.authUser.role !== 'Admin' && !req.authUser.permissions.includes(permission)) {
        res.status(403).json({ error: `Forbidden: missing permission "${permission}".` });
        return;
      }
      next();
    };
  };

  const requireStepUp = (req: Request, res: Response, next: NextFunction): void => {
    if (!req.authUser) {
      res.status(401).json({ error: 'Authentication required.' });
      return;
    }
    if (!req.authUser.stepUpVerified) {
      res.status(403).json({
        error: 'Re-authentication required for this sensitive security or financial action.',
        code: 'STEP_UP_REQUIRED',
      });
      return;
    }
    next();
  };

  const requireCandidateSession = (req: Request, res: Response, next: NextFunction): void => {
    const rawSessionToken = req.cookies?.[COOKIE_CANDIDATE_SESSION];
    if (!rawSessionToken) {
      res.status(401).json({
        error: 'Candidate upload session missing or expired. Please open your secure invitation link.',
        code: 'CANDIDATE_SESSION_REQUIRED',
      });
      return;
    }

    const tokenHash = sha256Hex(rawSessionToken);
    const row = db
      .prepare(`
        SELECT s.*, i.purpose, i.target_doc_types_json, i.revoked_at AS inv_revoked_at
        FROM candidate_upload_sessions s
        JOIN candidate_invitations i ON i.id = s.invitation_id
        WHERE s.session_token_hash = ?
      `)
      .get(tokenHash) as
      | {
          id: string;
          candidate_id: string;
          invitation_id: string;
          expires_at: string;
          revoked_at: string | null;
          inv_revoked_at: string | null;
          purpose: 'initial_upload' | 'reupload';
          target_doc_types_json: string | null;
        }
      | undefined;

    if (
      !row ||
      row.revoked_at ||
      row.inv_revoked_at ||
      new Date(row.expires_at).getTime() <= Date.now()
    ) {
      res.status(401).json({
        error: 'This candidate upload session is no longer valid or has been revoked.',
        code: 'CANDIDATE_SESSION_INVALID',
      });
      return;
    }

    let targetDocTypes: string[] | null = null;
    if (row.target_doc_types_json) {
      try {
        targetDocTypes = JSON.parse(row.target_doc_types_json) as string[];
      } catch {
        targetDocTypes = null;
      }
    }

    req.candidateSession = {
      sessionId: row.id,
      candidateId: row.candidate_id,
      invitationId: row.invitation_id,
      purpose: row.purpose,
      targetDocTypes,
    };
    next();
  };

  return {
    requireAuth,
    requireRole,
    requirePermission,
    requireStepUp,
    requireCandidateSession,
  };
}
