import crypto from 'crypto';
import path from 'path';

export interface AppConfig {
  port: number;
  nodeEnv: string;
  appUrl: string;
  sessionSecret: string;
  dbPath: string;
  privateStorageDir: string;
  supportEmail: string;
  defaultCandidateLinkExpiryHours: number;
  defaultMaxUploadSizeMb: number;
  smtp: {
    host: string;
    port: number;
    secure: boolean;
    user: string;
    pass: string;
    from: string;
  };
  clamav: {
    host: string;
    port: number;
  };
  adminBootstrapPassword: string;
}

const EPHEMERAL_FALLBACK_SECRET = crypto.randomBytes(32).toString('hex');

export function loadConfig(overrides: Partial<AppConfig> = {}): AppConfig {
  const rootDir = process.cwd();
  const dbPath =
    overrides.dbPath ||
    process.env.DB_PATH ||
    path.resolve(rootDir, 'data', '9hr_india.db');

  const privateStorageDir =
    overrides.privateStorageDir ||
    process.env.PRIVATE_STORAGE_DIR ||
    path.resolve(rootDir, 'private_storage');

  return {
    port: Number(process.env.PORT || 3000),
    nodeEnv: process.env.NODE_ENV || 'development',
    appUrl: (overrides.appUrl || process.env.APP_URL || 'http://localhost:3000').replace(/\/+$/, ''),
    sessionSecret:
      overrides.sessionSecret ||
      process.env.SESSION_SECRET ||
      EPHEMERAL_FALLBACK_SECRET,
    dbPath,
    privateStorageDir,
    supportEmail: process.env.SUPPORT_EMAIL || 'hr-support@9hrindia.com',
    defaultCandidateLinkExpiryHours: Number(process.env.CANDIDATE_LINK_EXPIRY_HOURS || 72),
    defaultMaxUploadSizeMb: Number(process.env.MAX_UPLOAD_SIZE_MB || 5),
    smtp: {
      host: overrides.smtp?.host ?? (process.env.SMTP_HOST || ''),
      port: overrides.smtp?.port ?? Number(process.env.SMTP_PORT || 587),
      secure: overrides.smtp?.secure ?? (process.env.SMTP_SECURE === 'true'),
      user: overrides.smtp?.user ?? (process.env.SMTP_USER || ''),
      pass: overrides.smtp?.pass ?? (process.env.SMTP_PASS || ''),
      from: overrides.smtp?.from ?? (process.env.SMTP_FROM || '9HR India HR <hr@9hrindia.com>'),
    },
    clamav: {
      host: process.env.CLAMAV_HOST || '',
      port: Number(process.env.CLAMAV_PORT || 3310),
    },
    adminBootstrapPassword: process.env.ADMIN_BOOTSTRAP_PASSWORD || '',
    ...overrides,
  };
}
