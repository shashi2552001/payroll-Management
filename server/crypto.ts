import argon2 from 'argon2';
import crypto from 'crypto';
import * as OTPAuth from 'otpauth';
import QRCode from 'qrcode';

export async function hashPassword(password: string): Promise<string> {
  return argon2.hash(password, {
    type: argon2.argon2id,
    memoryCost: 65536,
    timeCost: 3,
    parallelism: 1,
  });
}

export async function verifyPassword(hash: string, password: string): Promise<boolean> {
  if (!hash || !password) return false;
  try {
    return await argon2.verify(hash, password);
  } catch {
    return false;
  }
}

export function sha256Hex(value: string): string {
  return crypto.createHash('sha256').update(value, 'utf8').digest('hex');
}

export function sha256BufferHex(buf: Buffer): string {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

export function generateRandomToken(byteLength = 32): string {
  return crypto.randomBytes(byteLength).toString('base64url');
}

function deriveAesKey(secret: string): Buffer {
  return crypto.createHash('sha256').update(`9hr-aes-key:${secret}`, 'utf8').digest();
}

export function encryptAtRest(plaintext: string, secret: string): string {
  const key = deriveAesKey(secret);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `${iv.toString('base64url')}.${tag.toString('base64url')}.${encrypted.toString('base64url')}`;
}

export function decryptAtRest(ciphertext: string, secret: string): string {
  const parts = ciphertext.split('.');
  if (parts.length !== 3) {
    throw new Error('Invalid encrypted payload format');
  }
  const [ivB64, tagB64, dataB64] = parts;
  const key = deriveAesKey(secret);
  const decipher = crypto.createDecipheriv(
    'aes-256-gcm',
    key,
    Buffer.from(ivB64, 'base64url'),
  );
  decipher.setAuthTag(Buffer.from(tagB64, 'base64url'));
  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(dataB64, 'base64url')),
    decipher.final(),
  ]);
  return decrypted.toString('utf8');
}

export interface SignedTokenPayload {
  sub: string;
  typ: string;
  jti?: string;
  sid?: string;
  role?: string;
  docId?: string;
  exp: number;
  iat: number;
}

export function signToken(
  payload: Omit<SignedTokenPayload, 'iat' | 'exp'>,
  ttlSeconds: number,
  secret: string,
): string {
  const now = Math.floor(Date.now() / 1000);
  const fullPayload: SignedTokenPayload = {
    ...payload,
    iat: now,
    exp: now + ttlSeconds,
  };
  const headerB64 = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const bodyB64 = Buffer.from(JSON.stringify(fullPayload)).toString('base64url');
  const data = `${headerB64}.${bodyB64}`;
  const sig = crypto.createHmac('sha256', secret).update(data).digest('base64url');
  return `${data}.${sig}`;
}

export function verifyToken(token: string, secret: string, expectedType?: string): SignedTokenPayload | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const [headerB64, bodyB64, sigB64] = parts;
    const data = `${headerB64}.${bodyB64}`;
    const expectedSig = crypto.createHmac('sha256', secret).update(data).digest('base64url');
    const a = Buffer.from(sigB64, 'utf8');
    const b = Buffer.from(expectedSig, 'utf8');
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
      return null;
    }
    const payload = JSON.parse(Buffer.from(bodyB64, 'base64url').toString('utf8')) as SignedTokenPayload;
    const now = Math.floor(Date.now() / 1000);
    if (!payload.exp || payload.exp < now) {
      return null;
    }
    if (expectedType && payload.typ !== expectedType) {
      return null;
    }
    return payload;
  } catch {
    return null;
  }
}

export async function generateTotpEnrollment(accountLabel: string): Promise<{
  secretBase32: string;
  otpauthUri: string;
  qrDataUrl: string;
}> {
  const secret = new OTPAuth.Secret({ size: 20 });
  const totp = new OTPAuth.TOTP({
    issuer: '9HR India',
    label: accountLabel,
    algorithm: 'SHA1',
    digits: 6,
    period: 30,
    secret,
  });
  const otpauthUri = totp.toString();
  const qrDataUrl = await QRCode.toDataURL(otpauthUri, {
    width: 240,
    margin: 2,
    color: {
      dark: '#0B131E',
      light: '#FFFFFF',
    },
  });
  return {
    secretBase32: secret.base32,
    otpauthUri,
    qrDataUrl,
  };
}

export function verifyTotpCode(secretBase32: string, code: string): boolean {
  const normalized = code.replace(/\s+/g, '');
  if (!/^\d{6}$/.test(normalized)) return false;
  try {
    const totp = new OTPAuth.TOTP({
      issuer: '9HR India',
      algorithm: 'SHA1',
      digits: 6,
      period: 30,
      secret: OTPAuth.Secret.fromBase32(secretBase32),
    });
    const delta = totp.validate({ token: normalized, window: 1 });
    return delta !== null;
  } catch {
    return false;
  }
}

const RECOVERY_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

export async function generateRecoveryCodes(count = 8): Promise<{
  plaintextCodes: string[];
  hashedCodes: string[];
}> {
  const plaintextCodes: string[] = [];
  const hashedCodes: string[] = [];

  for (let i = 0; i < count; i++) {
    const bytes = crypto.randomBytes(8);
    let raw = '';
    for (let j = 0; j < 8; j++) {
      raw += RECOVERY_ALPHABET[bytes[j] % RECOVERY_ALPHABET.length];
    }
    const formatted = `${raw.slice(0, 4)}-${raw.slice(4, 8)}`;
    plaintextCodes.push(formatted);
    hashedCodes.push(await hashPassword(formatted));
  }

  return { plaintextCodes, hashedCodes };
}

export async function verifyAndConsumeRecoveryCode(
  storedHashes: Array<{ id: string; code_hash: string }>,
  candidateCode: string,
): Promise<string | null> {
  const normalized = candidateCode.trim().toUpperCase();
  for (const row of storedHashes) {
    if (await verifyPassword(row.code_hash, normalized)) {
      return row.id;
    }
  }
  return null;
}

export function maskBankAccount(accountNumber: string): string {
  const clean = accountNumber.replace(/\s+/g, '');
  if (clean.length <= 4) return '****';
  return `${'*'.repeat(Math.max(4, clean.length - 4))}${clean.slice(-4)}`;
}
