import crypto from 'crypto';
import fs from 'fs';
import net from 'net';
import path from 'path';
import type { AppConfig } from './config.ts';

export interface FileScanResult {
  safe: boolean;
  detectedType: 'pdf' | 'jpg' | 'png' | 'unknown';
  detectedMime: string;
  reason?: string;
  scanner: string;
}

const ALLOWED_EXTENSIONS = new Set(['.pdf', '.jpg', '.jpeg', '.png']);
const ALLOWED_MIMES = new Set(['application/pdf', 'image/jpeg', 'image/png']);

function detectMagicType(buffer: Buffer): 'pdf' | 'jpg' | 'png' | 'executable' | 'archive' | 'unknown' {
  if (buffer.length < 8) return 'unknown';

  // PE/MZ executable, ELF binary, Mach-O, shebang script
  if (buffer[0] === 0x4d && buffer[1] === 0x5a) return 'executable'; // MZ
  if (buffer[0] === 0x7f && buffer[1] === 0x45 && buffer[2] === 0x4c && buffer[3] === 0x46) {
    return 'executable'; // ELF
  }
  if (buffer[0] === 0x23 && buffer[1] === 0x21) return 'executable'; // #!
  if (
    (buffer[0] === 0xfe && buffer[1] === 0xed && buffer[2] === 0xfa && (buffer[3] === 0xce || buffer[3] === 0xcf)) ||
    (buffer[0] === 0xcf && buffer[1] === 0xfa && buffer[2] === 0xed && buffer[3] === 0xfe)
  ) {
    return 'executable';
  }
  if (buffer[0] === 0x50 && buffer[1] === 0x4b && buffer[2] === 0x03 && buffer[3] === 0x04) {
    return 'archive'; // ZIP / JAR / DOCX / APK
  }

  // PDF: %PDF-
  if (buffer.subarray(0, 5).toString('ascii') === '%PDF-') {
    return 'pdf';
  }

  // JPEG: FF D8 FF
  if (buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff) {
    return 'jpg';
  }

  // PNG: 89 50 4E 47 0D 0A 1A 0A
  if (
    buffer[0] === 0x89 &&
    buffer[1] === 0x50 &&
    buffer[2] === 0x4e &&
    buffer[3] === 0x47 &&
    buffer[4] === 0x0d &&
    buffer[5] === 0x0a &&
    buffer[6] === 0x1a &&
    buffer[7] === 0x0a
  ) {
    return 'png';
  }

  return 'unknown';
}

async function scanWithClamAv(
  buffer: Buffer,
  host: string,
  port: number,
): Promise<{ clean: boolean; detail: string } | null> {
  if (!host) return null;

  return new Promise((resolve) => {
    const socket = new net.Socket();
    let response = '';
    let settled = false;

    const finish = (result: { clean: boolean; detail: string } | null) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(result);
    };

    socket.setTimeout(5000);
    socket.on('timeout', () => finish(null));
    socket.on('error', () => finish(null));
    socket.on('data', (chunk) => {
      response += chunk.toString('utf8');
    });
    socket.on('end', () => {
      if (response.includes('OK') && !response.includes('FOUND')) {
        finish({ clean: true, detail: 'ClamAV: clean' });
      } else if (response.includes('FOUND')) {
        finish({ clean: false, detail: `ClamAV threat detected: ${response.trim()}` });
      } else {
        finish(null);
      }
    });

    socket.connect(port, host, () => {
      socket.write('zINSTREAM\0');
      const chunkSize = 16384;
      for (let offset = 0; offset < buffer.length; offset += chunkSize) {
        const slice = buffer.subarray(offset, Math.min(offset + chunkSize, buffer.length));
        const lenBuf = Buffer.alloc(4);
        lenBuf.writeUInt32BE(slice.length, 0);
        socket.write(lenBuf);
        socket.write(slice);
      }
      const zeroBuf = Buffer.alloc(4, 0);
      socket.write(zeroBuf);
    });
  });
}

export async function validateAndScanUpload(
  file: { originalname: string; mimetype: string; buffer: Buffer; size: number },
  maxSizeMb: number,
  config: AppConfig,
): Promise<FileScanResult> {
  const maxBytes = maxSizeMb * 1024 * 1024;
  if (!file || !file.buffer || file.size <= 0) {
    return {
      safe: false,
      detectedType: 'unknown',
      detectedMime: '',
      reason: 'Empty file upload is not permitted.',
      scanner: 'builtin-inspector',
    };
  }

  if (file.size > maxBytes) {
    return {
      safe: false,
      detectedType: 'unknown',
      detectedMime: file.mimetype,
      reason: `File exceeds maximum allowed size of ${maxSizeMb} MB.`,
      scanner: 'builtin-inspector',
    };
  }

  const ext = path.extname(file.originalname || '').toLowerCase();
  if (!ALLOWED_EXTENSIONS.has(ext)) {
    return {
      safe: false,
      detectedType: 'unknown',
      detectedMime: file.mimetype,
      reason: `Unsupported file extension "${ext}". Only PDF, JPG, and PNG files are allowed.`,
      scanner: 'builtin-inspector',
    };
  }

  if (!ALLOWED_MIMES.has((file.mimetype || '').toLowerCase())) {
    return {
      safe: false,
      detectedType: 'unknown',
      detectedMime: file.mimetype,
      reason: `Unsupported MIME type "${file.mimetype}".`,
      scanner: 'builtin-inspector',
    };
  }

  const magic = detectMagicType(file.buffer);
  if (magic === 'executable' || magic === 'archive' || magic === 'unknown') {
    return {
      safe: false,
      detectedType: 'unknown',
      detectedMime: file.mimetype,
      reason:
        magic === 'executable'
          ? 'Executable or script binary signature detected and blocked.'
          : 'File content signature does not match a valid PDF, JPG, or PNG document.',
      scanner: 'builtin-magic-scanner',
    };
  }

  const extMatchesMagic =
    (magic === 'pdf' && ext === '.pdf') ||
    (magic === 'jpg' && (ext === '.jpg' || ext === '.jpeg')) ||
    (magic === 'png' && ext === '.png');

  if (!extMatchesMagic) {
    return {
      safe: false,
      detectedType: 'unknown',
      detectedMime: file.mimetype,
      reason: 'File extension does not match actual file binary signature.',
      scanner: 'builtin-magic-scanner',
    };
  }

  // Deep heuristic malware / exploit payload check
  const sampleText = file.buffer.toString('latin1');
  if (magic === 'pdf') {
    const dangerousPdfMarkers = [
      /\/JavaScript\b/i,
      /\/JS\b/i,
      /\/Launch\b/i,
      /\/EmbeddedFile\b/i,
      /\/OpenAction\b/i,
      /\/AA\b/i,
      /\/RichMedia\b/i,
      /\/XFA\b/i,
    ];
    for (const marker of dangerousPdfMarkers) {
      if (marker.test(sampleText)) {
        return {
          safe: false,
          detectedType: 'pdf',
          detectedMime: 'application/pdf',
          reason: `Potentially unsafe active content (${marker.source}) detected inside PDF.`,
          scanner: 'builtin-pdf-sanitizer',
        };
      }
    }
    if (!sampleText.includes('%%EOF')) {
      return {
        safe: false,
        detectedType: 'pdf',
        detectedMime: 'application/pdf',
        reason: 'Malformed or truncated PDF document (missing %%EOF trailer).',
        scanner: 'builtin-pdf-sanitizer',
      };
    }
  } else {
    // Reject polyglot HTML/PHP/script payloads embedded inside images
    const polyglotMarkers = [/<script[\s>]/i, /<\?php/i, /javascript:/i, /onerror\s*=/i];
    for (const marker of polyglotMarkers) {
      if (marker.test(sampleText)) {
        return {
          safe: false,
          detectedType: magic,
          detectedMime: magic === 'jpg' ? 'image/jpeg' : 'image/png',
          reason: 'Suspicious embedded script payload detected in image file.',
          scanner: 'builtin-polyglot-scanner',
        };
      }
    }
  }

  // EICAR test signature check (industry standard malware test string)
  if (sampleText.includes('X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*')) {
    return {
      safe: false,
      detectedType: magic,
      detectedMime: file.mimetype,
      reason: 'Malware signature (EICAR test pattern) detected and quarantined.',
      scanner: 'builtin-signature-scanner',
    };
  }

  const clamResult = await scanWithClamAv(
    file.buffer,
    config.clamav.host,
    config.clamav.port,
  );
  if (clamResult && !clamResult.clean) {
    return {
      safe: false,
      detectedType: magic,
      detectedMime: file.mimetype,
      reason: clamResult.detail,
      scanner: 'clamav',
    };
  }

  return {
    safe: true,
    detectedType: magic,
    detectedMime:
      magic === 'pdf' ? 'application/pdf' : magic === 'jpg' ? 'image/jpeg' : 'image/png',
    scanner: clamResult ? 'clamav+builtin' : 'builtin-heuristic-scanner',
  };
}

export function getPrivateDocumentsDir(config: AppConfig): string {
  const dir = path.resolve(config.privateStorageDir, 'candidate_documents');
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  }
  return dir;
}

export function savePrivateDocument(
  config: AppConfig,
  buffer: Buffer,
  ext: string,
): { storedFilename: string; fullPath: string } {
  const baseDir = getPrivateDocumentsDir(config);
  const safeExt = ext.replace(/[^a-z0-9]/gi, '').toLowerCase() || 'bin';
  const storedFilename = `${crypto.randomUUID()}.${safeExt}`;
  const fullPath = path.resolve(baseDir, storedFilename);
  if (!fullPath.startsWith(baseDir + path.sep)) {
    throw new Error('Invalid private storage path resolution');
  }
  fs.writeFileSync(fullPath, buffer, { mode: 0o600 });
  return { storedFilename, fullPath };
}

export function resolvePrivateDocumentPath(config: AppConfig, storedFilename: string): string {
  const baseDir = getPrivateDocumentsDir(config);
  const safeName = path.basename(storedFilename);
  const fullPath = path.resolve(baseDir, safeName);
  if (!fullPath.startsWith(baseDir + path.sep)) {
    throw new Error('Path traversal attempt blocked');
  }
  return fullPath;
}
