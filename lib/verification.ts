import { createHash } from 'crypto';

// ─── Types ───────────────────────────────────────────────────────────────────

export interface VerificationPayload {
  productId: string;
  batchId?: string;
  timestamp: number;
  metadata?: Record<string, unknown>;
}

export interface VerificationResult {
  valid: boolean;
  hash: string;
  productId: string;
  timestamp: number;
  message: string;
}

export interface QRVerificationRecord {
  id: string;
  hash: string;
  productId: string;
  batchId?: string;
  issuedAt: Date;
  expiresAt?: Date;
  scanCount: number;
  revoked: boolean;
}

// ─── Constants ───────────────────────────────────────────────────────────────

const HASH_ALGORITHM = 'sha256';
const VERIFICATION_SECRET = process.env.VERIFICATION_SECRET ?? 'authichain-unified';
const DEFAULT_TTL_MS = 1000 * 60 * 60 * 24 * 365; // 1 year

// ─── Core Utilities ──────────────────────────────────────────────────────────

/**
 * Generate a deterministic verification hash for a product payload.
 */
export function generateVerificationHash(payload: VerificationPayload): string {
  const raw = JSON.stringify({
    productId: payload.productId,
    batchId: payload.batchId ?? '',
    timestamp: payload.timestamp,
    secret: VERIFICATION_SECRET,
  });
  return createHash(HASH_ALGORITHM).update(raw).digest('hex');
}

/**
 * Create a full QR verification record ready for storage.
 */
export function createVerificationRecord(
  payload: VerificationPayload,
  ttlMs: number = DEFAULT_TTL_MS
): QRVerificationRecord {
  const hash = generateVerificationHash(payload);
  const issuedAt = new Date(payload.timestamp);
  const expiresAt = new Date(payload.timestamp + ttlMs);

  return {
    id: `vrf_${hash.slice(0, 12)}`,
    hash,
    productId: payload.productId,
    batchId: payload.batchId,
    issuedAt,
    expiresAt,
    scanCount: 0,
    revoked: false,
  };
}

/**
 * Verify an inbound QR scan hash against a stored record.
 */
export function verifyHash(
  incomingHash: string,
  record: QRVerificationRecord
): VerificationResult {
  const now = Date.now();

  if (record.revoked) {
    return {
      valid: false,
      hash: incomingHash,
      productId: record.productId,
      timestamp: now,
      message: 'This product verification has been revoked.',
    };
  }

  if (record.expiresAt && now > record.expiresAt.getTime()) {
    return {
      valid: false,
      hash: incomingHash,
      productId: record.productId,
      timestamp: now,
      message: 'Verification record has expired.',
    };
  }

  const isValid = incomingHash === record.hash;

  return {
    valid: isValid,
    hash: incomingHash,
    productId: record.productId,
    timestamp: now,
    message: isValid
      ? '✅ Authentic product verified on AuthiChain.'
      : '❌ Hash mismatch — possible counterfeit detected.',
  };
}

/**
 * Build a scannable verification URL for a QR code.
 */
export function buildVerificationUrl(
  baseUrl: string,
  productId: string,
  hash: string
): string {
  const url = new URL('/verify', baseUrl);
  url.searchParams.set('id', productId);
  url.searchParams.set('hash', hash);
  return url.toString();
}

/**
 * Quick one-shot: generate a payload, hash it, and return the verification URL.
 */
export function issueVerificationUrl(
  baseUrl: string,
  productId: string,
  batchId?: string
): { url: string; hash: string; record: QRVerificationRecord } {
  const payload: VerificationPayload = {
    productId,
    batchId,
    timestamp: Date.now(),
  };

  const record = createVerificationRecord(payload);
  const url = buildVerificationUrl(baseUrl, productId, record.hash);

  return { url, hash: record.hash, record };
}
