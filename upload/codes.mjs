// Upload-code format + validation logic.
//
// Shared by the Cloudflare Worker (relay/worker.js) and the local test
// (test/worker_codes_test.mjs). Pure ESM, no dependencies, no I/O — the
// code store is injected, so the same logic runs against Cloudflare KV in
// production and an in-memory stub in tests.
//
// CODE FORMAT (production): three groups of four uppercase letters/digits
// separated by dashes, e.g. "K7QX-3M9P-Z2RD" — 12 significant characters,
// readable over the phone, no ambiguous glyphs required by the alphabet
// (issuance tooling SHOULD avoid 0/O and 1/I/L when generating).
//
// CODE RECORD (one per issued code, stored under the code as key):
//   {
//     "code":        "K7QX-3M9P-Z2RD",
//     "patientName": "Jane Doe",          // filing label / match target
//     "createdAt":   "2026-11-26T14:00:00.000Z",
//     "expiresAt":   "2026-11-29T14:00:00.000Z",   // office picks the window
//     "usedAt":      null                  // set by the relay on first use
//   }
//
// Codes are single-use and expiring by design: the code is the only sender
// authentication in this system (the office public key is public), so a
// code must be treated like a short-lived, per-patient secret. See
// relay/README.md for the issuance workflow.

export const UPLOAD_CODE_PATTERN = /^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/;

export function isValidCodeFormat(code) {
  return typeof code === 'string' && UPLOAD_CODE_PATTERN.test(code.trim().toUpperCase());
}

export function normalizeCode(code) {
  return typeof code === 'string' ? code.trim().toUpperCase() : '';
}

// Generation alphabet: ambiguous glyphs 0/O and 1/I/L excluded, so codes
// survive being read over the phone. 31 symbols.
export const CODE_ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';

// Generate one production-format code (XXXX-XXXX-XXXX) from a CSPRNG.
// Uses WebCrypto (globalThis.crypto), available in both the Cloudflare
// Worker runtime and Node >= 19, so the Worker (POST /issue) and local
// tooling share this one generator. Rejection sampling keeps every
// symbol equally likely (256 is not a multiple of 31).
export function generateUploadCode() {
  const LIMIT = 256 - (256 % CODE_ALPHABET.length); // 248
  const chars = [];
  while (chars.length < 12) {
    const bytes = new Uint8Array(24);
    globalThis.crypto.getRandomValues(bytes);
    for (const b of bytes) {
      if (b >= LIMIT) continue;
      chars.push(CODE_ALPHABET[b % CODE_ALPHABET.length]);
      if (chars.length === 12) break;
    }
  }
  const flat = chars.join('');
  return `${flat.slice(0, 4)}-${flat.slice(4, 8)}-${flat.slice(8, 12)}`;
}

// Minimal store interface used by validateUploadCode:
//   store.get(code)        -> Promise<record|null>
//   store.put(code, record)-> Promise<void>
// createMemoryCodeStore is the local stub for tests and dry runs — in
// production the Worker builds the same shape over a KV namespace
// (see createKvCodeStore in worker.js). No real KV is created by this repo.
export function createMemoryCodeStore(records = []) {
  const map = new Map(records.map((r) => [normalizeCode(r.code), { ...r }]));
  return {
    async get(code) {
      const rec = map.get(normalizeCode(code));
      return rec ? { ...rec } : null;
    },
    async put(code, record) {
      map.set(normalizeCode(code), { ...record });
    },
    // Test/debug helper only; not part of the worker-facing interface.
    _dump() {
      return [...map.values()].map((r) => ({ ...r }));
    },
  };
}

// Validate a presented code against the store.
// Returns { ok: true, record } or { ok: false, reason } where reason is one of:
//   'format'  — doesn't match the production code format
//   'unknown' — well-formed but no record (never issued, or mistyped)
//   'expired' — record exists but now > expiresAt
//   'used'    — record exists but was already consumed
export async function validateUploadCode(code, store, now = new Date()) {
  const normalized = normalizeCode(code);
  if (!isValidCodeFormat(normalized)) return { ok: false, reason: 'format' };
  const record = await store.get(normalized);
  if (!record) return { ok: false, reason: 'unknown' };
  if (record.usedAt) return { ok: false, reason: 'used' };
  if (record.expiresAt && now > new Date(record.expiresAt)) {
    return { ok: false, reason: 'expired' };
  }
  return { ok: true, record };
}

// Mark a code consumed after a successful relay. Returns the updated record.
export async function markCodeUsed(code, store, now = new Date()) {
  const normalized = normalizeCode(code);
  const record = await store.get(normalized);
  if (!record) return null;
  const updated = { ...record, usedAt: now.toISOString() };
  await store.put(normalized, updated);
  return updated;
}
