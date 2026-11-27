// Payload v2 — the insurance-card bundle format.
//
// An Insurance Cards upload carries MORE than one file plus typed
// fields (carrier, member ID, …). The relay is unchanged and still
// moves exactly one ciphertext + one manifest, so the page packs
// everything into ONE plaintext bundle and encrypts that with the
// office key exactly like a single document:
//
//   bundle = magic "SDUB" (4 bytes)
//          ‖ uint32 big-endian header length
//          ‖ UTF-8 JSON header { version: 2,
//                                fields: { plans: [ plan, … ] },
//                                files: [ { name, orig, size }, … ] }
//          ‖ file bytes concatenated in header order
//
// A plan is one insurance, in billing order (Shai, Nov 26, 2026 —
// up to three, replacing the earlier primary + optional-secondary
// shape):
//   { slot: "primary" | "secondary" | "tertiary",
//     carrier, memberId, group | null,
//     subscriber: { name, dob, relationship } | null,  // null = the
//                                // plan is in the patient's own name
//     photos: { front: <bundle file name> | null,
//               back:  <bundle file name> | null } }
//
// File names inside the bundle are role-labeled: card-front.<ext>,
// card-back.<ext> (primary), card2-front/back (secondary),
// card3-front/back (tertiary). `orig` keeps the patient's original
// filename for the filed name.
//
// PRIVACY: the typed insurance fields exist ONLY inside this
// encrypted bundle (and, after decryption, in the office-side
// requests.json / card-records.json). They are never put in the
// manifest, the email subject, or anywhere else that travels in the
// clear — test/card_bundle_test.mjs asserts the manifest stays clean.
//
// The office agent detects the bundle by the magic after decryption;
// every non-bundle payload keeps the legacy single-file path.

export const BUNDLE_MAGIC = 'SDUB';
export const BUNDLE_VERSION = 2;

const MAGIC_BYTES = new TextEncoder().encode(BUNDLE_MAGIC);

// Role order is the bundle order: primary front/back, then
// secondary, then tertiary.
export const CARD_ROLES = ['front', 'back', 'front2', 'back2', 'front3', 'back3'];
export const CARD_ROLE_LABELS = {
  front: 'Insurance Cards (Primary, Front)',
  back: 'Insurance Cards (Primary, Back)',
  front2: 'Insurance Cards (Secondary, Front)',
  back2: 'Insurance Cards (Secondary, Back)',
  front3: 'Insurance Cards (Tertiary, Front)',
  back3: 'Insurance Cards (Tertiary, Back)',
};
const ROLE_TO_BUNDLE_NAME = {
  front: 'card-front',
  back: 'card-back',
  front2: 'card2-front',
  back2: 'card2-back',
  front3: 'card3-front',
  back3: 'card3-back',
};

function bundleBaseName(role) {
  const base = ROLE_TO_BUNDLE_NAME[role];
  if (!base) throw new Error(`unknown card photo role: ${role}`);
  return base;
}

function extOf(filename) {
  const m = String(filename ?? '').match(/\.([A-Za-z0-9]{1,8})$/);
  return m ? m[1].toLowerCase() : 'jpg';
}

/**
 * Build a bundle. `files` is an array of { role, origName, bytes }
 * (bytes: Uint8Array); roles must come from CARD_ROLES. Returns a
 * Uint8Array ready to hand to encryptDocument as fileBytes.
 */
export function buildBundle({ fields, files }) {
  if (!fields || typeof fields !== 'object') throw new Error('bundle needs a fields object');
  if (!Array.isArray(files) || files.length === 0) throw new Error('bundle needs at least one file');
  const entries = [];
  const chunks = [];
  for (const f of files) {
    if (!f || !f.bytes) throw new Error('each bundle file needs bytes');
    const bytes = f.bytes instanceof Uint8Array ? f.bytes : new Uint8Array(f.bytes);
    entries.push({
      name: `${bundleBaseName(f.role)}.${extOf(f.origName)}`,
      orig: String(f.origName ?? ''),
      size: bytes.length,
    });
    chunks.push(bytes);
  }
  const header = { version: BUNDLE_VERSION, fields, files: entries };
  const headerBytes = new TextEncoder().encode(JSON.stringify(header));
  const out = new Uint8Array(4 + 4 + headerBytes.length + chunks.reduce((n, c) => n + c.length, 0));
  out.set(MAGIC_BYTES, 0);
  new DataView(out.buffer).setUint32(4, headerBytes.length, false);
  out.set(headerBytes, 8);
  let off = 8 + headerBytes.length;
  for (const c of chunks) { out.set(c, off); off += c.length; }
  return out;
}

/** True when the decrypted bytes start with the bundle magic. */
export function isBundle(bytes) {
  if (!bytes || bytes.length < 8) return false;
  return bytes[0] === 0x53 && bytes[1] === 0x44 && bytes[2] === 0x55 && bytes[3] === 0x42;
}

/** Role for a bundle file name (card-front.jpg -> 'front'). */
export function roleOfBundleName(name) {
  for (const role of CARD_ROLES) {
    if (String(name).startsWith(ROLE_TO_BUNDLE_NAME[role] + '.')) return role;
  }
  return null;
}

/**
 * Parse a bundle produced by buildBundle. Returns
 * { version, fields, files: [{ name, orig, role, bytes }] }.
 * Throws on any structural problem — the agent treats a malformed
 * bundle as a filing failure, never a partial success.
 */
export function parseBundle(bytes) {
  if (!isBundle(bytes)) throw new Error('not an SDUB bundle');
  const headerLen = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(4, false);
  const headerStart = 8;
  const dataStart = headerStart + headerLen;
  if (headerLen <= 0 || dataStart > bytes.length) throw new Error('bundle header length out of range');
  let header;
  try {
    header = JSON.parse(new TextDecoder().decode(bytes.subarray(headerStart, dataStart)));
  } catch {
    throw new Error('bundle header is not valid JSON');
  }
  if (header.version !== BUNDLE_VERSION) throw new Error(`unsupported bundle version: ${header.version}`);
  if (!header.fields || typeof header.fields !== 'object') throw new Error('bundle header has no fields');
  if (!Array.isArray(header.files) || header.files.length === 0) throw new Error('bundle header has no files');
  const files = [];
  let off = dataStart;
  for (const entry of header.files) {
    const size = Number(entry.size);
    if (!Number.isInteger(size) || size < 0 || off + size > bytes.length) {
      throw new Error(`bundle file ${entry.name} size out of range`);
    }
    files.push({
      name: String(entry.name),
      orig: String(entry.orig ?? ''),
      role: roleOfBundleName(entry.name),
      bytes: bytes.subarray(off, off + size),
    });
    off += size;
  }
  if (off !== bytes.length) throw new Error('bundle has trailing bytes');
  return { version: header.version, fields: header.fields, files };
}
