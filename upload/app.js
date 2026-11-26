// Upload page logic. Encryption happens entirely in the browser using the
// SAME shared code path as the automated test: ../shared/encrypt.mjs.
// Serve the repo root over HTTP (see README) so the relative imports resolve.

// ==========================================================================
// CUTOVER CONFIG — the ONLY block that changes between POC and production.
// --------------------------------------------------------------------------
// RELAY_URL:            Production: the deployed relay endpoint, e.g.
//                       'https://secure-doc-upload-relay.<acct>.workers.dev/upload'.
//                       Empty string = POC mode: no relay, the encrypted
//                       file is downloaded instead of sent.
// PUBLIC_KEY_URL:       The office public key the page encrypts to. At
//                       cutover this file is REPLACED with the production
//                       public key produced by the key ceremony
//                       (docs/KEY-CEREMONY.md) — the POC key below must
//                       never encrypt a real patient document.
// KEY_LABEL:            Human label shown on the page next to the key
//                       fingerprint so staff can confirm at a glance which
//                       key is live.
// EXPECTED_KEY_FINGERPRINT: The page refuses to run if the key it loaded
//                       doesn't match this fingerprint — a tripwire against
//                       the wrong key file being published. Set to the
//                       production fingerprint at cutover (printed by the
//                       key ceremony).
// ==========================================================================
const CONFIG = {
  RELAY_URL: 'https://secure-doc-upload-relay.uniontpkedental.workers.dev/upload', // <-- set at deploy: https://secure-doc-upload-relay.<account-subdomain>.workers.dev/upload (docs/GO-LIVE.md)
  PUBLIC_KEY_URL: './public-key.asc',
  KEY_LABEL: 'PRODUCTION — Union Tpke Dental office key (generated on softdentsync, Nov 26, 2026)',
  EXPECTED_KEY_FINGERPRINT: '306460877b9e71ab509eb27f08e569aa16ae8ddb',
};

import * as openpgp from './vendor/openpgp.min.mjs';
import { encryptDocument } from './encrypt.mjs';
import { isValidCodeFormat, normalizeCode } from './codes.mjs';

const form = document.getElementById('upload-form');
const status = document.getElementById('status');
const keyinfo = document.getElementById('keyinfo');
const button = document.getElementById('go');
const codeInput = document.getElementById('code');
const patientInput = document.getElementById('patient');
const requestInfo = document.getElementById('requestinfo');

// The relay's /code-info endpoint lives next to /upload.
const CODE_INFO_URL = CONFIG.RELAY_URL
  ? CONFIG.RELAY_URL.replace(/\/upload\/?$/, '/code-info')
  : '';

const CODE_PROBLEM_MESSAGE =
  'This upload code isn’t valid or has expired. Upload codes work once and ' +
  'only for a limited time. Please call the office and we’ll text you a new code.';

let publicKeyArmored = null;

// Load the encryption key up front, verify it against the configured
// fingerprint, and show both on the page. If anything is off, disable the
// form — encrypting to the wrong key would make the document unreadable
// to the office (or worse, readable by someone else).
async function initKey() {
  try {
    publicKeyArmored = await (await fetch(CONFIG.PUBLIC_KEY_URL)).text();
    const key = await openpgp.readKey({ armoredKey: publicKeyArmored });
    const fingerprint = key.getFingerprint().toLowerCase();
    keyinfo.textContent = `Encryption key: ${CONFIG.KEY_LABEL} · fingerprint ${fingerprint}`;
    if (CONFIG.EXPECTED_KEY_FINGERPRINT && fingerprint !== CONFIG.EXPECTED_KEY_FINGERPRINT.toLowerCase()) {
      keyinfo.textContent += ' — MISMATCH with configured fingerprint. Uploads are disabled; please call the office.';
      keyinfo.className = 'err';
      button.disabled = true;
    }
  } catch (err) {
    keyinfo.textContent = `Could not load the office encryption key (${err.message}). Uploads are disabled; please call the office.`;
    keyinfo.className = 'err';
    button.disabled = true;
  }
}
initKey();

// ---------------------------------------------------------------------
// Code info: when the office issued this code for a specific document
// request (staff console), the relay can say what was requested. We ask
// when the patient leaves the code field, on load when the link itself
// carried the code (see initCodeFromUrl below), and again at submit if
// we haven't yet; show "Union Tpke Dental requested: …", prefill the
// name, and stamp the request fields into the manifest so the office
// can tie the filed document back to the request. ANY failure — plain
// code, relay unreachable, old relay without /code-info — silently
// falls back to the plain flow; nothing here may block an upload.
// ---------------------------------------------------------------------
let codeInfo = null;      // last successful /code-info body
let codeInfoFor = '';     // normalized code it belongs to
let nameAutoFilled = '';  // value we last prefilled into the name field

async function fetchCodeInfo(code) {
  const normalized = normalizeCode(code);
  if (!CODE_INFO_URL || !isValidCodeFormat(normalized)) return;
  if (codeInfoFor === normalized && codeInfo) return;
  try {
    const resp = await fetch(`${CODE_INFO_URL}?code=${encodeURIComponent(normalized)}`);
    if (!resp.ok) return;
    const body = await resp.json();
    if (!body || body.ok !== true) return;
    if (normalizeCode(codeInput.value) !== normalized) return; // field moved on
    codeInfo = body;
    codeInfoFor = normalized;
    if (body.category) {
      requestInfo.style.display = 'block';
      requestInfo.textContent =
        `Union Tpke Dental requested: ${body.category}` +
        (body.note ? ` (${body.note})` : '');
    }
    if (body.patientName && (!patientInput.value.trim() || patientInput.value === nameAutoFilled)) {
      patientInput.value = body.patientName;
      nameAutoFilled = body.patientName;
    }
  } catch { /* silent fallback — plain flow */ }
}
codeInput.addEventListener('change', () => fetchCodeInfo(codeInput.value));

// Deep link: the office's text/email carries the code in the link
// itself (…/upload/?code=XXXX-XXXX-XXXX), because a patient cannot
// select/copy just the code out of a text message on a phone. One tap
// lands here with the code filled in and looked up — exactly as if
// they had typed it and left the field — so they are one tap from
// picking their file. A malformed or missing param is ignored
// silently; manual entry below keeps working exactly as before.
//
// The link also carries the patient's name as an ENCRYPTED token
// (…&n=<TOKEN>) — a FALLBACK prefill for when /code-info can't
// supply the name (hand-issued code with no stored name, relay
// hiccup). The name never appears in the link in readable form.
//
// TOKEN = base64url( salt[16] || iv[12] || AES-256-GCM ct+tag ) of
// the UTF-8 name, key = PBKDF2-HMAC-SHA256(password = the upload
// code, salt, 100,000 iterations, 32-byte key). The senders
// (office-agent/send_text.py, send_email.py) encrypt; this page
// decrypts with WebCrypto using the ?code= value (normalizeCode
// output — identical to the code as issued for real codes, which
// are canonical uppercase). This is READABILITY protection, not
// access control: anyone holding the full link holds the code and
// can decrypt. It keeps the name out of message logs, link
// previews and screenshots — nothing more is claimed for it.
//
// The token never wins over /code-info (a code-info name replaces
// a token-prefilled one, via nameAutoFilled), and neither source
// overwrites text the patient typed themselves. ANY decrypt
// failure — bad token, wrong code, malformed — is silently
// ignored and the plain flow continues.
let urlName = '';  // name decrypted from the ?n= token, once resolved

function sanitizeUrlName(raw) {
  if (!raw) return '';
  // Strip control characters, trim, and cap the length — a prefill
  // convenience, not data worth trusting at arbitrary size.
  return raw.replace(/[\u0000-\u001F\u007F]/g, '').trim().slice(0, 80).trim();
}

function base64UrlDecode(token) {
  const b64 = token.replace(/-/g, '+').replace(/_/g, '/');
  const padded = b64 + '='.repeat((4 - (b64.length % 4)) % 4);
  const bin = atob(padded);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

async function decryptUrlName(token, code) {
  try {
    if (!token || !code || !window.crypto?.subtle) return '';
    const raw = base64UrlDecode(token);
    if (raw.length < 16 + 12 + 16) return ''; // salt + iv + tag minimum
    const salt = raw.slice(0, 16);
    const iv = raw.slice(16, 28);
    const ciphertext = raw.slice(28);
    const baseKey = await crypto.subtle.importKey(
      'raw', new TextEncoder().encode(code), 'PBKDF2', false, ['deriveKey']);
    const key = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
      baseKey, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
    return sanitizeUrlName(new TextDecoder().decode(plain));
  } catch { return ''; } // silent — plain flow
}

function applyUrlNameFallback() {
  if (!urlName) return;
  if (codeInfo && codeInfo.patientName) return; // code-info wins
  if (!patientInput.value.trim() || patientInput.value === nameAutoFilled) {
    patientInput.value = urlName;
    nameAutoFilled = urlName;
  }
}

(function initCodeFromUrl() {
  let param = '';
  let token = '';
  try {
    param = new URLSearchParams(window.location.search).get('code') ?? '';
    token = new URLSearchParams(window.location.search).get('n') ?? '';
  } catch { return; }
  const normalized = normalizeCode(param);
  if (token && isValidCodeFormat(normalized)) {
    // Fire and forget: prefill whenever the decrypt resolves, unless
    // code-info (or the patient) got there first — applyUrlNameFallback
    // and fetchCodeInfo together guarantee code-info wins and typed
    // text is never overwritten.
    decryptUrlName(token, normalized).then((name) => {
      if (name) { urlName = name; applyUrlNameFallback(); }
    });
  }
  if (!isValidCodeFormat(normalized)) return;
  codeInput.value = normalized;
  fetchCodeInfo(normalized);
})();

codeInput.addEventListener('input', () => {
  // A different code invalidates what we showed/prefilled for the old one.
  if (codeInfoFor && normalizeCode(codeInput.value) !== codeInfoFor) {
    codeInfo = null;
    codeInfoFor = '';
    requestInfo.style.display = 'none';
    requestInfo.textContent = '';
    if (patientInput.value === nameAutoFilled) patientInput.value = '';
    nameAutoFilled = '';
  }
});

function download(name, data, type) {
  const url = URL.createObjectURL(new Blob([data], { type }));
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 5000);
}

// Send the ciphertext + manifest to the relay (production mode).
// Returns true on success; on a known relay error, shows the matching
// patient-friendly message and returns false.
async function sendViaRelay({ uploadCode, patientName, ciphertext, manifest }) {
  const formData = new FormData();
  formData.set('code', uploadCode);
  formData.set('patientName', patientName);
  formData.set('manifest', JSON.stringify(manifest));
  formData.set('file', new Blob([ciphertext], { type: 'application/octet-stream' }), `${manifest.originalFilename}.pgp`);

  const resp = await fetch(CONFIG.RELAY_URL, { method: 'POST', body: formData });
  let body = {};
  try { body = await resp.json(); } catch { /* non-JSON error page */ }
  if (resp.ok && body.ok) return true;

  status.className = 'err';
  if (body.error === 'code_expired' || body.error === 'code_invalid' || body.error === 'code_used') {
    status.textContent = CODE_PROBLEM_MESSAGE;
  } else if (body.error === 'too_large') {
    status.textContent = 'That document is too large to send this way (25 MB maximum). Please call the office and we’ll arrange another way.';
  } else {
    status.textContent = 'Something went wrong while sending. Please try again, or call the office for help.';
  }
  return false;
}

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  button.disabled = true;
  status.className = '';
  try {
    const uploadCode = document.getElementById('code').value.trim();
    const patientName = document.getElementById('patient').value.trim();
    const file = document.getElementById('file').files[0];
    if (!file) throw new Error('Choose a document first.');
    if (!publicKeyArmored) throw new Error('The encryption key has not loaded yet — wait a moment and try again.');

    // In production mode the relay is the authority on codes, but a
    // format pre-check here gives the patient the friendly message
    // instantly instead of after a round trip. (POC mode has no relay;
    // the demo code from the README is accepted there.)
    if (CONFIG.RELAY_URL && !isValidCodeFormat(uploadCode)) {
      status.className = 'err';
      status.textContent = CODE_PROBLEM_MESSAGE;
      return;
    }

    // If the code field never blurred, ask the relay what this code is
    // for now, so the manifest still carries the request fields.
    if (CONFIG.RELAY_URL) await fetchCodeInfo(uploadCode);
    const requestFields = codeInfo && codeInfoFor === normalizeCode(uploadCode)
      ? {
          category: codeInfo.category ?? null,
          note: codeInfo.note ?? null,
          requestId: codeInfo.requestId ?? null,
          patientRecordId: codeInfo.patientRecordId ?? null,
        }
      : {};

    status.textContent = 'Encrypting in your browser…';
    const fileBytes = new Uint8Array(await file.arrayBuffer());
    const { ciphertext, manifest } = await encryptDocument(openpgp, publicKeyArmored, {
      uploadCode,
      patientName,
      originalFilename: file.name,
      fileBytes,
      ...requestFields,
    });

    if (CONFIG.RELAY_URL) {
      status.textContent = 'Encrypted. Sending securely…';
      const sent = await sendViaRelay({ uploadCode, patientName, ciphertext, manifest });
      if (sent) {
        status.className = 'ok';
        status.textContent = 'Done — your document was encrypted on this device and sent to the office. You can close this page.';
      }
    } else {
      const base = file.name.replace(/[^\w.-]+/g, '_');
      download(`${base}.pgp`, ciphertext, 'application/octet-stream');
      download(`${base}.manifest.json`, JSON.stringify(manifest, null, 2), 'application/json');
      status.className = 'ok';
      status.textContent =
        `Done. Your document was encrypted before leaving this device.\n` +
        `Downloaded: ${base}.pgp and ${base}.manifest.json\n` +
        `(POC mode — in production these are sent to the office automatically.)\n` +
        `SHA-256 of original: ${manifest.sha256}`;
    }
  } catch (err) {
    status.className = 'err';
    status.textContent = `Something went wrong: ${err.message}`;
  } finally {
    button.disabled = false;
  }
});
