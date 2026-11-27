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
import { buildBundle } from './bundle.mjs';
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
    updateInsuranceUi();
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
    insEscapeChosen = false;
    insReviewDone = false;
    resetInsurancePlans();
    updateInsuranceUi();
  }
});

// ---------------------------------------------------------------------
// Insurance Cards flow (payload v2). When the code was issued for an
// Insurance Cards request, the patient types their insurance details
// AND photographs the front and back of the card; the page packs
// fields + photos into ONE bundle (shared/bundle.mjs) and encrypts
// the bundle exactly like a single document. The typed values exist
// only inside that encrypted bundle — never in the manifest.
// "Just send a document instead" falls back to the original
// single-file flow, unchanged.
// ---------------------------------------------------------------------
const insBox = document.getElementById('insurance');
const docStep = document.getElementById('docstep');
const fileInput = document.getElementById('file');
let insEscapeChosen = false;
let insReviewDone = false;

const insVal = (id) => document.getElementById(id).value.trim();
const insChecked = (id) => document.getElementById(id).checked;

function insuranceActive() {
  return !!codeInfo && codeInfo.category === 'Insurance Cards' && !insEscapeChosen;
}

function updateInsuranceUi() {
  const active = insuranceActive();
  insBox.style.display = active ? 'block' : 'none';
  docStep.style.display = active ? 'none' : 'block';
  fileInput.required = !active;
}
updateInsuranceUi();

document.getElementById('ins-escape').addEventListener('click', (e) => {
  e.preventDefault();
  insEscapeChosen = true;
  updateInsuranceUi();
});

for (const n of [1, 2, 3]) {
  document.getElementById(`ins${n}-own`).addEventListener('change', (e) => {
    document.getElementById(`ins${n}-sub`).style.display = e.target.checked ? 'none' : 'block';
  });
}

// Up to THREE plans, in billing order (Shai, Nov 26, 2026). Plan 1
// ("Primary insurance") is always present; "Add another insurance"
// reveals Plan 2 ("Secondary insurance"), then Plan 3 ("Third
// insurance"). Photos are required for Plan 1, optional for 2 and 3.
let insPlanCount = 1;
const PLAN_SLOTS = ['primary', 'secondary', 'tertiary'];
const PLAN_TITLES = ['Primary insurance', 'Secondary insurance', 'Third insurance'];

function invalidateInsuranceReview() {
  insReviewDone = false;
  document.getElementById('ins-review').style.display = 'none';
  document.getElementById('ins-edit-btn').style.display = 'none';
}
function resetInsurancePlans() {
  insPlanCount = 1;
  document.getElementById('ins2-block').style.display = 'none';
  document.getElementById('ins3-block').style.display = 'none';
  document.getElementById('ins-add2').style.display = 'inline-block';
  document.getElementById('ins-add3').style.display = 'inline-block';
}
document.getElementById('ins-add2').addEventListener('click', () => {
  insPlanCount = 2;
  document.getElementById('ins2-block').style.display = 'block';
  document.getElementById('ins-add2').style.display = 'none';
  invalidateInsuranceReview();
});
document.getElementById('ins-add3').addEventListener('click', () => {
  insPlanCount = 3;
  document.getElementById('ins3-block').style.display = 'block';
  document.getElementById('ins-add3').style.display = 'none';
  invalidateInsuranceReview();
});
insBox.addEventListener('input', invalidateInsuranceReview);

function readPlan(n) {
  const prefix = `ins${n}-`;
  const own = insChecked(`${prefix}own`);
  return {
    slot: PLAN_SLOTS[n - 1],
    carrier: insVal(`${prefix}carrier`),
    memberId: insVal(`${prefix}member`),
    group: insVal(`${prefix}group`) || null,
    // null when the plan is in the patient's own name
    subscriber: own ? null : {
      name: insVal(`${prefix}subname`) || null,
      dob: document.getElementById(`${prefix}subdob`).value || null,
      relationship: document.getElementById(`${prefix}subrel`).value,
    },
    photos: { front: null, back: null }, // bundle file names, set at send time
  };
}

// The plans the patient has opened, in billing order.
function activePlans() {
  const plans = [];
  for (let n = 1; n <= insPlanCount; n++) plans.push(readPlan(n));
  return plans;
}

function planProblems(plan, label) {
  const problems = [];
  if (!plan.carrier) problems.push(`${label}: insurance company is missing`);
  if (!plan.memberId) problems.push(`${label}: member ID is missing`);
  if (plan.subscriber && !plan.subscriber.name) problems.push(`${label}: subscriber name is missing`);
  return problems;
}

function describePlan(plan, label, lines) {
  lines.push(`${label}: ${plan.carrier}`);
  lines.push(`  Member ID: ${plan.memberId}`);
  if (plan.group) lines.push(`  Group number: ${plan.group}`);
  if (!plan.subscriber) lines.push('  Plan is in your name');
  else lines.push(`  Subscriber: ${plan.subscriber.name ?? ''} (born ${plan.subscriber.dob ?? '—'}, ${plan.subscriber.relationship ?? ''})`);
}

document.getElementById('ins-review-btn').addEventListener('click', () => {
  const plans = activePlans();
  const problems = [];
  plans.forEach((plan, i) => problems.push(...planProblems(plan, PLAN_TITLES[i])));
  if (!document.getElementById('file1-front').files[0]) problems.push('Primary insurance: front of card photo is missing');
  if (!document.getElementById('file1-back').files[0]) problems.push('Primary insurance: back of card photo is missing');
  const review = document.getElementById('ins-review');
  if (problems.length) {
    review.style.display = 'block';
    review.textContent = 'Almost there:\n' + problems.map((p) => `• ${p}`).join('\n');
    insReviewDone = false;
    return;
  }
  const lines = ['Please check this matches your cards:', ''];
  plans.forEach((plan, i) => { if (i) lines.push(''); describePlan(plan, PLAN_TITLES[i], lines); });
  lines.push('', 'We’ll bill them in this order.');
  lines.push(plans.length > 1 ? 'Photos of your cards are attached.'
                              : 'Photos: front and back of your card are attached.');
  review.style.display = 'block';
  review.textContent = lines.join('\n');
  document.getElementById('ins-edit-btn').style.display = 'inline-block';
  insReviewDone = true;
});
document.getElementById('ins-edit-btn').addEventListener('click', () => {
  insReviewDone = false;
  document.getElementById('ins-review').style.display = 'none';
  document.getElementById('ins-edit-btn').style.display = 'none';
  insBox.scrollIntoView({ behavior: 'smooth' });
});

const ROLE_FOR_PICK = { '1-front': 'front', '1-back': 'back', '2-front': 'front2', '2-back': 'back2', '3-front': 'front3', '3-back': 'back3' };
const BASE_FOR_ROLE = { front: 'card-front', back: 'card-back', front2: 'card2-front', back2: 'card2-back', front3: 'card3-front', back3: 'card3-back' };

function bundleNameFor(role, origName) {
  const m = String(origName ?? '').match(/\.([A-Za-z0-9]{1,8})$/);
  return `${BASE_FOR_ROLE[role]}.${m ? m[1].toLowerCase() : 'jpg'}`;
}

// Collect the plans + photos into bundle inputs, stamping each
// plan's photos.{front,back} with the bundle file name it travels
// under (null when that side wasn't photographed).
async function collectInsuranceBundle() {
  const plans = activePlans();
  const files = [];
  for (let n = 1; n <= insPlanCount; n++) {
    const plan = plans[n - 1];
    for (const side of ['front', 'back']) {
      const f = document.getElementById(`file${n}-${side}`).files[0];
      if (!f) {
        if (n === 1) throw new Error('Please add photos of the front and back of your card.');
        continue;
      }
      const role = ROLE_FOR_PICK[`${n}-${side}`];
      plan.photos[side] = bundleNameFor(role, f.name);
      files.push({ role, origName: f.name, bytes: new Uint8Array(await f.arrayBuffer()) });
    }
  }
  return { fields: { plans }, files };
}

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
    let ciphertext, manifest, downloadBase;
    if (insuranceActive()) {
      // Insurance Cards bundle (payload v2): typed fields + card
      // photos in ONE encrypted bundle under the same code/manifest
      // contract. The manifest carries only the usual metadata —
      // never any typed insurance value.
      if (!insReviewDone) {
        status.className = 'err';
        status.textContent = 'Please tap “Check what I typed” first, make sure it matches your card, then send.';
        return;
      }
      const { fields, files } = await collectInsuranceBundle();
      const bundleBytes = buildBundle({ fields, files });
      ({ ciphertext, manifest } = await encryptDocument(openpgp, publicKeyArmored, {
        uploadCode,
        patientName,
        originalFilename: 'insurance-card-bundle',
        fileBytes: bundleBytes,
        ...requestFields,
      }));
      downloadBase = 'insurance-card-bundle';
    } else {
      const file = document.getElementById('file').files[0];
      if (!file) throw new Error('Choose a document first.');
      const fileBytes = new Uint8Array(await file.arrayBuffer());
      ({ ciphertext, manifest } = await encryptDocument(openpgp, publicKeyArmored, {
        uploadCode,
        patientName,
        originalFilename: file.name,
        fileBytes,
        ...requestFields,
      }));
      downloadBase = file.name.replace(/[^\w.-]+/g, '_');
    }

    if (CONFIG.RELAY_URL) {
      status.textContent = 'Encrypted. Sending securely…';
      const sent = await sendViaRelay({ uploadCode, patientName, ciphertext, manifest });
      if (sent) {
        status.className = 'ok';
        status.textContent = 'Done — your document was encrypted on this device and sent to the office. You can close this page.';
      }
    } else {
      download(`${downloadBase}.pgp`, ciphertext, 'application/octet-stream');
      download(`${downloadBase}.manifest.json`, JSON.stringify(manifest, null, 2), 'application/json');
      status.className = 'ok';
      status.textContent =
        `Done. Your document was encrypted before leaving this device.\n` +
        `Downloaded: ${downloadBase}.pgp and ${downloadBase}.manifest.json\n` +
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
