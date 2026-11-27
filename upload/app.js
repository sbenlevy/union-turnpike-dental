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
import { downscalePhotoFile } from './images.mjs';
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
let urlKind = 'dental';  // insurance kind from the &kind= link param
                         // ("medical" only; absent/other = dental).
                         // Wording-only on this page — the office
                         // request record is the authoritative kind.

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
  let kindParam = '';
  try {
    param = new URLSearchParams(window.location.search).get('code') ?? '';
    token = new URLSearchParams(window.location.search).get('n') ?? '';
    kindParam = new URLSearchParams(window.location.search).get('kind') ?? '';
  } catch { return; }
  if (kindParam === 'medical') urlKind = 'medical';
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
    insDentalYes = false;
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

// Dental-vs-medical gate (Nov 27, 2026): the plan form stays hidden
// behind #ins-dental-gate until the patient confirms they have
// insurance OF THE KIND THE OFFICE ASKED FOR. The office sometimes
// bills a medical plan, so an Insurance Cards request carries a kind
// ("dental" default, or "medical" via the &kind=medical link param)
// and the gate mirrors its wording. "I don't have … insurance" sends
// its own zero-file bundle (see sendNoInsurance below) instead of
// the form.
const dentalGate = document.getElementById('ins-dental-gate');
const insPlans = document.getElementById('ins-plans');
let insDentalYes = false;

const GATE_TEXTS = {
  dental: {
    heading: 'Your dental insurance',
    line1: "We need the insurance that pays for DENTAL work — cleanings, fillings, crowns. That's a separate card from your medical insurance.",
    line2: 'Dental plans include: Delta Dental, MetLife, Cigna Dental, Guardian, Aetna Dental, UnitedHealthcare Dental.',
    line3: "Please don't send: a Medicare card, a medical/health card, or a pharmacy card — those don't cover dental work.",
    line4: "If one card covers both medical and dental, send it — we'll sort it out.",
    yes: 'Yes, I have dental insurance',
    no: "I don't have dental insurance",
    reminder: "One check: the card you're about to enter — does it cover dental work? If it's a medical-only card, go back and tap 'I don't have dental insurance' — or call us if you're not sure.",
    thanks: "Thanks for letting us know. You don't need to send anything else. If you get dental insurance later, just tell the office.",
  },
  medical: {
    heading: 'Your medical insurance',
    line1: "We need the insurance that pays for MEDICAL care — doctor visits and hospital bills. For this, we're billing your medical plan, not a dental plan.",
    line2: 'Medical plans include: Medicare, Aetna, Cigna, UnitedHealthcare, Empire BlueCross BlueShield, Humana.',
    line3: "Please don't send: a dental-only card (like Delta Dental or MetLife Dental) — that doesn't cover medical care.",
    line4: "If one card covers both medical and dental, send it — we'll sort it out.",
    yes: 'Yes, I have medical insurance',
    no: "I don't have medical insurance",
    reminder: "One check: the card you're about to enter — does it cover medical care? If it's a dental-only card, go back and tap 'I don't have medical insurance' — or call us if you're not sure.",
    thanks: "Thanks for letting us know. You don't need to send anything else. If you get medical insurance later, just tell the office.",
  },
};

function applyGateKind() {
  const t = GATE_TEXTS[urlKind] ?? GATE_TEXTS.dental;
  document.getElementById('ins-gate-heading').textContent = t.heading;
  document.getElementById('ins-gate-line1').textContent = t.line1;
  document.getElementById('ins-gate-line2').textContent = t.line2;
  document.getElementById('ins-gate-line3').textContent = t.line3;
  document.getElementById('ins-gate-line4').textContent = t.line4;
  document.getElementById('ins-dental-yes').textContent = t.yes;
  document.getElementById('ins-dental-no').textContent = t.no;
  document.getElementById('ins-dental-reminder').textContent = t.reminder;
}

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
  applyGateKind();
  dentalGate.style.display = active && !insDentalYes ? 'block' : 'none';
  insPlans.style.display = active && insDentalYes ? 'block' : 'none';
}
updateInsuranceUi();

document.getElementById('ins-dental-yes').addEventListener('click', () => {
  insDentalYes = true;
  updateInsuranceUi();
});
document.getElementById('ins-dental-back').addEventListener('click', (e) => {
  e.preventDefault();
  insDentalYes = false;
  updateInsuranceUi();
});
document.getElementById('ins-dental-no').addEventListener('click', () => {
  sendNoInsurance();
});

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

// Up to THREE plans, in billing order (Shai, Nov 26, 2026), shown
// by PROGRESSIVE DISCLOSURE: only Plan 1 ("Primary insurance") is
// visible at first. A plain gate question — "Do you have another
// insurance plan that also covers you?" — decides whether Plan 2
// appears, and the same question again gates Plan 3. A plan block
// is never displayed before it is declared, and undeclared plans
// are simply absent from the bundle. For a DECLARED plan the front
// and back photos are required — unless the patient checks
// "I don't have this card with me right now" for that plan, which
// records photosStatus "not_with_me" so staff can follow up.
let insPlanCount = 1;
let insGate1 = null; // null | 'yes' | 'no'
let insGate2 = null;
const PLAN_SLOTS = ['primary', 'secondary', 'tertiary'];
const PLAN_TITLES = ['Primary insurance', 'Secondary insurance', 'Third insurance'];

function invalidateInsuranceReview() {
  insReviewDone = false;
  document.getElementById('ins-review').style.display = 'none';
  document.getElementById('ins-edit-btn').style.display = 'none';
}
function resetInsurancePlans() {
  insPlanCount = 1;
  insGate1 = null;
  insGate2 = null;
  document.getElementById('ins2-block').style.display = 'none';
  document.getElementById('ins3-block').style.display = 'none';
  document.getElementById('ins-gate1').style.display = 'block';
  document.getElementById('ins-gate1-done').style.display = 'none';
  document.getElementById('ins-gate2').style.display = 'none';
  document.getElementById('ins-gate2-done').style.display = 'none';
}
document.getElementById('ins-gate1-yes').addEventListener('click', () => {
  insGate1 = 'yes';
  insPlanCount = 2;
  document.getElementById('ins-gate1').style.display = 'none';
  document.getElementById('ins2-block').style.display = 'block';
  document.getElementById('ins-gate2').style.display = 'block';
  invalidateInsuranceReview();
});
document.getElementById('ins-gate1-no').addEventListener('click', () => {
  insGate1 = 'no';
  document.getElementById('ins-gate1').style.display = 'none';
  document.getElementById('ins-gate1-done').style.display = 'block';
  invalidateInsuranceReview();
});
document.getElementById('ins-gate1-change').addEventListener('click', (e) => {
  e.preventDefault();
  resetInsurancePlans();
  invalidateInsuranceReview();
});
document.getElementById('ins-gate2-yes').addEventListener('click', () => {
  insGate2 = 'yes';
  insPlanCount = 3;
  document.getElementById('ins-gate2').style.display = 'none';
  document.getElementById('ins3-block').style.display = 'block';
  invalidateInsuranceReview();
});
document.getElementById('ins-gate2-no').addEventListener('click', () => {
  insGate2 = 'no';
  document.getElementById('ins-gate2').style.display = 'none';
  document.getElementById('ins-gate2-done').style.display = 'block';
  invalidateInsuranceReview();
});
document.getElementById('ins-gate2-change').addEventListener('click', (e) => {
  e.preventDefault();
  insGate2 = null;
  insPlanCount = 2;
  document.getElementById('ins3-block').style.display = 'none';
  document.getElementById('ins-gate2').style.display = 'block';
  document.getElementById('ins-gate2-done').style.display = 'none';
  invalidateInsuranceReview();
});
for (const n of [1, 2, 3]) {
  document.getElementById(`ins${n}-nocard`).addEventListener('change', (e) => {
    document.getElementById(`file${n}-front`).disabled = e.target.checked;
    document.getElementById(`file${n}-back`).disabled = e.target.checked;
    invalidateInsuranceReview();
  });
}
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
    photosStatus: insChecked(`ins${n}-nocard`) ? 'not_with_me' : 'provided',
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
  if (insGate1 === null) {
    problems.push('Please answer: do you have another insurance plan that also covers you?');
  } else if (insGate1 === 'yes' && insGate2 === null) {
    problems.push('Please answer the same question under your second plan: do you have another insurance plan that also covers you?');
  }
  plans.forEach((plan, i) => {
    if (plan.photosStatus === 'not_with_me') return;
    const n = i + 1;
    if (!document.getElementById(`file${n}-front`).files[0]) problems.push(`${PLAN_TITLES[i]}: front of card photo is missing`);
    if (!document.getElementById(`file${n}-back`).files[0]) problems.push(`${PLAN_TITLES[i]}: back of card photo is missing`);
  });
  const review = document.getElementById('ins-review');
  review.textContent = '';
  if (problems.length) {
    review.style.display = 'block';
    review.textContent = 'Almost there:\n' + problems.map((p) => `• ${p}`).join('\n');
    insReviewDone = false;
    return;
  }
  const head = document.createElement('div');
  head.textContent = 'Please check this matches your cards:';
  review.appendChild(head);
  plans.forEach((plan, i) => {
    const lines = [];
    describePlan(plan, PLAN_TITLES[i], lines);
    if (plan.photosStatus === 'not_with_me') {
      lines.push('  Card photos: you don\'t have this card with you — the office may ask for them later.');
    } else {
      lines.push('  Card photos: front and back attached.');
    }
    const block = document.createElement('div');
    block.style.marginTop = '.8rem';
    const text = document.createElement('div');
    text.textContent = lines.join('\n');
    const edit = document.createElement('button');
    edit.type = 'button';
    edit.className = 'secondary';
    edit.textContent = `Edit ${PLAN_TITLES[i].toLowerCase()}`;
    edit.addEventListener('click', () => {
      invalidateInsuranceReview();
      document.getElementById(`ins${i + 1}-block`).scrollIntoView({ behavior: 'smooth' });
    });
    block.append(text, edit);
    review.appendChild(block);
  });
  const order = document.createElement('div');
  order.style.marginTop = '.8rem';
  order.textContent = 'We’ll bill them in this order.';
  review.appendChild(order);
  const more = document.createElement('div');
  more.style.marginTop = '.4rem';
  more.textContent = 'If you have more than three insurance plans, please call the office and we’ll collect the rest.';
  review.appendChild(more);
  review.style.display = 'block';
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
// under (null when that side wasn't photographed). Photos are
// downscaled in the browser first (bundle flow only — see
// shared/images.mjs) so a 3-plan bundle stays well under the email
// size limit. A plan marked "not_with_me" contributes no files.
async function collectInsuranceBundle() {
  const plans = activePlans();
  const files = [];
  for (let n = 1; n <= insPlanCount; n++) {
    const plan = plans[n - 1];
    if (plan.photosStatus === 'not_with_me') continue;
    for (const side of ['front', 'back']) {
      const f = document.getElementById(`file${n}-${side}`).files[0];
      if (!f) throw new Error(`Please add the ${side} photo of card ${n}, or check "I don't have this card with me right now".`);
      const role = ROLE_FOR_PICK[`${n}-${side}`];
      const { bytes, name } = await downscalePhotoFile(f);
      plan.photos[side] = bundleNameFor(role, name);
      files.push({ role, origName: name, bytes });
    }
  }
  return { fields: { plans }, files };
}

// "I don't have … insurance" (dental or medical, per the request's
// kind): the answer itself is the upload — a payload-v2 bundle with
// header noInsurance: true + kind, plans: [] and ZERO files,
// encrypted and sent through the exact same code + manifest contract
// as a card bundle (manifest carries no insurance values — there are
// none). The office agent records it and the request flips to
// "No dental insurance" / "No medical insurance" in the console, so
// staff stop waiting on a card that doesn't exist.
async function sendNoInsurance() {
  const noBtn = document.getElementById('ins-dental-no');
  const yesBtn = document.getElementById('ins-dental-yes');
  status.className = '';
  try {
    const uploadCode = codeInput.value.trim();
    const patientName = patientInput.value.trim();
    if (!publicKeyArmored) throw new Error('The encryption key has not loaded yet — wait a moment and try again.');
    if (CONFIG.RELAY_URL && !isValidCodeFormat(uploadCode)) {
      status.className = 'err';
      status.textContent = CODE_PROBLEM_MESSAGE;
      return;
    }
    if (!patientName) {
      status.className = 'err';
      status.textContent = 'Please type your name above first, so the office knows who answered.';
      patientInput.focus();
      return;
    }
    noBtn.disabled = true;
    yesBtn.disabled = true;
    if (CONFIG.RELAY_URL) await fetchCodeInfo(uploadCode);
    const requestFields = codeInfo && codeInfoFor === normalizeCode(uploadCode)
      ? {
          category: codeInfo.category ?? null,
          note: codeInfo.note ?? null,
          requestId: codeInfo.requestId ?? null,
          patientRecordId: codeInfo.patientRecordId ?? null,
        }
      : {};
    if (requestFields.category === 'Insurance Cards') requestFields.requestKind = urlKind;
    status.textContent = 'Encrypting in your browser…';
    const bundleBytes = buildBundle({
      fields: { plans: [] }, files: [], noInsurance: true, kind: urlKind,
    });
    const { ciphertext, manifest } = await encryptDocument(openpgp, publicKeyArmored, {
      uploadCode,
      patientName,
      originalFilename: 'insurance-card-bundle',
      fileBytes: bundleBytes,
      ...requestFields,
    });
    if (CONFIG.RELAY_URL) {
      status.textContent = 'Encrypted. Sending securely…';
      const sent = await sendViaRelay({ uploadCode, patientName, ciphertext, manifest });
      if (sent) {
        status.className = 'ok';
        status.textContent = GATE_TEXTS[urlKind].thanks;
      } else {
        noBtn.disabled = false;
        yesBtn.disabled = false;
      }
    } else {
      download('insurance-card-bundle.pgp', ciphertext, 'application/octet-stream');
      download('insurance-card-bundle.manifest.json', JSON.stringify(manifest, null, 2), 'application/json');
      status.className = 'ok';
      status.textContent = GATE_TEXTS[urlKind].thanks;
    }
  } catch (err) {
    status.className = 'err';
    status.textContent = `Something went wrong: ${err.message}`;
    noBtn.disabled = false;
    yesBtn.disabled = false;
  }
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
    if (requestFields.category === 'Insurance Cards') requestFields.requestKind = urlKind;

    status.textContent = 'Encrypting in your browser…';
    let ciphertext, manifest, downloadBase;
    if (insuranceActive()) {
      // Insurance Cards bundle (payload v2): typed fields + card
      // photos in ONE encrypted bundle under the same code/manifest
      // contract. The manifest carries only the usual metadata —
      // never any typed insurance value.
      if (!insDentalYes) {
        status.className = 'err';
        const t = GATE_TEXTS[urlKind];
        status.textContent = `Please answer the insurance question above first — tap “${t.yes}” or “${t.no}”.`;
        return;
      }
      if (!insReviewDone) {
        status.className = 'err';
        status.textContent = 'Please tap “Check what I typed” first, make sure it matches your card, then send.';
        return;
      }
      const { fields, files } = await collectInsuranceBundle();
      const bundleBytes = buildBundle({ fields, files, kind: urlKind });
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
