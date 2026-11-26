// Shared encryption logic — the SINGLE code path used by both the browser
// upload page (upload-page/app.js) and the Node end-to-end test
// (test/e2e_test.mjs). The `openpgp` argument is injected so the browser can
// pass the vendored bundle (upload-page/vendor/openpgp.min.mjs) and Node can
// pass the npm package; the logic is identical either way.

export async function sha256Hex(bytes) {
  const digest = await globalThis.crypto.subtle.digest('SHA-256', bytes);
  return [...new Uint8Array(digest)]
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Encrypt a document in the browser/harness with the office public key.
 * Returns { ciphertext: Uint8Array, manifest: object }.
 * The manifest is the POC's stand-in for the email metadata: it travels
 * alongside the .pgp file (in production, as email headers/body fields).
 */
export async function encryptDocument(openpgp, publicKeyArmored, {
  uploadCode,
  patientName,
  originalFilename,
  fileBytes,
}) {
  if (!uploadCode || !patientName || !originalFilename || !fileBytes) {
    throw new Error('uploadCode, patientName, originalFilename and fileBytes are all required');
  }
  const sha256 = await sha256Hex(fileBytes);
  const publicKey = await openpgp.readKey({ armoredKey: publicKeyArmored });
  const message = await openpgp.createMessage({ binary: fileBytes, filename: originalFilename });
  const ciphertext = await openpgp.encrypt({
    message,
    encryptionKeys: publicKey,
    format: 'binary',
  });
  const manifest = {
    version: 1,
    kind: 'secure-doc-upload-poc',
    uploadCode,
    patientName,
    originalFilename,
    sha256,
    sizeBytes: fileBytes.length,
    createdAt: new Date().toISOString(),
  };
  return { ciphertext: new Uint8Array(ciphertext), manifest };
}
