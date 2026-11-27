// Client-side photo downscaling for the insurance-card bundle flow.
//
// Six card photos at full phone resolution can push a bundle past
// the Gmail delivery limit, so in the bundle flow ONLY, each photo
// is downscaled in the browser before bundling: drawn to a canvas
// at max dimension 2048 px and re-encoded as JPEG quality 0.85. A
// small PNG keeps its original bytes (screenshots of text stay
// crisp); everything else becomes JPEG. A full 3-plan bundle then
// lands comfortably under 18 MB.
//
// planPhotoConversion is the pure decision (unit-tested in Node via
// test/image_downscale_test.mjs); downscalePhotoFile is the browser
// implementation. Any decode/encode failure falls back to the
// original bytes — a photo that can't be downscaled still sends.

export const MAX_PHOTO_DIM = 2048;
export const JPEG_QUALITY = 0.85;
export const SMALL_PNG_BYTES = 512 * 1024;

/**
 * Decide what to do with one photo.
 * Input: { type, size, width, height } (width/height may be 0 when
 * unknown). Returns { action: 'keep' } or
 * { action: 'jpeg', quality, targetWidth, targetHeight }.
 */
export function planPhotoConversion({ type, size, width, height }) {
  if (type === 'image/png' && size <= SMALL_PNG_BYTES) return { action: 'keep' };
  const w = width || 0;
  const h = height || 0;
  const scale = w && h ? Math.min(1, MAX_PHOTO_DIM / Math.max(w, h)) : 1;
  return {
    action: 'jpeg',
    quality: JPEG_QUALITY,
    targetWidth: w ? Math.max(1, Math.round(w * scale)) : null,
    targetHeight: h ? Math.max(1, Math.round(h * scale)) : null,
  };
}

function jpegName(name) {
  const base = String(name ?? 'photo').replace(/\.[A-Za-z0-9]{1,8}$/, '');
  return `${base || 'photo'}.jpg`;
}

/**
 * Browser: downscale one picked photo file per planPhotoConversion.
 * Returns { bytes: Uint8Array, name, converted } — `name` gains a
 * .jpg extension when the bytes were re-encoded.
 */
export async function downscalePhotoFile(file) {
  const origBytes = new Uint8Array(await file.arrayBuffer());
  const keep = { bytes: origBytes, name: file.name, converted: false };
  let bitmap = null;
  try {
    bitmap = await createImageBitmap(file);
  } catch {
    return keep; // undecodable here (e.g. HEIC in some browsers) — send as-is
  }
  try {
    const plan = planPhotoConversion({
      type: file.type, size: file.size, width: bitmap.width, height: bitmap.height,
    });
    if (plan.action === 'keep') return keep;
    if (file.type === 'image/jpeg' &&
        plan.targetWidth === bitmap.width && plan.targetHeight === bitmap.height) {
      return keep; // already a JPEG within bounds — don't re-encode
    }
    const canvas = document.createElement('canvas');
    canvas.width = plan.targetWidth ?? bitmap.width;
    canvas.height = plan.targetHeight ?? bitmap.height;
    const ctx = canvas.getContext('2d');
    if (!ctx) return keep;
    ctx.drawImage(bitmap, 0, 0, canvas.width, canvas.height);
    const blob = await new Promise((resolveP) => canvas.toBlob(resolveP, 'image/jpeg', plan.quality));
    if (!blob) return keep;
    return {
      bytes: new Uint8Array(await blob.arrayBuffer()),
      name: jpegName(file.name),
      converted: true,
    };
  } catch {
    return keep;
  } finally {
    if (bitmap && typeof bitmap.close === 'function') bitmap.close();
  }
}
