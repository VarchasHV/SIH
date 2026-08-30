// Pixel-space redaction on a canvas. Used in the offscreen document to sanitize
// the screenshot before it is sent to the server.
//
// ALL redaction uses solid black boxes for maximum privacy. No blur or pixelate.
//
// A region is { x, y, w, h, category, mode? } in *canvas pixels*.

function clampRegion(r, W, H) {
  const x = Math.max(0, Math.min(W, Math.floor(r.x)));
  const y = Math.max(0, Math.min(H, Math.floor(r.y)));
  const w = Math.max(1, Math.min(W - x, Math.ceil(r.w)));
  const h = Math.max(1, Math.min(H - y, Math.ceil(r.h)));
  return { x, y, w, h };
}

function blackoutRegion(ctx, r) {
  ctx.save();
  ctx.fillStyle = "#0a0a0a";
  ctx.fillRect(r.x, r.y, r.w, r.h);
  ctx.restore();
}

/**
 * Apply blackout redaction in place. All regions are censored with solid
 * black boxes regardless of category.
 * @param {OffscreenCanvas|HTMLCanvasElement} canvas
 * @param {Array} regions
 * @param {{pad?: number}} opts
 * @returns {{count:number, regions:Array}}
 */
export function redactCanvas(canvas, regions, opts = {}) {
  const { pad = 3 } = opts;
  const ctx = canvas.getContext("2d");
  const W = canvas.width;
  const H = canvas.height;
  const applied = [];
  for (const raw of regions || []) {
    const padded = { x: raw.x - pad, y: raw.y - pad, w: raw.w + pad * 2, h: raw.h + pad * 2 };
    const r = clampRegion(padded, W, H);
    if (r.w < 2 || r.h < 2) continue;
    blackoutRegion(ctx, r);
    applied.push({ ...r, category: raw.category, mode: "blackout" });
  }
  return { count: applied.length, regions: applied };
}

/** Fraction of PII pixels still recoverable = leak proxy (for the eval harness). */
export function leakScore(originalCanvas, redactedCanvas, regions) {
  const a = originalCanvas.getContext("2d");
  const b = redactedCanvas.getContext("2d");
  let changed = 0;
  let total = 0;
  for (const r of regions) {
    const rr = clampRegion(r, originalCanvas.width, originalCanvas.height);
    const da = a.getImageData(rr.x, rr.y, rr.w, rr.h).data;
    const db = b.getImageData(rr.x, rr.y, rr.w, rr.h).data;
    for (let i = 0; i < da.length; i += 4) {
      total++;
      if (Math.abs(da[i] - db[i]) + Math.abs(da[i + 1] - db[i + 1]) + Math.abs(da[i + 2] - db[i + 2]) > 24) changed++;
    }
  }
  return total ? 1 - changed / total : 0;
}

export default { redactCanvas, leakScore };
