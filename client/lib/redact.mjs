// Pixel-space redaction on a canvas. Used in the offscreen document to sanitize
// the screenshot before it is sent to the server.
//
// ALL redactions use solid black boxes for maximum privacy.
// In addition to the input field itself, adjacent label text to the left
// is also blacked out so VLMs cannot read the labels.

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
 * Apply blackout redaction in place. All sensitive regions and their adjacent
 * leftward label zones are censored with solid black boxes.
 * @param {OffscreenCanvas|HTMLCanvasElement} canvas
 * @param {Array} regions
 * @param {{pad?: number, labelOffset?: number}} opts
 * @returns {{count:number, regions:Array}}
 */
export function redactCanvas(canvas, regions, opts = {}) {
  const { pad = 4, labelOffset = 250 } = opts;
  const ctx = canvas.getContext("2d");
  const W = canvas.width;
  const H = canvas.height;
  const applied = [];
  for (const raw of regions || []) {
    // 1. Black out the input / detection region
    const padded = { x: raw.x - pad, y: raw.y - pad, w: raw.w + pad * 2, h: raw.h + pad * 2 };
    const r = clampRegion(padded, W, H);
    if (r.w < 2 || r.h < 2) continue;
    blackoutRegion(ctx, r);

    // 2. Black out the adjacent text label area to the left
    const labelRegion = clampRegion({
      x: Math.max(0, raw.x - labelOffset),
      y: raw.y - pad,
      w: Math.min(raw.x, labelOffset) + pad,
      h: raw.h + pad * 2,
    }, W, H);
    if (labelRegion.w > 2 && labelRegion.h > 2) {
      blackoutRegion(ctx, labelRegion);
      applied.push({ ...labelRegion, category: `${raw.category}_label`, mode: "blackout" });
    }

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
