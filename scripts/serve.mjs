// Minimal static file server.  Usage: node scripts/serve.mjs <dir> [port]
import { createServer } from "node:http";
import { readFile, stat } from "node:fs/promises";
import { extname, join, normalize, resolve } from "node:path";

const dir = resolve(process.argv[2] || "fixtures");
const port = Number(process.argv[3] || 4173);

const TYPES = {
  ".html": "text/html", ".css": "text/css", ".js": "text/javascript",
  ".mjs": "text/javascript", ".json": "application/json", ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg", ".png": "image/png", ".svg": "image/svg+xml",
  ".wasm": "application/wasm", ".gz": "application/gzip",
};

createServer(async (req, res) => {
  try {
    let p = normalize(decodeURIComponent(req.url.split("?")[0]));
    if (p.endsWith("/")) p += "index.html";
    const file = join(dir, p);
    if (!file.startsWith(dir)) { res.writeHead(403).end("no"); return; }
    const s = await stat(file);
    if (s.isDirectory()) { res.writeHead(302, { Location: p + "/" }).end(); return; }
    const body = await readFile(file);
    res.writeHead(200, { "content-type": TYPES[extname(file)] || "application/octet-stream" });
    res.end(body);
  } catch {
    res.writeHead(404).end("not found");
  }
}).listen(port, () => console.log(`serving ${dir} → http://localhost:${port}/`));
