/**
 * Cache-busts the UI assets in public/index.html.
 *
 * `index.html` is served with `Cache-Control: no-store`, but `app.js` / `styles.css`
 * are revalidated with ETags — some proxies (and Safari's back/forward cache)
 * still hand back an old copy for a while. Stamping a content hash onto the URLs
 * makes stale mixes impossible.
 *
 * Idempotent: running it twice with unchanged sources produces the same output.
 */
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const htmlPath = join(root, "public", "index.html");

const hash = (...files) => {
	const h = createHash("sha256");
	for (const file of files) h.update(readFileSync(join(root, "public", file)));
	return h.digest("hex").slice(0, 10);
};

const jsVersion = hash("app.js");
const cssVersion = hash("styles.css");

let html = readFileSync(htmlPath, "utf8");
const before = html;
html = html
	.replace(/href="\/styles\.css(?:\?v=[^"]*)?"/, `href="/styles.css?v=${cssVersion}"`)
	.replace(/src="\/app\.js(?:\?v=[^"]*)?"/, `src="/app.js?v=${jsVersion}"`);

if (html !== before) writeFileSync(htmlPath, html);
console.log(`[stamp-assets] app.js?v=${jsVersion} styles.css?v=${cssVersion}${html === before ? " (unchanged)" : ""}`);
