/**
 * Patches node_modules/ssh2 so it can run inside workerd (Cloudflare Workers).
 *
 * Two upstream blockers:
 *
 * 1. `lib/protocol/crypto.js` eagerly instantiates a base64-embedded WASM module
 *    for poly1305 at module load. workerd forbids dynamic `WebAssembly.instantiate`,
 *    so importing ssh2 at all throws:
 *      "Wasm code generation disallowed by embedder"
 *    Fix: make poly1305 lazy — it is only needed by chacha20-poly1305, which we
 *    never negotiate on Workers (see SSH_ALGORITHMS in src/ssh/session.ts).
 *
 * 2. `lib/protocol/constants.js` does `require('cpu-features')` inside a try/catch.
 *    Bundlers statically resolve that require and then choke on the `.node` binary.
 *    Fix: drop the native binding; it only tunes curve25519 throughput.
 *
 * Also guards canUseCipher/canUseMAC against unknown algorithm names.
 *
 * Idempotent: safe to run multiple times.
 */
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const ssh2 = join(root, "node_modules", "ssh2");
const cryptoPath = join(ssh2, "lib", "protocol", "crypto.js");
const constantsPath = join(ssh2, "lib", "protocol", "constants.js");

if (!existsSync(cryptoPath)) {
	console.error(`[patch-ssh2] ssh2 not installed at ${ssh2} — nothing to do`);
	process.exit(0);
}

let changed = 0;

// ---- 1. lazy poly1305 -------------------------------------------------------
let cryptoSource = readFileSync(cryptoPath, "utf8");
const eagerPoly = `  init: (() => {
    // eslint-disable-next-line no-async-promise-executor
    return new Promise(async (resolve, reject) => {
      try {
        POLY1305_WASM_MODULE = await require('./crypto/poly1305.js')();
        POLY1305_RESULT_MALLOC = POLY1305_WASM_MODULE._malloc(16);
        poly1305_auth = POLY1305_WASM_MODULE.cwrap(
          'poly1305_auth',
          null,
          ['number', 'array', 'number', 'array', 'number', 'array']
        );
      } catch (ex) {
        return reject(ex);
      }
      resolve();
    });
  })(),`;

const lazyPoly = `  init: (() => {
    // PATCHED for workerd: the poly1305 WASM module cannot be instantiated
    // (dynamic WebAssembly is disallowed), and retrying it on every connection
    // leaks memory until the isolate OOMs. chacha20-poly1305 is never
    // negotiated here (see ALGORITHMS.cipher), so the module is not needed.
    return Promise.resolve();
  })(),`;

if (cryptoSource.includes(eagerPoly)) {
	cryptoSource = cryptoSource.replace(eagerPoly, lazyPoly);
	changed++;
} else if (!cryptoSource.includes("PATCHED for workerd")) {
	console.warn("[patch-ssh2] WARN: poly1305 init block not matched (ssh2 version changed?)");
}

// Guard the poly1305 call sites so an unavailable module gives a clear error
// instead of "poly1305_auth is not a function". Normalize first so re-running
// the patch does not stack guards.
const guard = (ws) =>
	`${ws}if (typeof poly1305_auth !== 'function')\n${ws}  throw new Error('chacha20-poly1305 is not available on this runtime');`;
const guardRe = /\s+if \(typeof poly1305_auth !== 'function'\)\s+throw new Error\('chacha20-poly1305 is not available on this runtime'\);/g;
const callRe = /([ \t]*)poly1305_auth\(/g;
cryptoSource = cryptoSource
	.replace(guardRe, "")
	.replace(callRe, (match, ws) => `${guard(ws)}\n${ws}poly1305_auth(`);

writeFileSync(cryptoPath, cryptoSource);

// ---- 2. drop the native cpu-features binding ------------------------------
let constantsSource = readFileSync(constantsPath, "utf8");
const cpuBlock = `let cpuInfo;
try {
  cpuInfo = require('cpu-features')();
} catch {}`;
const cpuReplacement = `// PATCHED for workerd: no native cpu-features binding.
const cpuInfo = undefined;`;

if (constantsSource.includes(cpuBlock)) {
	constantsSource = constantsSource.replace(cpuBlock, cpuReplacement);
	changed++;
} else if (!constantsSource.includes("PATCHED for workerd")) {
	console.warn("[patch-ssh2] WARN: cpu-features block not matched (ssh2 version changed?)");
}

// ---- 3. tolerate unknown algorithm names ----------------------------------
constantsSource = constantsSource
	.replace(
		"return (name) => ciphers.includes(CIPHER_INFO[name].sslName);",
		"return (name) => {\n    const info = CIPHER_INFO[name];\n    return !!info && ciphers.includes(info.sslName);\n  };",
	)
	.replace(
		"return (name) => hashes.includes(MAC_INFO[name].sslName);",
		"return (name) => {\n    const info = MAC_INFO[name];\n    return !!info && hashes.includes(info.sslName);\n  };",
	);

writeFileSync(constantsPath, constantsSource);


// ---- 4. ESM-safe __dirname (ssh2/lib/agent.js) ------------------------------
// The bundle is ESM, so `__dirname` is undefined at module scope. This is only
// used to locate Pageant on Windows, which workerd never runs.
const agentPath = join(ssh2, "lib", "agent.js");
let agentSource = readFileSync(agentPath, "utf8");
const before = agentSource;
agentSource = agentSource.replace(
	/const EXEPATH = resolve\(__dirname, '\.\.', 'util\/pagent\.exe'\);/,
	"const EXEPATH = '/util/pagent.exe'; // PATCHED for workerd (no __dirname in ESM)",
);
if (agentSource === before) {
	console.warn("[patch-ssh2] WARN: agent.js __dirname block not matched");
} else {
	changed++;
}
writeFileSync(agentPath, agentSource);


// ---- 5. use the real node:crypto, not the unenv shim ------------------------
// Wrangler bundles bare `require('crypto')` to unenv's WebCrypto-backed shim,
// which is missing `crypto.diffieHellman` (removed in the shim). ssh2 gates
// curve25519 support on it, so without this every key exchange is rejected.
// Pointing at `node:crypto` gives the runtime's real implementation.
import { readdirSync, statSync } from "node:fs";

function walk(dir) {
	const out = [];
	for (const entry of readdirSync(dir)) {
		const full = join(dir, entry);
		if (statSync(full).isDirectory()) out.push(...walk(full));
		else if (full.endsWith(".js")) out.push(full);
	}
	return out;
}

let cryptoRewrites = 0;
for (const file of walk(join(ssh2, "lib"))) {
	const source = readFileSync(file, "utf8");
	if (!/require\(['"]crypto['"]\)/.test(source)) continue;
	const next = source.replace(/require\(['"]crypto['"]\)/g, 'require("node:crypto")');
	cryptoRewrites += (source.match(/require\(['"]crypto['"]\)/g) || []).length;
	writeFileSync(file, next);
}
if (cryptoRewrites > 0) changed += cryptoRewrites;

console.log(`[patch-ssh2] applied (${changed} primary patch${changed === 1 ? "" : "es"})`);
