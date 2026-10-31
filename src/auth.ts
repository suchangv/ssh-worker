/**
 * Cloudflare Access (Zero Trust) verification.
 *
 * Access puts a signed JWT in `Cf-Access-Jwt-Assertion` (header) and in the
 * `CF_Authorization` cookie. Both are the same RS256 token; we accept either so
 * WebSocket upgrades and fetches behave the same.
 *
 * We verify locally against the team's JWKS instead of trusting the header name,
 * so a misconfigured route (or a removed Access application) fails closed.
 */
import { base64UrlToBytes, utf8String } from "./lib/encoding.js";
import type { Env } from "./types.js";

export interface AclUser {
	email: string;
	devBypass: boolean;
}

export class AuthError extends Error {
	constructor(
		message: string,
		readonly status = 403,
	) {
		super(message);
	}
}

interface Jwk extends JsonWebKey {
	kid?: string;
}

interface JwksCacheEntry {
	keys: Jwk[];
	fetchedAt: number;
}

const JWKS_TTL_MS = 10 * 60 * 1000;
let jwksCache: JwksCacheEntry | undefined;

function teamDomain(env: Env): string {
	return (env.ACCESS_TEAM_DOMAIN || "").replace(/^https?:\/\//, "").replace(/\/+$/, "");
}

function tokenFromRequest(request: Request): string | undefined {
	const header = request.headers.get("Cf-Access-Jwt-Assertion");
	if (header) return header;

	const cookie = request.headers.get("Cookie");
	if (!cookie) return undefined;
	for (const part of cookie.split(";")) {
		const [name, ...rest] = part.trim().split("=");
		if (name === "CF_Authorization") return rest.join("=");
	}
	return undefined;
}

async function fetchJwks(domain: string): Promise<Jwk[]> {
	const now = Date.now();
	if (jwksCache && now - jwksCache.fetchedAt < JWKS_TTL_MS) return jwksCache.keys;

	const response = await fetch(`https://${domain}/cdn-cgi/access/certs`, {
		cf: { cacheTtl: 300, cacheEverything: true },
	});
	if (!response.ok) throw new AuthError(`could not load Access JWKS (${response.status})`, 502);

	const body = (await response.json()) as { keys?: Jwk[] };
	const keys = (body.keys || []).filter((key) => key.kty === "RSA");
	if (keys.length === 0) throw new AuthError("Access JWKS contained no RSA keys", 502);

	jwksCache = { keys, fetchedAt: now };
	return keys;
}

export async function authenticate(request: Request, env: Env): Promise<AclUser> {
	const url = new URL(request.url);

	// Local development escape hatch. `wrangler dev` rewrites the request host to
	// the Worker's custom domain, so the host name cannot prove locality. Cloudflare
	// always stamps `cf-ray` on edge requests and workerd never does locally, so a
	// request that reached the edge can never take this branch. The flag itself is
	// only ever set in .dev.vars, never in a deploy config.
	const fromEdge = request.headers.has("cf-ray");
	if ((env.DEV_AUTH_BYPASS || "").toLowerCase() === "true" && !fromEdge) {
		return { email: "dev@localhost", devBypass: true };
	}

	const domain = teamDomain(env);
	if (!domain || !env.ACCESS_AUD) {
		throw new AuthError("ACCESS_TEAM_DOMAIN / ACCESS_AUD are not configured", 500);
	}

	const token = tokenFromRequest(request);
	if (!token) throw new AuthError("missing Cloudflare Access token", 401);

	const [headerB64, payloadB64, signatureB64] = token.split(".");
	if (!headerB64 || !payloadB64 || !signatureB64) throw new AuthError("malformed Access token", 401);

	let header: { alg?: string; kid?: string };
	try {
		header = JSON.parse(utf8String(base64UrlToBytes(headerB64)));
	} catch {
		throw new AuthError("malformed Access token header", 401);
	}
	if (header.alg !== "RS256") throw new AuthError("unexpected Access token algorithm", 401);

	const keys = await fetchJwks(domain);
	const candidates = header.kid ? keys.filter((key) => key.kid === header.kid) : keys;
	if (candidates.length === 0) throw new AuthError("no matching Access signing key", 401);

	const signedData = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
	const signature = base64UrlToBytes(signatureB64);

	let verified = false;
	for (const jwk of candidates) {
		const key = await crypto.subtle.importKey(
			"jwk",
			{ kty: jwk.kty, n: jwk.n, e: jwk.e } as JsonWebKey,
			{ name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
			false,
			["verify"],
		);
		if (await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, signature, signedData)) {
			verified = true;
			break;
		}
	}
	if (!verified) throw new AuthError("invalid Access token signature", 401);

	let claims: {
		email?: string;
		common_name?: string;
		aud?: string | string[];
		iss?: string;
		exp?: number;
		nbf?: number;
		sub?: string;
	};
	try {
		claims = JSON.parse(utf8String(base64UrlToBytes(payloadB64)));
	} catch {
		throw new AuthError("malformed Access token payload", 401);
	}

	const now = Math.floor(Date.now() / 1000);
	if (typeof claims.exp !== "number" || claims.exp < now - 30) throw new AuthError("Access token expired", 401);
	if (typeof claims.nbf === "number" && claims.nbf > now + 30) throw new AuthError("Access token not yet valid", 401);

	const audiences = Array.isArray(claims.aud) ? claims.aud : claims.aud ? [claims.aud] : [];
	if (!audiences.includes(env.ACCESS_AUD)) throw new AuthError("Access token audience mismatch", 403);

	const expectedIss = `https://${domain}`;
	if (claims.iss && claims.iss !== expectedIss) throw new AuthError("Access token issuer mismatch", 403);

	// Access service tokens carry `common_name` instead of `email`. They are only
	// issued because an operator attached the token to this application's policy,
	// so they bypass the email allowlist but are still audited as "service:<id>".
	const serviceName = (claims.common_name || "").trim();
	const email = (claims.email || "").trim().toLowerCase();
	if (!email && !serviceName) throw new AuthError("Access token has no subject", 403);
	if (serviceName && !email) return { email: `service:${serviceName}`, devBypass: false };

	const allowlist = (env.ALLOWED_EMAILS || "")
		.split(",")
		.map((entry) => entry.trim().toLowerCase())
		.filter(Boolean);
	if (allowlist.length > 0 && !allowlist.includes(email)) {
		throw new AuthError(`access denied for ${email}`, 403);
	}

	return { email, devBypass: false };
}
