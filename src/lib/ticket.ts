/**
 * Short-lived session tickets.
 *
 * The Worker verifies the Cloudflare Access JWT on every request. For the
 * WebSocket upgrade it then mints a ticket that the Durable Object can verify
 * without re-fetching Access JWKS over the network.
 *
 * Format: base64url(json payload) + "." + base64url(HMAC-SHA256)
 */
import { base64ToBytes, base64UrlToBytes, bytesToBase64Url, utf8Bytes, utf8String } from "./encoding.js";
import type { SessionTicketPayload } from "../types.js";

const TICKET_TTL_SECONDS = 60;

async function hmacKey(secret: string | undefined): Promise<CryptoKey> {
	if (!secret) throw new Error("APP_SECRET is not configured");
	const raw = base64ToBytes(secret.trim());
	if (raw.length !== 32) throw new Error("APP_SECRET must be a base64-encoded 32-byte key");
	return crypto.subtle.importKey("raw", raw, { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}

export async function mintTicket(
	secret: string | undefined,
	serverId: string,
	email: string,
	sessionId?: string,
): Promise<{ ticket: string; expiresAt: number }> {
	const expiresAt = Math.floor(Date.now() / 1000) + TICKET_TTL_SECONDS;
	const payload: SessionTicketPayload = { s: serverId, e: email, x: expiresAt, d: sessionId };
	const payloadB64 = bytesToBase64Url(utf8Bytes(JSON.stringify(payload)));
	const signature = await crypto.subtle.sign("HMAC", await hmacKey(secret), utf8Bytes(payloadB64));
	return { ticket: `${payloadB64}.${bytesToBase64Url(new Uint8Array(signature))}`, expiresAt };
}

export async function verifyTicket(secret: string | undefined, ticket: string): Promise<SessionTicketPayload> {
	const [payloadB64, signatureB64] = ticket.split(".");
	if (!payloadB64 || !signatureB64) throw new Error("malformed session ticket");

	const valid = await crypto.subtle.verify(
		"HMAC",
		await hmacKey(secret),
		base64UrlToBytes(signatureB64),
		utf8Bytes(payloadB64),
	);
	if (!valid) throw new Error("bad session ticket signature");

	const payload = JSON.parse(utf8String(base64UrlToBytes(payloadB64))) as SessionTicketPayload;
	if (typeof payload.s !== "string" || typeof payload.e !== "string" || typeof payload.x !== "number") {
		throw new Error("malformed session ticket payload");
	}
	if (payload.x < Math.floor(Date.now() / 1000)) throw new Error("session ticket expired");
	return payload;
}
