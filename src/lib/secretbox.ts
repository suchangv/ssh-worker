/**
 * Envelope encryption for SSH credentials stored in KV.
 *
 * Key: 32 bytes from APP_SECRET (base64). Cipher: AES-256-GCM.
 * Format: "v1." + base64url(iv[12] || ciphertext)
 */
import { base64ToBytes, base64UrlToBytes, bytesToBase64Url, concatBytes, utf8Bytes, utf8String } from "./encoding.js";

const VERSION = "v1";

async function importKey(secret: string | undefined): Promise<CryptoKey> {
	if (!secret) {
		throw new Error("APP_SECRET is not configured: refusing to touch encrypted credentials");
	}
	const raw = base64ToBytes(secret.trim());
	if (raw.length !== 32) {
		throw new Error("APP_SECRET must be a base64-encoded 32-byte key (openssl rand -base64 32)");
	}
	return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

export async function seal(secret: string | undefined, plaintext: string): Promise<string> {
	const key = await importKey(secret);
	const iv = crypto.getRandomValues(new Uint8Array(12));
	const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, utf8Bytes(plaintext));
	return `${VERSION}.${bytesToBase64Url(concatBytes(iv, new Uint8Array(ciphertext)))}`;
}

export async function open(secret: string | undefined, sealed: string): Promise<string> {
	const [version, payload] = sealed.split(".");
	if (version !== VERSION || !payload) throw new Error("unsupported secret envelope");
	const raw = base64UrlToBytes(payload);
	const iv = raw.slice(0, 12);
	const body = raw.slice(12);
	const key = await importKey(secret);
	const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, body);
	return utf8String(new Uint8Array(plaintext));
}
