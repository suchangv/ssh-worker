/**
 * Server inventory: the only persistent state.
 *
 * Records live in KV under `server:<id>`; the SSH host key pin lives under
 * `hostkey:<id>` so it can be rotated independently of the credentials.
 */
import { open, seal } from "./lib/secretbox.js";
import type { AuthType, Env, PublicServer, ServerRecord } from "./types.js";

const MAX_NAME = 64;
const MAX_HOST = 253;
const MAX_USER = 64;
const MAX_NOTE = 500;
const MAX_SECRET = 16 * 1024;

export class ValidationError extends Error {}

function text(value: unknown, field: string, max: number, required = true): string {
	if (typeof value !== "string") {
		if (!required && (value === undefined || value === null)) return "";
		throw new ValidationError(`${field} must be a string`);
	}
	const trimmed = value.trim();
	if (required && trimmed.length === 0) throw new ValidationError(`${field} is required`);
	if (trimmed.length > max) throw new ValidationError(`${field} is longer than ${max} characters`);
	if (/[\u0000-\u001f\u007f]/.test(trimmed)) throw new ValidationError(`${field} contains control characters`);
	return trimmed;
}

/** Hostname or IP literal. Rejects anything that could confuse the socket API. */
export function parseHost(value: unknown): string {
	const host = text(value, "host", MAX_HOST).toLowerCase();
	if (!/^[a-z0-9._:%-]+$/.test(host)) throw new ValidationError("host may only contain letters, digits, dots, dashes, colons and %");
	if (host.includes("/") || host.startsWith("-") || host.endsWith("-")) throw new ValidationError("invalid host");
	if (host.includes("..")) throw new ValidationError("invalid host");
	return host;
}

export function parsePort(value: unknown): number {
	const port = typeof value === "string" ? Number(value) : value;
	if (typeof port !== "number" || !Number.isInteger(port) || port < 1 || port > 65535) {
		throw new ValidationError("port must be an integer between 1 and 65535");
	}
	return port;
}

/**
 * Optional manual expiry date. Text only (`yyyy-MM-dd`) — no picker, no timezone
 * math on the server: it is stored and compared as a plain calendar day.
 */
export function parseExpiresOn(value: unknown): string | undefined {
	if (value === undefined || value === null) return undefined;
	if (typeof value !== "string") throw new ValidationError("expiresOn must be a string");
	const text = value.trim();
	if (text === "") return undefined;
	if (!/^\d{4}-\d{2}-\d{2}$/.test(text)) throw new ValidationError("到期时间格式必须是 yyyy-MM-dd");
	const [year, month, day] = text.split("-").map(Number);
	const date = new Date(Date.UTC(year, month - 1, day));
	if (date.getUTCFullYear() !== year || date.getUTCMonth() !== month - 1 || date.getUTCDate() !== day) {
		throw new ValidationError("到期时间不是有效日期");
	}
	if (year < 2000 || year > 2100) throw new ValidationError("到期时间年份需要在 2000-2100 之间");
	return text;
}

export function parseAuthType(value: unknown): AuthType {
	if (value === "password" || value === "key") return value;
	throw new ValidationError("authType must be 'password' or 'key'");
}

function recordKey(id: string): string {
	return `server:${id}`;
}

function hostKeyKey(id: string): string {
	return `hostkey:${id}`;
}

export function newServerId(): string {
	const bytes = crypto.getRandomValues(new Uint8Array(9));
	return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function toPublic(record: ServerRecord, hostKeyPinned: boolean): PublicServer {
	return {
		id: record.id,
		name: record.name,
		host: record.host,
		port: record.port,
		username: record.username,
		authType: record.authType,
		note: record.note,
		expiresOn: record.expiresOn,
		hasSecret: Boolean(record.secret),
		hasPassphrase: Boolean(record.passphrase),
		hostKeyPinned,
		createdAt: record.createdAt,
		updatedAt: record.updatedAt,
		lastUsedAt: record.lastUsedAt,
	};
}

export interface ServerInput {
	name: string;
	host: string;
	port: number;
	username: string;
	authType: AuthType;
	note?: string;
	expiresOn?: string;
	/** Plaintext password or private key. Omit to keep the stored one. */
	credential?: string;
	passphrase?: string;
}

export function parseServerInput(body: unknown): ServerInput {
	if (!body || typeof body !== "object") throw new ValidationError("body must be a JSON object");
	const raw = body as Record<string, unknown>;

	const username = text(raw.username, "username", MAX_USER);
	if (!/^[A-Za-z0-9._@\\-]+$/.test(username)) throw new ValidationError("username contains unsupported characters");

	const credential = typeof raw.credential === "string" ? raw.credential : undefined;
	if (credential !== undefined) {
		if (credential.length === 0) throw new ValidationError("credential must not be empty");
		if (credential.length > MAX_SECRET) throw new ValidationError("credential is too large (16 KiB max)");
	}

	const passphrase = typeof raw.passphrase === "string" && raw.passphrase.length > 0 ? raw.passphrase : undefined;
	if (passphrase && passphrase.length > MAX_SECRET) throw new ValidationError("passphrase is too large");

	return {
		name: text(raw.name, "name", MAX_NAME),
		host: parseHost(raw.host),
		port: parsePort(raw.port ?? 22),
		username,
		authType: parseAuthType(raw.authType),
		note: raw.note === undefined ? undefined : text(raw.note, "note", MAX_NOTE, false),
		expiresOn: parseExpiresOn(raw.expiresOn),
		credential,
		passphrase,
	};
}

export async function listServers(env: Env): Promise<PublicServer[]> {
	const listing = await env.SERVERS.list({ prefix: "server:" });
	const records = await Promise.all(
		listing.keys.map(async (key) => {
			const record = await env.SERVERS.get<ServerRecord>(key.name, "json");
			if (!record) return undefined;
			const hostKey = await env.SERVERS.get(hostKeyKey(record.id));
			return toPublic(record, Boolean(hostKey));
		}),
	);
	return records
		.filter((record): record is PublicServer => Boolean(record))
		.sort((a, b) => a.name.localeCompare(b.name));
}

export async function getServer(env: Env, id: string): Promise<ServerRecord | undefined> {
	return (await env.SERVERS.get<ServerRecord>(recordKey(id), "json")) ?? undefined;
}

export async function putServer(env: Env, record: ServerRecord): Promise<void> {
	await env.SERVERS.put(recordKey(record.id), JSON.stringify(record));
}

export async function deleteServer(env: Env, id: string): Promise<void> {
	await env.SERVERS.delete(recordKey(id));
	await env.SERVERS.delete(hostKeyKey(id));
}

export async function getPinnedHostKey(env: Env, id: string): Promise<string | undefined> {
	return (await env.SERVERS.get(hostKeyKey(id))) ?? undefined;
}

export async function pinHostKey(env: Env, id: string, fingerprint: string): Promise<void> {
	await env.SERVERS.put(hostKeyKey(id), fingerprint);
}

export async function createServer(env: Env, input: ServerInput, email: string): Promise<PublicServer> {
	const now = Date.now();
	const record: ServerRecord = {
		id: newServerId(),
		name: input.name,
		host: input.host,
		port: input.port,
		username: input.username,
		authType: input.authType,
		note: input.note,
		expiresOn: input.expiresOn,
		createdAt: now,
		updatedAt: now,
		createdBy: email,
	};
	if (input.credential) record.secret = await seal(env.APP_SECRET, input.credential);
	if (input.passphrase) record.passphrase = await seal(env.APP_SECRET, input.passphrase);
	await putServer(env, record);
	return toPublic(record, false);
}

export async function updateServer(
	env: Env,
	existing: ServerRecord,
	input: ServerInput,
): Promise<PublicServer> {
	const record: ServerRecord = {
		...existing,
		name: input.name,
		host: input.host,
		port: input.port,
		username: input.username,
		authType: input.authType,
		note: input.note,
		expiresOn: input.expiresOn, // undefined clears it
		updatedAt: Date.now(),
	};
	if (input.credential) record.secret = await seal(env.APP_SECRET, input.credential);
	if (input.passphrase !== undefined) record.passphrase = await seal(env.APP_SECRET, input.passphrase);
	if (input.authType !== existing.authType) {
		// Credentials are auth-type specific; a stale secret is worse than a missing one.
		record.secret = input.credential ? await seal(env.APP_SECRET, input.credential) : undefined;
		record.passphrase = undefined;
	}
	await putServer(env, record);
	const hostKey = await getPinnedHostKey(env, record.id);
	return toPublic(record, Boolean(hostKey));
}

/** Decrypts the credentials a Durable Object needs to open a connection. */
export async function resolveCredentials(
	env: Env,
	record: ServerRecord,
): Promise<{ password?: string; privateKey?: string; passphrase?: string }> {
	if (!record.secret) throw new ValidationError("this server has no stored credential");
	const secret = await open(env.APP_SECRET, record.secret);
	const passphrase = record.passphrase ? await open(env.APP_SECRET, record.passphrase) : undefined;
	return record.authType === "key"
		? { privateKey: secret, passphrase }
		: { password: secret };
}

export async function markUsed(env: Env, record: ServerRecord): Promise<void> {
	const updated: ServerRecord = { ...record, lastUsedAt: Date.now() };
	await putServer(env, updated);
}
