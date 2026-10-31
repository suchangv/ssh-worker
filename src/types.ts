export interface Env {
	/** KV namespace holding encrypted server records. */
	SERVERS: KVNamespace;
	/** One Durable Object instance per SSH session. */
	SSH_SESSION: DurableObjectNamespace;
	/** Static UI assets (public/). */
	ASSETS: Fetcher;
	/** Base64-encoded 32-byte master key used to encrypt credentials at rest. */
	APP_SECRET?: string;
	/** e.g. "myteam.cloudflareaccess.com" */
	ACCESS_TEAM_DOMAIN?: string;
	/** Access application Audience (AUD) tag. */
	ACCESS_AUD?: string;
	/** Optional comma-separated allowlist of emails. Empty = any Access user. */
	ALLOWED_EMAILS?: string;
	/** "true" skips Access verification — only honored for localhost requests. */
	DEV_AUTH_BYPASS?: string;
}

export type AuthType = "password" | "key";

/** Stored shape. `secret`/`passphrase` are AES-GCM sealed. */
export interface ServerRecord {
	id: string;
	name: string;
	host: string;
	port: number;
	username: string;
	authType: AuthType;
	secret?: string;
	passphrase?: string;
	note?: string;
	/** Manual expiry date, `yyyy-MM-dd`. */
	expiresOn?: string;
	createdAt: number;
	updatedAt: number;
	lastUsedAt?: number;
	createdBy?: string;
}

/** What the browser sees. No secrets, ever. */
export interface PublicServer {
	id: string;
	name: string;
	host: string;
	port: number;
	username: string;
	authType: AuthType;
	note?: string;
	expiresOn?: string;
	hasSecret: boolean;
	hasPassphrase: boolean;
	hostKeyPinned: boolean;
	createdAt: number;
	updatedAt: number;
	lastUsedAt?: number;
}

export interface SessionTicketPayload {
	/** server id */
	s: string;
	/** email */
	e: string;
	/** expiry, unix seconds */
	x: number;
	/** Durable Object / session id, so file requests reach the live SSH session */
	d?: string;
}
