/**
 * One Durable Object instance per terminal session.
 *
 * - Verifies the ticket minted by the Worker (which already verified Cloudflare Access).
 * - Opens a raw TCP socket to the VPS via `cloudflare:sockets`.
 * - Speaks SSH2 through `ssh2` over that socket (patched to run on workerd).
 * - Bridges the PTY to the browser over a WebSocket.
 */
import { Client } from "ssh2";
import type { SFTPWrapper } from "ssh2";
import { createHash } from "node:crypto";
import type { Duplex } from "node:stream";
import { verifyTicket } from "../lib/ticket.js";
import { getPinnedHostKey, getServer, markUsed, pinHostKey, resolveCredentials } from "../store.js";
import type { Env, ServerRecord } from "../types.js";
import { openTcpStream } from "./tcp.js";
import { explainFailure } from "./diagnostics.js";
import { imageTypeFor, looksBinary } from "./sniff.js";

/**
 * workerd's nodejs_compat rejects ssh2's AES-GCM decrypt sequence ("No auth tag
 * provided", mscdex/ssh2#1494), so we negotiate CTR + EtM only.
 *
 * curve25519-sha256 is deliberately absent: ssh2 gates it on the deprecated
 * `crypto.diffieHellman()`, which workerd's node:crypto does not expose on the
 * default export, so advertising it fails the whole negotiation. Every modern
 * OpenSSH server also offers ecdh-sha2-nistp256.
 */
const ALGORITHMS = {
	kex: [
		"ecdh-sha2-nistp256",
		"ecdh-sha2-nistp384",
		"ecdh-sha2-nistp521",
		"diffie-hellman-group14-sha256",
		"diffie-hellman-group16-sha512",
	],
	cipher: ["aes128-ctr", "aes192-ctr", "aes256-ctr"],
	hmac: [
		"hmac-sha2-256-etm@openssh.com",
		"hmac-sha2-512-etm@openssh.com",
		"hmac-sha2-256",
		"hmac-sha2-512",
	],
	compress: ["none", "zlib@openssh.com"],
	serverHostKey: ["ssh-ed25519", "ecdsa-sha2-nistp256", "rsa-sha2-512", "rsa-sha2-256", "ssh-rsa"],
};

const IDLE_TIMEOUT_MS = 30 * 60 * 1000;
const DEFAULT_COLS = 120;
const DEFAULT_ROWS = 32;

const PROBE_COMMAND = [
	"cat /etc/os-release 2>/dev/null | head -2",
	"uname -srm",
	"uptime",
	"free -m 2>/dev/null | head -2",
	"df -h / 2>/dev/null | tail -1",
	"whoami",
	"hostname",
].join("; ");

export function fingerprintHostKey(key: Uint8Array): string {
	const digest = createHash("sha256").update(Buffer.from(key)).digest("base64").replace(/=+$/, "");
	return `SHA256:${digest}`;
}

function sanitize(message: unknown): string {
	const text = message instanceof Error ? message.message : String(message);
	return text.replace(/[\u0000-\u001f\u007f]/g, " ").slice(0, 400);
}

type ClientMessage =
	| { t: "i"; d: string }
	| { t: "r"; c: number; r: number }
	| { t: "p"; n?: number }
	| { t: "ls"; p: string; n: number };

interface DirEntry {
	name: string;
	path: string;
	type: "dir" | "file";
	link: boolean;
	size: number;
	mtime: number;
}

const MAX_DIR_ENTRIES = 600;
const MAX_TEXT_PREVIEW = 512 * 1024;
const MAX_IMAGE_PREVIEW = 6 * 1024 * 1024;
const MAX_DOWNLOAD = 200 * 1024 * 1024;

function joinPath(base: string, name: string): string {
	return base.endsWith("/") ? base + name : `${base}/${name}`;
}

function normalizePath(path: string): string {
	return path.replace(/\/{2,}/g, "/");
}

export class SshSession {
	private client: Client | undefined;
	private shell: { write(data: string | Uint8Array): void; setWindow(rows: number, cols: number, height: number, width: number): void; end?(): void } | undefined;
	private duplex: Duplex | undefined;
	private socket: WebSocket | undefined;
	private idleTimer: ReturnType<typeof setTimeout> | undefined;
	private sftp: SFTPWrapper | undefined;
	private homePath: string | undefined;
	private disposed = false;
	private cols = DEFAULT_COLS;
	private rows = DEFAULT_ROWS;

	constructor(
		private readonly state: DurableObjectState,
		private readonly env: Env,
	) {}

	async fetch(request: Request): Promise<Response> {
		const url = new URL(request.url);
		if (request.headers.get("x-probe") === "1") return this.handleProbe(request);
		if (request.headers.get("x-file") === "1") return this.handleFile(request);

		if ((request.headers.get("Upgrade") || "").toLowerCase() !== "websocket") {
			return Response.json({ error: "expected a WebSocket upgrade" }, { status: 426 });
		}

		const serverId = request.headers.get("x-server-id") || "";
		const ticket = request.headers.get("x-ticket") || "";
		let email: string;
		try {
			const payload = await verifyTicket(this.env.APP_SECRET, ticket);
			if (payload.s !== serverId) throw new Error("ticket does not match server");
			email = payload.e;
		} catch (error) {
			return Response.json({ error: sanitize(error) }, { status: 403 });
		}

		const record = await getServer(this.env, serverId);
		if (!record) return Response.json({ error: "unknown server" }, { status: 404 });

		const pair = new WebSocketPair();
		const client = pair[0];
		const server = pair[1];
		server.accept();
		this.socket = server;

		server.addEventListener("message", (event) => this.onClientMessage(event.data));
		server.addEventListener("close", () => this.dispose("client closed"));
		server.addEventListener("error", () => this.dispose("client socket error"));

		this.touchIdle();
		void this.start(server, record, email);
		return new Response(null, { status: 101, webSocket: client });
	}

	// ---------------------------------------------------------------- terminal

	private async start(ws: WebSocket, record: ServerRecord, email: string): Promise<void> {
		const send = (message: unknown) => {
			try {
				if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(message));
			} catch {
				/* socket already gone */
			}
		};

		const connectedAt = Date.now();
		send({ t: "s", m: `connecting to ${record.username}@${record.host}:${record.port} as ${email}` });

		try {
			const credentials = await resolveCredentials(this.env, record);
			const pinned = await getPinnedHostKey(this.env, record.id);

			const tcp = openTcpStream(record.host, record.port);
			this.duplex = tcp.duplex;

			const client = new Client();
			this.client = client;

			let offered: string | undefined;
			let hostKeyError: string | undefined;

			client.on("banner", (message) => {
				const banner = String(message).trim().split("\n")[0];
				if (banner) send({ t: "s", m: `banner: ${banner.slice(0, 200)}` });
			});

			client.on("keyboard-interactive", (_name, _instructions, _lang, prompts, finish) => {
				const answers = prompts.map(() => credentials.password ?? "");
				finish(answers);
			});

			client.on("ready", () => {
				if (this.disposed) return;
				send({ t: "s", m: "authenticated" });
				if (!pinned && offered) {
					void pinHostKey(this.env, record.id, offered).then(() => send({ t: "s", m: `host key pinned ${offered}` }));
				}
				client.shell(
					{
						term: "xterm-256color",
						cols: this.cols,
						rows: this.rows,
						env: { LANG: "en_US.UTF-8", LC_ALL: "en_US.UTF-8" },
					},
					(error, stream) => {
						if (error) {
							send({ t: "e", m: `could not open shell: ${sanitize(error)}` });
							this.dispose("shell failed");
							return;
						}
						this.shell = stream as unknown as typeof this.shell;

						const decoder = new TextDecoder();
						stream.on("data", (chunk: Uint8Array) => {
							this.touchIdle();
							send({ t: "o", d: decoder.decode(chunk, { stream: true }) });
						});
						stream.stderr?.on("data", (chunk: Uint8Array) => {
							send({ t: "o", d: decoder.decode(chunk, { stream: true }) });
						});
						stream.on("close", () => {
							send({ t: "x", m: "remote shell closed" });
							this.dispose("shell closed");
						});

						void markUsed(this.env, record).catch(() => undefined);
						// Handshake + auth + PTY latency, shown in the terminal header.
						send({ t: "ready", ms: Date.now() - connectedAt });
					},
				);
			});

			client.on("error", (error: Error) => {
				if (hostKeyError) {
					send({ t: "e", m: `host key changed — refusing to connect. ${hostKeyError}` });
					this.dispose("host key mismatch");
					return;
				}
				void this.reportFailure(send, record, error);
			});

			client.on("close", () => this.dispose("ssh closed"));

			client.connect({
				sock: tcp.duplex,
				username: record.username,
				password: credentials.password,
				privateKey: credentials.privateKey,
				passphrase: credentials.passphrase,
				tryKeyboard: true,
				readyTimeout: 15_000,
				keepaliveInterval: 20_000,
				keepaliveCountMax: 3,
				algorithms: ALGORITHMS,
				hostVerifier: (key: Uint8Array) => {
					const fingerprint = fingerprintHostKey(key);
					offered = fingerprint;
					if (!pinned) return true; // trust on first use, pinned right after auth
					if (pinned === fingerprint) return true;
					hostKeyError = `pinned ${pinned}, presented ${fingerprint}. Delete the pin after verifying the change, then reconnect.`;
					return false;
				},
			});
		} catch (error) {
			void this.reportFailure(send, record, error);
		}
	}

	/** Sends the raw error, then the TCP-level diagnosis, then tears down. */
	private async reportFailure(
		send: (message: unknown) => void,
		record: ServerRecord,
		error: unknown,
	): Promise<void> {
		send({ t: "e", m: sanitize(error) });
		try {
			const diagnosis = await explainFailure(record.host, record.port, error);
			for (const hint of diagnosis.hints) send({ t: "s", m: `诊断：${hint}` });
		} catch {
			/* diagnostics are best effort */
		}
		this.dispose("connection failed");
	}

	private onClientMessage(data: unknown): void {
		if (this.disposed) return;
		let message: ClientMessage;
		try {
			message = JSON.parse(typeof data === "string" ? data : new TextDecoder().decode(data as ArrayBuffer)) as ClientMessage;
		} catch {
			return;
		}
		this.touchIdle();

		if (message.t === "i" && typeof message.d === "string") {
			this.shell?.write(message.d);
			return;
		}
		if (message.t === "r") {
			const cols = Math.max(20, Math.min(500, Math.floor(message.c)));
			const rows = Math.max(5, Math.min(300, Math.floor(message.r)));
			if (!Number.isFinite(cols) || !Number.isFinite(rows)) return;
			this.cols = cols;
			this.rows = rows;
			try {
				this.shell?.setWindow(rows, cols, 0, 0);
			} catch {
				/* shell not open yet; values are reused when it is */
			}
			return;
		}
		if (message.t === "p") {
			this.socket?.send(JSON.stringify({ t: "pong", n: message.n }));
			return;
		}
		if (message.t === "ls") {
			void this.handleList(String(message.p ?? "~"), Number(message.n) || 0);
		}
	}

	// ------------------------------------------------------------- file manager

	/** Streams or previews a single file from the live SFTP session. */
	private async handleFile(request: Request): Promise<Response> {
		const url = new URL(request.url);
		const serverId = request.headers.get("x-server-id") || "";
		const sessionId = request.headers.get("x-session-id") || "";

		try {
			const payload = await verifyTicket(this.env.APP_SECRET, request.headers.get("x-ticket") || "");
			if (payload.s !== serverId) throw new Error("ticket does not match server");
			if (payload.d && sessionId && payload.d !== sessionId) throw new Error("ticket does not match session");
		} catch (error) {
			return new Response(sanitize(error), { status: 403 });
		}

		const path = url.searchParams.get("path") || "";
		const mode = url.searchParams.get("mode") === "download" ? "download" : "preview";
		if (!path.startsWith("/")) return new Response("invalid path", { status: 400 });

		const name = path.slice(path.lastIndexOf("/") + 1) || "file";

		try {
			const sftp = await this.ensureSftp();
			const stats = await new Promise<{ size: number; isDirectory(): boolean }>((resolve, reject) => {
				sftp.stat(path, (error, result) => (error ? reject(error) : resolve(result)));
			});
			if (stats.isDirectory()) return new Response("path is a directory", { status: 400 });

			if (mode === "download") {
				if (stats.size > MAX_DOWNLOAD) return new Response("file too large", { status: 413 });
				const nodeStream = sftp.createReadStream(path);
				const body = new ReadableStream<Uint8Array>({
					start(controller) {
						nodeStream.on("data", (chunk: Uint8Array) => controller.enqueue(new Uint8Array(chunk)));
						nodeStream.on("end", () => {
							try {
								controller.close();
							} catch {
								/* already closed */
							}
						});
						nodeStream.on("error", (error: Error) => controller.error(error));
					},
					cancel() {
						(nodeStream as unknown as { destroy?: () => void }).destroy?.();
					},
				});
				return new Response(body, {
					headers: {
						"content-type": "application/octet-stream",
						"content-length": String(stats.size),
						"content-disposition": `attachment; filename="${name.replace(/["\\]/g, "_")}"; filename*=UTF-8''${encodeURIComponent(name)}`,
						"cache-control": "no-store",
					},
				});
			}

			const imageType = imageTypeFor(name);
			if (imageType && stats.size > MAX_IMAGE_PREVIEW) {
				return new Response(`${name} 太大（${Math.round(stats.size / 1024)} KB），请直接下载`, { status: 413 });
			}
			const limit = imageType ? MAX_IMAGE_PREVIEW : MAX_TEXT_PREVIEW;
			const truncated = stats.size > limit;
			const buffer = await new Promise<Uint8Array>((resolve, reject) => {
				const chunks: Uint8Array[] = [];
				const stream = sftp.createReadStream(path, { start: 0, end: Math.min(stats.size, limit) - 1 });
				stream.on("data", (chunk: Uint8Array) => chunks.push(new Uint8Array(chunk)));
				stream.on("end", () => {
					const total = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
					const merged = new Uint8Array(total);
					let offset = 0;
					for (const chunk of chunks) {
						merged.set(chunk, offset);
						offset += chunk.length;
					}
					resolve(merged);
				});
				stream.on("error", (error: Error) => reject(error));
			});
			if (!imageType && looksBinary(buffer)) {
				return new Response(`${name} 看起来是二进制内容（含 NUL 字节或过多控制字符），无法预览`, { status: 415 });
			}
			return new Response(buffer, {
				headers: {
					"content-type": imageType || "text/plain; charset=utf-8",
					"x-file-size": String(stats.size),
					"x-truncated": truncated ? "1" : "0",
					"cache-control": "no-store",
				},
			});
		} catch (error) {
			return new Response(sanitize(error), { status: 500 });
		}
	}

	private async ensureSftp(): Promise<SFTPWrapper> {
		if (this.sftp) return this.sftp;
		const client = this.client;
		if (!client) throw new Error("SSH 会话未连接");

		const sftp = await new Promise<SFTPWrapper>((resolve, reject) => {
			client.sftp((error, wrapper) => (error ? reject(error) : resolve(wrapper)));
		});
		this.sftp = sftp;
		this.homePath = await new Promise<string>((resolve, reject) => {
			sftp.realpath(".", (error, absolute) => (error ? reject(error) : resolve(absolute)));
		});
		return sftp;
	}

	/** Streams a directory listing to the browser; SFTP is opened on first use. */
	private async handleList(requestedPath: string, requestId: number): Promise<void> {
		const reply = (payload: Record<string, unknown>) => {
			try {
				if (this.socket?.readyState === WebSocket.OPEN) {
					this.socket.send(JSON.stringify({ t: "lsr", n: requestId, ...payload }));
				}
			} catch {
				/* socket gone */
			}
		};

		try {
			const sftp = await this.ensureSftp();
			const home = this.homePath || "/";
			let target = requestedPath.trim();
			if (target === "" || target === "~") target = home;
			else if (target.startsWith("~/")) target = joinPath(home, target.slice(2));
			target = normalizePath(target.startsWith("/") ? target : joinPath(home, target));

			const raw = await new Promise<Array<{ filename: string; longname: string; attrs: { size: number; mtime: number; isDirectory(): boolean; isSymbolicLink(): boolean } }>>(
				(resolve, reject) => {
					sftp.readdir(target, (error, list) => (error ? reject(error) : resolve(list as never)));
				},
			);

			const entries: DirEntry[] = raw
				.filter((entry) => entry.filename !== "." && entry.filename !== "..")
				.map((entry) => {
					const link = entry.attrs.isSymbolicLink();
					const looksLikeDir = entry.longname.startsWith("d") || entry.longname.startsWith("l") && entry.longname.includes(" -> ") && entry.longname.includes("-> /");
					return {
						name: entry.filename,
						path: joinPath(target, entry.filename),
						type: entry.attrs.isDirectory() || (!link && looksLikeDir) ? ("dir" as const) : ("file" as const),
						link,
						size: entry.attrs.size || 0,
						mtime: (entry.attrs.mtime || 0) * 1000,
					};
				})
				.sort((a, b) => {
					if (a.type !== b.type) return a.type === "dir" ? -1 : 1;
					return a.name.localeCompare(b.name, "en", { numeric: true, sensitivity: "base" });
				});

			const truncated = entries.length > MAX_DIR_ENTRIES;
			reply({
				p: target,
				home,
				entries: entries.slice(0, MAX_DIR_ENTRIES),
				truncated,
			});
		} catch (error) {
			const message = sanitize(error);
			reply({
				p: requestedPath,
				error: /subsystem|sftp/i.test(message)
					? `${message}（该服务器可能未启用 SFTP 子系统，文件树不可用）`
					: message,
			});
		}
	}

	// ------------------------------------------------------------------- probe

	private async handleProbe(request: Request): Promise<Response> {
		const serverId = request.headers.get("x-server-id") || "";
		try {
			const payload = await verifyTicket(this.env.APP_SECRET, request.headers.get("x-ticket") || "");
			if (payload.s !== serverId) throw new Error("ticket does not match server");
		} catch (error) {
			return Response.json({ ok: false, error: sanitize(error) }, { status: 403 });
		}

		const record = await getServer(this.env, serverId);
		if (!record) return Response.json({ ok: false, error: "unknown server" }, { status: 404 });

		const startedAt = Date.now();
		try {
			const output = await this.runProbe(record);
			await markUsed(this.env, record).catch(() => undefined);
			return Response.json({ ok: true, latencyMs: Date.now() - startedAt, output });
		} catch (error) {
			const diagnosis = await explainFailure(record.host, record.port, error).catch(() => undefined);
			return Response.json({
				ok: false,
				error: sanitize(error),
				latencyMs: Date.now() - startedAt,
				diagnosis: diagnosis?.diagnosis,
				hints: diagnosis?.hints ?? [],
				resolved: diagnosis?.resolved ?? [],
				proxyDetected: diagnosis?.proxyDetected ?? false,
			});
		}
	}

	private runProbe(record: ServerRecord): Promise<string> {
		return new Promise(async (resolve, reject) => {
			let tcp: ReturnType<typeof openTcpStream> | undefined;
			let settled = false;
			const finish = (error: Error | null, value?: string) => {
				if (settled) return;
				settled = true;
				clearTimeout(timer);
				try {
					client.end();
				} catch {
					/* ignore */
				}
				error ? reject(error) : resolve(value ?? "");
			};

			const timer = setTimeout(() => finish(new Error("probe timed out after 20s")), 20_000);
			const client = new Client();

			try {
				const credentials = await resolveCredentials(this.env, record);
				const pinned = await getPinnedHostKey(this.env, record.id);
				tcp = openTcpStream(record.host, record.port);

				client.on("keyboard-interactive", (_n, _i, _l, prompts, done) => {
					done(prompts.map(() => credentials.password ?? ""));
				});
				client.on("ready", () => {
						client.exec(PROBE_COMMAND, (error, stream) => {
								if (error) return finish(error);
						let text = "";
						const decoder = new TextDecoder();
						stream.on("data", (chunk: Uint8Array) => (text += decoder.decode(chunk, { stream: true })));
						stream.stderr?.on("data", (chunk: Uint8Array) => (text += decoder.decode(chunk, { stream: true })));
						stream.on("close", () => finish(null, text.trim()));
					});
				});
				client.on("error", (error: Error) => finish(error));
				client.connect({
					sock: tcp.duplex,
					username: record.username,
					password: credentials.password,
					privateKey: credentials.privateKey,
					passphrase: credentials.passphrase,
					tryKeyboard: true,
					readyTimeout: 15_000,
					algorithms: ALGORITHMS,
					hostVerifier: (key: Uint8Array) => !pinned || pinned === fingerprintHostKey(key),
				});
			} catch (error) {
				finish(error instanceof Error ? error : new Error(String(error)));
			}
		});
	}

	// --------------------------------------------------------------- lifecycle

	private touchIdle(): void {
		clearTimeout(this.idleTimer);
		this.idleTimer = setTimeout(() => {
			try {
				this.socket?.send(JSON.stringify({ t: "e", m: "session idle for 30 minutes, disconnecting" }));
			} catch {
				/* ignore */
			}
			this.dispose("idle timeout");
		}, IDLE_TIMEOUT_MS);
	}

	private dispose(reason: string): void {
		if (this.disposed) return;
		this.disposed = true;
		clearTimeout(this.idleTimer);

		try {
			this.sftp?.end();
		} catch {
			/* ignore */
		}
		try {
			this.shell?.end?.();
		} catch {
			/* ignore */
		}
		try {
			this.client?.end();
		} catch {
			/* ignore */
		}
		try {
			// Only needed when a connection was never established; otherwise
			// client.end() already closed the socket through final().
			if (!this.client) this.duplex?.destroy();
		} catch {
			/* ignore */
		}
		try {
			if (this.socket && this.socket.readyState === WebSocket.OPEN) {
				this.socket.close(1000, reason.slice(0, 120));
			}
		} catch {
			/* ignore */
		}
		this.shell = undefined;
		this.sftp = undefined;
		this.homePath = undefined;
		this.client = undefined;
		this.duplex = undefined;
		this.socket = undefined;
	}
}
