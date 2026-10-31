/**
 * HTTP entry point.
 *
 * Everything under /api requires a valid Cloudflare Access JWT (RS256, verified
 * locally against the team JWKS) — the edge protects the hostname too, but this
 * layer fails closed if the Access application is ever detached.
 */
import { AuthError, authenticate } from "./auth.js";
import { mintTicket } from "./lib/ticket.js";
import {
	ValidationError,
	createServer,
	deleteServer,
	getPinnedHostKey,
	getServer,
	listServers,
	parseServerInput,
	toPublic,
	updateServer,
} from "./store.js";
import type { Env } from "./types.js";

export { SshSession } from "./ssh/session.js";

const JSON_HEADERS = {
	"content-type": "application/json; charset=utf-8",
	"cache-control": "no-store",
	"x-content-type-options": "nosniff",
};

function json(data: unknown, status = 200): Response {
	return new Response(JSON.stringify(data), { status, headers: JSON_HEADERS });
}

function fail(message: string, status: number): Response {
	return json({ error: message }, status);
}

function requestOriginAllowed(request: Request, url: URL): boolean {
	// Same-origin fetch/XHR from the UI always sends Origin on non-GET requests.
	// A cross-site page cannot forge it, and cannot set x-csrf without a preflight.
	const origin = request.headers.get("Origin");
	if (origin && origin !== url.origin) return false;
	if (request.headers.get("x-csrf") !== "1") return false;
	return true;
}

async function readJson(request: Request): Promise<unknown> {
	const type = request.headers.get("content-type") || "";
	if (!type.includes("application/json")) throw new ValidationError("expected application/json body");
	const text = await request.text();
	if (text.length > 64 * 1024) throw new ValidationError("request body too large");
	try {
		return JSON.parse(text);
	} catch {
		throw new ValidationError("invalid JSON body");
	}
}

function ticketFor(request: Request): string | undefined {
	const header = request.headers.get("x-ticket");
	if (header) return header;
	const url = new URL(request.url);
	return url.searchParams.get("ticket") ?? undefined;
}

export default {
	async fetch(request: Request, env: Env): Promise<Response> {
		const url = new URL(request.url);

		if (!url.pathname.startsWith("/api/")) {
			// Static assets normally never reach the Worker (run_worker_first only
			// matches /api/*), but stay defensive if that routing changes.
			if (!env.ASSETS) return new Response("Not found", { status: 404 });
			return env.ASSETS.fetch(request);
		}

		let user: { email: string; devBypass: boolean };
		try {
			user = await authenticate(request, env);
		} catch (error) {
			if (error instanceof AuthError) {
				return fail(error.message, error.status);
			}
			return fail("authentication failed", 500);
		}

		if (!["GET", "HEAD"].includes(request.method) && !requestOriginAllowed(request, url)) {
			return fail("cross-site request rejected", 403);
		}

		try {
			return await route(request, env, url, user.email);
		} catch (error) {
			if (error instanceof ValidationError) return fail(error.message, 400);
			if (error instanceof AuthError) return fail(error.message, error.status);
			console.error("unhandled error", error);
			return fail("internal error", 500);
		}
	},
};

async function route(request: Request, env: Env, url: URL, email: string): Promise<Response> {
	const parts = url.pathname.split("/").filter(Boolean); // ["api", ...]
	const method = request.method;

	if (parts[1] === "me" && parts.length === 2) {
		if (method !== "GET") return fail("method not allowed", 405);
		// Access clears its session cookie only on the team domain, so hand the
		// browser a ready-made logout URL instead of guessing it client-side.
		const team = (env.ACCESS_TEAM_DOMAIN || "").replace(/^https?:\/\//, "").replace(/\/+$/, "");
		const logoutUrl = team
			? `https://${team}/cdn-cgi/access/logout?redirect_url=${encodeURIComponent(`${url.origin}/`)}`
			: null;
		return json({ email, devBypass: email === "dev@localhost", logoutUrl });
	}

	if (parts[1] === "servers") {
		if (parts.length === 2) {
			if (method === "GET") return json({ servers: await listServers(env) });
			if (method === "POST") {
				const input = parseServerInput(await readJson(request));
				if (!input.credential) throw new ValidationError("credential is required when creating a server");
				const created = await createServer(env, input, email);
				return json({ server: created }, 201);
			}
			return fail("method not allowed", 405);
		}

		const id = parts[2];
		if (!/^[a-f0-9]{8,32}$/.test(id)) return fail("invalid server id", 400);

		if (parts.length === 3) {
			const record = await getServer(env, id);
			if (!record) return fail("server not found", 404);
			if (method === "GET") {
				return json({ server: toPublic(record, Boolean(await getPinnedHostKey(env, id))) });
			}
			if (method === "PUT") {
				const input = parseServerInput(await readJson(request));
				return json({ server: await updateServer(env, record, input) });
			}
			if (method === "DELETE") {
				await deleteServer(env, id);
				return json({ ok: true });
			}
			return fail("method not allowed", 405);
		}

		if (parts.length === 4 && parts[3] === "session" && method === "POST") {
			const record = await getServer(env, id);
			if (!record) return fail("server not found", 404);
			const body = (await readJson(request).catch(() => ({}))) as { sid?: unknown };
			const sid = typeof body.sid === "string" && /^[a-z0-9-]{8,64}$/i.test(body.sid) ? body.sid : undefined;
			const { ticket, expiresAt } = await mintTicket(env.APP_SECRET, id, email, sid);
			return json({ ticket, expiresAt, sid, path: `/api/servers/${id}/terminal` });
		}

		if (parts.length === 4 && parts[3] === "file" && method === "GET") {
			const record = await getServer(env, id);
			if (!record) return fail("server not found", 404);
			const sid = url.searchParams.get("sid") || "";
			const filePath = url.searchParams.get("path") || "";
			if (!/^[a-z0-9-]{8,64}$/i.test(sid)) return fail("invalid session id", 400);
			if (!filePath.startsWith("/")) return fail("invalid path", 400);

			const { ticket } = await mintTicket(env.APP_SECRET, id, email, sid);
			const stub = env.SSH_SESSION.get(env.SSH_SESSION.idFromName(sid));
			const response = await stub.fetch(url.href, {
				headers: {
					"x-file": "1",
					"x-ticket": ticket,
					"x-server-id": id,
					"x-session-id": sid,
				},
			});
			return new Response(response.body, { status: response.status, headers: response.headers });
		}

		if (parts.length === 4 && parts[3] === "probe" && method === "POST") {
			const record = await getServer(env, id);
			if (!record) return fail("server not found", 404);
			const { ticket } = await mintTicket(env.APP_SECRET, id, email);
			const stub = env.SSH_SESSION.get(env.SSH_SESSION.newUniqueId());
			const target = new URL(url.href);
			target.pathname = `/probe/${id}`;
			const response = await stub.fetch(target.href, {
				method: "POST",
				headers: { "x-probe": "1", "x-server-id": id, "x-ticket": ticket },
			});
			return new Response(response.body, {
				status: response.status,
				headers: JSON_HEADERS,
			});
		}

		if (parts.length === 4 && parts[3] === "terminal") {
			if ((request.headers.get("Upgrade") || "").toLowerCase() !== "websocket") {
				return fail("expected a WebSocket upgrade", 426);
			}
			const record = await getServer(env, id);
			if (!record) return fail("server not found", 404);

			const sid = url.searchParams.get("sid") || "";
			if (!/^[a-z0-9-]{8,64}$/i.test(sid)) return fail("invalid session id", 400);

			let ticket = ticketFor(request);
			if (!ticket) {
				// Browsers cannot set headers on WebSocket upgrades; mint one on the fly.
				ticket = (await mintTicket(env.APP_SECRET, id, email, sid)).ticket;
			}
			const stub = env.SSH_SESSION.get(env.SSH_SESSION.idFromName(sid));
			const target = new URL(url.href);
			target.pathname = `/terminal/${id}`;
			target.search = "";
			return stub.fetch(target.href, {
				method: "GET",
				headers: {
					Upgrade: "websocket",
					"x-server-id": id,
					"x-session-id": sid,
					"x-ticket": ticket,
				},
			});
		}
	}

	return fail("not found", 404);
}
