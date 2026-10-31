/**
 * Cloudflare-native project config (used by `cf deploy` / `cf dev`).
 *
 * Personal values (domain, KV id, Access team/AUD, allowlist) come from the
 * environment so the repository stays free of identifiers. Copy `.env.example`
 * to `.env.deploy`, fill it in, then `npm run deploy` (which sources it).
 */
import { bindings, defineConfig, defineWorker, exports } from "cf/config";

const setting = (key: string, fallback: string): string => process.env[key] || fallback;

const worker = defineWorker({
	name: "ssh-worker",
	compatibilityDate: "2025-10-01",
	compatibilityFlags: ["nodejs_compat"],
	entrypoint: "./src/index.ts",
	workersDev: false,
	observability: { enabled: true },
	assets: { runWorkerFirst: ["/api/*"], notFoundHandling: "single-page-application" },
	domains: [setting("CF_DOMAIN", "ssh.example.com")],
	exports: {
		SshSession: exports.durableObject({ storage: "sqlite" }),
	},
	env: {
		SERVERS: bindings.kv({ id: setting("CF_KV_NAMESPACE_ID", "<KV_NAMESPACE_ID>") }),
		SSH_SESSION: bindings.durableObject({ worker: "ssh-worker", exportName: "SshSession" }),
		APP_SECRET: bindings.secret(),
		ACCESS_TEAM_DOMAIN: bindings.text(setting("CF_ACCESS_TEAM_DOMAIN", "yourteam.cloudflareaccess.com")),
		ACCESS_AUD: bindings.text(setting("CF_ACCESS_AUD", "<ACCESS_AUD_TAG>")),
		ALLOWED_EMAILS: bindings.text(setting("CF_ALLOWED_EMAILS", "you@example.com")),
		DEV_AUTH_BYPASS: bindings.text("false"),
	},
});

export default defineConfig({ worker });
