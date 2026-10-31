/**
 * TCP-level diagnostics for failed SSH connections.
 *
 * `ssh2` only tells us "Connection lost before handshake", which is useless when
 * the real cause is a Cloudflare-proxied hostname, a filtered port, or an HTTP
 * service on the wrong port. These helpers re-probe the endpoint on their own
 * and translate the result into something actionable.
 */
import { connect } from "cloudflare:sockets";

const CF_IPS_URL = "https://api.cloudflare.com/client/v4/ips";
const CIDR_TTL_MS = 60 * 60 * 1000;

interface Cidr4 {
	base: number;
	bits: number;
}
interface Cidr6 {
	base: bigint;
	bits: number;
}

let cidrCache: { v4: Cidr4[]; v6: Cidr6[]; at: number } | undefined;

function sleep(ms: number): Promise<null> {
	return new Promise((resolve) => setTimeout(() => resolve(null), ms));
}

export function parseIpv4(value: string): number | undefined {
	const parts = value.split(".");
	if (parts.length !== 4) return undefined;
	let out = 0;
	for (const part of parts) {
		if (!/^\d{1,3}$/.test(part)) return undefined;
		const byte = Number(part);
		if (byte > 255) return undefined;
		out = out * 256 + byte;
	}
	return out;
}

export function parseIpv6(value: string): bigint | undefined {
	let text = value.trim().toLowerCase();
	if (text.startsWith("[") && text.endsWith("]")) text = text.slice(1, -1);
	if (!text.includes(":")) return undefined;
	text = text.split("%")[0];

	const halves = text.split("::");
	if (halves.length > 2) return undefined;

	const toGroups = (chunk: string): string[] => (chunk.length === 0 ? [] : chunk.split(":"));
	let head = toGroups(halves[0]);
	let tail = halves.length === 2 ? toGroups(halves[1]) : [];

	const expandIpv4Tail = (groups: string[]): string[] | undefined => {
		if (groups.length === 0) return groups;
		const last = groups[groups.length - 1];
		if (!last.includes(".")) return groups;
		const v4 = parseIpv4(last);
		if (v4 === undefined) return undefined;
		return [...groups.slice(0, -1), ((v4 >>> 16) & 0xffff).toString(16), (v4 & 0xffff).toString(16)];
	};

	const expandedHead = expandIpv4Tail(head);
	const expandedTail = expandIpv4Tail(tail);
	if (!expandedHead || !expandedTail) return undefined;
	head = expandedHead;
	tail = expandedTail;

	const groups = halves.length === 2 ? [...head, ...Array(8 - head.length - tail.length).fill("0"), ...tail] : head;
	if (groups.length !== 8) return undefined;

	let out = 0n;
	for (const group of groups) {
		if (!/^[0-9a-f]{1,4}$/.test(group)) return undefined;
		out = (out << 16n) | BigInt(parseInt(group, 16));
	}
	return out;
}

function ipv4ToString(value: number): string {
	return [(value >>> 24) & 255, (value >>> 16) & 255, (value >>> 8) & 255, value & 255].join(".");
}

function inCidr4(ip: number, cidr: Cidr4): boolean {
	if (cidr.bits === 0) return true;
	const mask = cidr.bits === 32 ? 0xffffffff : ~((1 << (32 - cidr.bits)) - 1) >>> 0;
	return (ip & mask) === (cidr.base & mask);
}

function inCidr6(ip: bigint, cidr: Cidr6): boolean {
	if (cidr.bits === 0) return true;
	const shift = BigInt(128 - cidr.bits);
	return ip >> shift === cidr.base >> shift;
}

async function loadCloudflareRanges(): Promise<{ v4: Cidr4[]; v6: Cidr6[] }> {
	if (cidrCache && Date.now() - cidrCache.at < CIDR_TTL_MS) return cidrCache;

	const response = await fetch(CF_IPS_URL, { headers: { accept: "application/json" } });
	if (!response.ok) throw new Error(`could not load Cloudflare IP ranges (${response.status})`);
	const body = (await response.json()) as { result?: { ipv4_cidrs?: string[]; ipv6_cidrs?: string[] } };
	const ipv4 = (body.result?.ipv4_cidrs || []).flatMap((entry) => {
		const [ip, bits] = entry.split("/");
		const base = parseIpv4(ip);
		return base === undefined ? [] : [{ base, bits: Number(bits) }];
	});
	const ipv6 = (body.result?.ipv6_cidrs || []).flatMap((entry) => {
		const [ip, bits] = entry.split("/");
		const base = parseIpv6(ip);
		return base === undefined ? [] : [{ base, bits: Number(bits) }];
	});
	cidrCache = { v4: ipv4, v6: ipv6, at: Date.now() };
	return cidrCache;
}

export function isCloudflareAddress(address: string, ranges: { v4: Cidr4[]; v6: Cidr6[] }): boolean {
	const v4 = parseIpv4(address);
	if (v4 !== undefined) return ranges.v4.some((cidr) => inCidr4(v4, cidr));
	const v6 = parseIpv6(address);
	if (v6 !== undefined) return ranges.v6.some((cidr) => inCidr6(v6, cidr));
	return false;
}

/** Resolves A/AAAA over DNS-over-HTTPS (Workers have no dns module). */
export async function resolveHost(host: string): Promise<{ v4: string[]; v6: string[]; error?: string }> {
	if (parseIpv4(host) !== undefined) return { v4: [host], v6: [] };
	if (parseIpv6(host) !== undefined) return { v4: [], v6: [host] };

	const query = async (type: "A" | "AAAA"): Promise<string[]> => {
		const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(host)}&type=${type}`;
		const response = await fetch(url, { headers: { accept: "application/dns-json" } });
		if (!response.ok) return [];
		const body = (await response.json()) as { Answer?: Array<{ type: number; data: string }> };
		const expected = type === "A" ? 1 : 28;
		return (body.Answer || []).filter((answer) => answer.type === expected).map((answer) => answer.data);
	};

	try {
		const [v4, v6] = await Promise.all([query("A"), query("AAAA")]);
		return { v4, v6 };
	} catch (error) {
		return { v4: [], v6: [], error: error instanceof Error ? error.message : String(error) };
	}
}

export type TcpStage = "banner" | "silent" | "http" | "closed" | "connect-failed" | "timeout";

export interface TcpProbeResult {
	stage: TcpStage;
	detail: string;
	latencyMs: number;
	firstBytes?: string;
}

/**
 * Opens a raw TCP connection and reads up to `bannerBytes` immediately.
 * Independent of ssh2, so it tells us whether the problem is the network or the
 * SSH handshake.
 */
export async function probeTcp(host: string, port: number, timeoutMs = 10_000): Promise<TcpProbeResult> {
	const started = Date.now();
	let socket;
	try {
		socket = connect({ hostname: host, port });
	} catch (error) {
		return {
			stage: "connect-failed",
			detail: error instanceof Error ? error.message : String(error),
			latencyMs: Date.now() - started,
		};
	}

	const opened = await Promise.race([
		socket.opened.then(() => "open" as const).catch((error: unknown) => `error:${error instanceof Error ? error.message : String(error)}`),
		sleep(timeoutMs).then(() => "timeout" as const),
	]);

	if (opened === "timeout") {
		try {
			void socket.close();
		} catch {
			/* ignore */
		}
		return {
			stage: "timeout",
			detail: `TCP 连接 ${Math.round(timeoutMs / 1000)} 秒内没有建立`,
			latencyMs: Date.now() - started,
		};
	}
	if (opened.startsWith("error:")) {
		try {
			void socket.close();
		} catch {
			/* ignore */
		}
		return { stage: "connect-failed", detail: opened.slice(6), latencyMs: Date.now() - started };
	}

	const reader = socket.readable.getReader();
	let chunk: Uint8Array | null = null;
	let closedEarly = false;
	try {
		const result = await Promise.race([reader.read(), sleep(6000).then(() => null)]);
		if (result === null) {
			chunk = null;
		} else if (result.done) {
			closedEarly = true;
		} else {
			chunk = result.value ?? null;
		}
	} catch {
		closedEarly = true;
	} finally {
		try {
			await reader.cancel();
		} catch {
			/* ignore */
		}
		try {
			void socket.close();
		} catch {
			/* ignore */
		}
	}

	const latencyMs = Date.now() - started;
	const text = chunk ? new TextDecoder().decode(chunk.slice(0, 120)) : "";

	if (text.startsWith("SSH-")) {
		return { stage: "banner", detail: `收到 SSH banner：${text.split("\n")[0].trim()}`, latencyMs, firstBytes: text };
	}
	if (/^HTTP\/|^\u0015\u0003|^GET |^HEAD /i.test(text)) {
		return { stage: "http", detail: "该端口返回的是 HTTP 流量，不是 SSH", latencyMs, firstBytes: text };
	}
	if (closedEarly && !chunk) {
		return { stage: "closed", detail: "TCP 已建立但立刻被对端关闭", latencyMs };
	}
	if (!chunk) {
		return { stage: "silent", detail: "TCP 已连通，但 6 秒内没有收到任何字节", latencyMs };
	}
	return { stage: "banner", detail: `收到 ${chunk.length} 字节的未知协议数据`, latencyMs, firstBytes: text };
}

export interface ConnectionDiagnosis {
	diagnosis: string;
	hints: string[];
	resolved: string[];
	proxyDetected: boolean;
}

function looksLikeTransportFailure(message: string): boolean {
	return /handshake|socket|connect|ECONN|EPIPE|timed out|network|closed/i.test(message);
}

/** Turns an ssh2 error into a Chinese explanation plus concrete next steps. */
export async function explainFailure(host: string, port: number, error: unknown): Promise<ConnectionDiagnosis> {
	const message = error instanceof Error ? error.message : String(error);
	const hints: string[] = [];
	const resolved: string[] = [];
	let proxyDetected = false;

	if (!looksLikeTransportFailure(message)) {
		hints.push("认证或算法阶段失败：检查用户名、密码/私钥、以及服务器的 sshd 配置。");
		return { diagnosis: message, hints, resolved, proxyDetected };
	}

	const [probe, dns] = await Promise.all([probeTcp(host, port).catch(() => undefined), resolveHost(host)]);
	resolved.push(...dns.v4, ...dns.v6);

	if (resolved.length > 0) {
		try {
			const ranges = await loadCloudflareRanges();
			proxyDetected = resolved.some((address) => isCloudflareAddress(address, ranges));
		} catch {
			/* ranges unavailable: skip that hint */
		}
	}

	if (resolved.length === 0) {
		hints.push(`${host} 没有解析到任何 A/AAAA 记录，请检查域名拼写或 DNS 是否生效。`);
	} else if (dns.v4.length === 0 && dns.v6.length > 0) {
		hints.push(`${host} 只有 IPv6 地址（${dns.v6.join(", ")}）：确认服务器 IPv6 真的可用，或补一条 A 记录。`);
	}

	if (proxyDetected) {
		hints.push(
			`${host} 解析到 Cloudflare 代理地址。橙色云朵的代理只转发 HTTP/HTTPS，22 端口会被直接拒绝。`,
			"请把该 DNS 记录改成「仅 DNS」（灰色云朵），或直接填写源站 IP / 未走代理的域名。",
			"如果是 Cloudflare Tunnel 域名，需要本机 cloudflared 隧道，Workers 不能直接连。",
		);
	}

	if (!probe) {
		hints.push("TCP 探测本身也失败了，请稍后重试。");
		return { diagnosis: message, hints, resolved, proxyDetected };
	}

	switch (probe.stage) {
		case "timeout": {
			hints.push(
				`TCP 握手在 ${Math.round(probe.latencyMs / 1000)} 秒内没有完成：对方「丢包」而不是「拒绝」，通常是防火墙 / 安全组直接丢弃了来自 Cloudflare 的 SYN，或服务器只监听内网地址。`,
				"先在服务器上执行 `ss -ltnp | grep :22` 确认在 0.0.0.0/:: 上监听，并检查 ufw / firewalld / 云厂商安全组。",
			);
			try {
				const ranges = await loadCloudflareRanges();
				const sample = ranges.v4.slice(0, 4).map((cidr) => `${ipv4ToString(cidr.base)}/${cidr.bits}`);
				if (sample.length > 0) {
					hints.push(
						`如果做了来源 IP 白名单，需要放行 Cloudflare 的出站网段，例如 ${sample.join("、")} …（完整列表见 https://api.cloudflare.com/client/v4/ips）。`,
					);
				}
			} catch {
				/* ranges unavailable */
			}
			hints.push("也可以把 sshd 换到高位端口（如 2222）再看是否被运营商/机房专门封了 22。");
			break;
		}
		case "connect-failed":
			if (/HTTP-based service/i.test(probe.detail)) {
				hints.push(`Cloudflare 判定 ${port} 是 HTTP(S) 端口：那里跑的是网站，不是 SSH。`);
			} else if (/cannot connect to the specified address/i.test(probe.detail)) {
				hints.push(
					`Cloudflare 无法连接到 ${host}:${port}：目标不接受 Cloudflare 的出站连接（端口未放行，或域名走了代理）。`,
				);
			} else {
				hints.push(
					`TCP 连接失败：${probe.detail}`,
					"端口被主动拒绝（RST）通常意味着端口没开、sshd 未运行，或防火墙配置了 reject。",
				);
			}
			break;
		case "closed":
			hints.push("TCP 三次握手成功后对端立刻关闭，常见于 fail2ban/denyhosts 封禁、端口转发规则错误，或该端口不是 SSH。");
			break;
		case "silent":
			hints.push("TCP 已连通但 6 秒内收不到 SSH banner：对方端口是通的，但服务没有主动发问候语。");
			if ([80, 443, 8080, 8443, 3000, 8000].includes(port)) {
				hints.push(`${port} 通常是 HTTP(S) 端口，服务在等客户端先发请求，所以不会有 banner。请确认 sshd 的实际端口。`);
			} else {
				hints.push(
					"检查是否把 SSH 放在了 TCP 负载均衡 / NAT 后面，或该端口其实是别的协议（例如 Docker 端口映射错位）。",
				);
			}
			break;
		case "http":
			hints.push("这个端口跑的是 HTTP 服务（可能是面板 / 反代），不是 SSH。请换回 22 或 sshd 实际端口。");
			break;
		case "banner":
			hints.push(
				`网络可达（${probe.detail}），失败发生在 SSH 协议/算法/认证阶段。`,
				"服务器可能禁用了 aes-ctr 或 ecdh-sha2-nistp256。在服务端 `grep -E '^(Ciphers|KexAlgorithms|MACs)' /etc/ssh/sshd_config` 检查，或临时加回 `aes128-ctr`。",
				"也可能是用户名/密码/私钥不对，或 sshd 只允许特定用户。",
			);
			break;
	}

	return { diagnosis: message, hints, resolved, proxyDetected };
}
