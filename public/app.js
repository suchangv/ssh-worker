/* SSH Worker UI — plain ES2020, hash-free routing with the History API. */
(() => {
	"use strict";

	const $ = (id) => document.getElementById(id);
	const FONT_KEY = "ssh-worker:font-size";
	const MIN_FONT = 10;
	const MAX_FONT = 22;

	const state = {
		me: null,
		servers: null,
		loadedAt: 0,
		session: null,
		term: null,
		fit: null,
		ws: null,
		pingTimer: null,
		clockTimer: null,
		fitTimer: null,
		resizeObserver: null,
		sessionStart: 0,
		pendingPing: 0,
		lastPong: 0,
		fontSize: 14,
		sessionId: null,
		preview: { path: null, url: null },
	};

	const FILES_KEY = "ssh-worker:files-visible";
	const files = {
		open: true,
		home: null,
		root: null,
		entries: new Map(),
		expanded: new Set(),
		loading: new Set(),
		errors: new Map(),
		seq: 0,
		pending: new Map(),
		hint: "连接后加载…",
	};

	/* ------------------------------------------------------------------ util */

	async function api(path, options = {}) {
		const headers = Object.assign({}, options.headers);
		if (options.body !== undefined) headers["content-type"] = "application/json";
		if (options.method && options.method !== "GET") headers["x-csrf"] = "1";
		const response = await fetch(path, { ...options, headers, credentials: "same-origin" });
		const text = await response.text();
		let data = {};
		try {
			data = text ? JSON.parse(text) : {};
		} catch {
			data = { error: text.slice(0, 200) };
		}
		if (!response.ok) throw new Error(data.error || `${response.status} ${response.statusText}`);
		return data;
	}

	function toast(message, isError = false) {
		const el = document.createElement("div");
		el.className = "toast" + (isError ? " err" : "");
		el.textContent = message;
		$("toasts").appendChild(el);
		setTimeout(() => el.remove(), 4200);
	}

	function escapeHtml(value) {
		return String(value ?? "").replace(/[&<>"']/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[ch]);
	}

	function fmtTime(ts) {
		if (!ts) return "从未";
		return new Date(ts).toLocaleString("zh-CN", { hour12: false });
	}

	function fmtDuration(ms) {
		const total = Math.max(0, Math.floor(ms / 1000));
		const h = String(Math.floor(total / 3600)).padStart(2, "0");
		const m = String(Math.floor((total % 3600) / 60)).padStart(2, "0");
		const s = String(total % 60).padStart(2, "0");
		return `${h}:${m}:${s}`;
	}

	function fmtLatency(ms) {
		if (!ms || ms < 0) return "—";
		return ms < 1000 ? `${Math.round(ms)} ms` : `${(ms / 1000).toFixed(2)} s`;
	}

	/** Calendar-day difference for a `yyyy-MM-dd` string (negative = expired). */
	function daysUntil(dateText) {
		if (!/^\d{4}-\d{2}-\d{2}$/.test(dateText || "")) return null;
		const [y, m, d] = dateText.split("-").map(Number);
		const target = Date.UTC(y, m - 1, d);
		const now = new Date();
		const today = Date.UTC(now.getFullYear(), now.getMonth(), now.getDate());
		return Math.round((target - today) / 86400000);
	}

	function expiryTag(server) {
		const days = daysUntil(server.expiresOn);
		if (days === null) return "";
		let cls = "";
		let text = `到期 ${server.expiresOn}`;
		if (days < 0) {
			cls = "danger";
			text += ` · 已过期 ${-days} 天`;
		} else if (days === 0) {
			cls = "danger";
			text += " · 今天到期";
		} else if (days <= 14) {
			cls = "warn";
			text += ` · 剩 ${days} 天`;
		} else {
			text += ` · 剩 ${days} 天`;
		}
		return `<span class="tag ${cls}">${escapeHtml(text)}</span>`;
	}

	/* ----------------------------------------------------------- file manager */

	function humanSize(bytes) {
		if (!Number.isFinite(bytes) || bytes <= 0) return "";
		const units = ["B", "K", "M", "G", "T"];
		let value = bytes;
		let unit = 0;
		while (value >= 1024 && unit < units.length - 1) {
			value /= 1024;
			unit += 1;
		}
		return `${value >= 10 || unit === 0 ? Math.round(value) : value.toFixed(1)}${units[unit]}`;
	}

	function shellQuote(value) {
		return "'" + String(value).replace(/'/g, "'\\''") + "'";
	}

	function requestDir(path) {
		if (!state.ws || state.ws.readyState !== WebSocket.OPEN) return;
		const id = ++files.seq;
		files.pending.set(id, path);
		files.loading.add(path);
		files.errors.delete(path);
		send({ t: "ls", p: path, n: id });
	}

	function onDirListing(message) {
		const requested = files.pending.get(message.n);
		files.pending.delete(message.n);
		if (requested) files.loading.delete(requested);

		if (message.error) {
			files.errors.set(requested || message.p || "?", message.error);
			renderTree();
			return;
		}

		const path = message.p;
		files.errors.delete(path);
		files.entries.set(path, message.entries || []);
		if (message.home) files.home = message.home;
		if (!files.root) {
			files.root = path;
			$("files-root").title = `复制根路径：${path}`;
			$("files-root-label").textContent = files.home && path === files.home ? `~ ${path}` : path;
			// Re-hydrate anything the user had expanded before a refresh.
			for (const expandedPath of files.expanded) {
				if (!files.entries.has(expandedPath)) requestDir(expandedPath);
			}
		}
		if (message.truncated) files.hint = "目录条目过多，仅显示前 600 项";
		renderTree();
	}

	function treeErrorRow(text, depth) {
		const row = document.createElement("div");
		row.className = "tree-error";
		row.style.paddingLeft = `${10 + depth * 14}px`;
		row.textContent = text;
		return row;
	}

	function buildRow(entry, depth) {
		const row = document.createElement("div");
		row.className = "tree-row" + (entry.type === "dir" ? " is-dir" : "") + (entry.link ? " is-link" : "");
		row.dataset.path = entry.path;
		row.style.paddingLeft = `${6 + depth * 14}px`;

		const twist = document.createElement("button");
		twist.type = "button";
		twist.className = "twist";
		if (entry.type === "dir") {
			twist.textContent = files.expanded.has(entry.path) ? "▾" : "▸";
			twist.setAttribute("aria-label", files.expanded.has(entry.path) ? "收起" : "展开");
		} else {
			twist.disabled = true;
			twist.style.visibility = "hidden";
		}

		const icon = document.createElement("span");
		icon.className = `fico ${entry.type === "dir" ? "dir" : "file"}`;

		const name = document.createElement("span");
		name.className = "fname";
		name.textContent = entry.name;
		name.title = entry.path;

		const size = document.createElement("span");
		size.className = "fsize";
		size.textContent = entry.type === "dir" ? "" : humanSize(entry.size);

		const actions = document.createElement("span");
		actions.className = "facts";
		if (entry.type === "dir") {
			const cd = document.createElement("button");
			cd.type = "button";
			cd.className = "act cd";
			cd.dataset.act = "cd";
			cd.textContent = "cd";
			cd.title = `把 cd ${entry.path} 粘贴到终端（不回车）`;
			actions.appendChild(cd);
		} else {
			const preview = document.createElement("button");
			preview.type = "button";
			preview.className = "act";
			preview.dataset.act = "preview";
			preview.textContent = "预览";
			preview.title = "在线预览（文本 / 图片）";
			actions.appendChild(preview);

			const download = document.createElement("button");
			download.type = "button";
			download.className = "act";
			download.dataset.act = "download";
			download.textContent = "下载";
			download.title = "下载到本机";
			actions.appendChild(download);
		}
		const copy = document.createElement("button");
		copy.type = "button";
		copy.className = "act";
		copy.dataset.act = "copy";
		copy.textContent = "路径";
		copy.title = "复制路径";
		actions.appendChild(copy);

		row.append(twist, icon, name, size, actions);
		return row;
	}

	function appendDir(container, path, depth) {
		if (files.loading.has(path) && !files.entries.has(path)) {
			const loading = document.createElement("div");
			loading.className = "tree-loading";
			loading.style.paddingLeft = `${10 + depth * 14}px`;
			loading.textContent = "加载中…";
			container.appendChild(loading);
			return;
		}
		const error = files.errors.get(path);
		if (error) {
			container.appendChild(treeErrorRow(error, depth));
			return;
		}
		const entries = files.entries.get(path);
		if (!entries) {
			requestDir(path);
			return;
		}
		if (entries.length === 0) {
			const empty = document.createElement("div");
			empty.className = "files-empty";
			empty.style.paddingLeft = `${10 + depth * 14}px`;
			empty.textContent = "（空目录）";
			container.appendChild(empty);
			return;
		}
		for (const entry of entries) {
			container.appendChild(buildRow(entry, depth));
			if (entry.type === "dir" && files.expanded.has(entry.path)) {
				appendDir(container, entry.path, depth + 1);
			}
		}
	}

	function renderTree() {
		const tree = $("files-tree");
		if (!tree) return;
		const scrollTop = tree.scrollTop;
		tree.textContent = "";
		if (!files.root) {
			const empty = document.createElement("div");
			empty.className = "files-empty";
			empty.textContent = files.hint;
			tree.appendChild(empty);
			tree.scrollTop = scrollTop;
			return;
		}
		appendDir(tree, files.root, 0);
		tree.scrollTop = scrollTop;
	}

	function toggleDir(path) {
		if (files.expanded.has(path)) files.expanded.delete(path);
		else files.expanded.add(path);
		renderTree();
	}

	function resetFiles(reason) {
		files.home = null;
		files.root = null;
		files.entries.clear();
		files.expanded.clear();
		files.loading.clear();
		files.errors.clear();
		files.pending.clear();
		files.hint = reason || "连接后加载…";
		$("files-root-label").textContent = "~";
		renderTree();
		if (files.open && reason === undefined) requestDir("~");
	}

	function insertCd(path) {
		if (!state.ws || state.ws.readyState !== WebSocket.OPEN) {
			toast("会话未连接，无法粘贴命令", true);
			return;
		}
		send({ t: "i", d: `cd ${shellQuote(path)}` });
		if (state.term) state.term.focus();
		toast(`已粘贴 cd ${path}，按 Enter 执行`);
	}

	async function copyPath(path) {
		if (!path) return;
		try {
			await navigator.clipboard.writeText(path);
			toast(`已复制 ${path}`);
		} catch {
			toast("浏览器拒绝写入剪贴板", true);
		}
	}

	function fileName(path) {
		return path.slice(path.lastIndexOf("/") + 1) || "download";
	}

	/** Fresh ticket that is bound to this browser session's Durable Object. */
	async function sessionTicket() {
		if (!state.session) throw new Error("会话未连接");
		const { ticket } = await api(`/api/servers/${state.session.id}/session`, {
			method: "POST",
			body: JSON.stringify({ sid: state.sessionId }),
		});
		return ticket;
	}

	async function fetchFile(path, mode) {
		const ticket = await sessionTicket();
		const query = new URLSearchParams({ sid: state.sessionId, path, mode });
		const response = await fetch(`/api/servers/${state.session.id}/file?${query}`, {
			headers: { "x-ticket": ticket },
			credentials: "same-origin",
		});
		if (!response.ok) {
			const detail = await response.text().catch(() => "");
			throw new Error(detail.slice(0, 180) || `${response.status} ${response.statusText}`);
		}
		return response;
	}

	async function downloadFile(path) {
		const name = fileName(path);
		toast(`开始下载 ${name}`);
		try {
			const response = await fetchFile(path, "download");
			const blob = await response.blob();
			const url = URL.createObjectURL(blob);
			const link = document.createElement("a");
			link.href = url;
			link.download = name;
			document.body.appendChild(link);
			link.click();
			link.remove();
			setTimeout(() => URL.revokeObjectURL(url), 30_000);
			toast(`已下载 ${name}（${humanSize(blob.size)}）`);
		} catch (error) {
			toast(error.message, true);
		}
	}

	function closePreview() {
		$("preview-modal").classList.add("hidden");
		$("preview-text").textContent = "";
		$("preview-image").removeAttribute("src");
		if (state.preview.url) {
			URL.revokeObjectURL(state.preview.url);
			state.preview.url = null;
		}
		state.preview.path = null;
	}

	async function previewFile(path) {
		state.preview.path = path;
		$("preview-title").textContent = fileName(path);
		$("preview-meta").textContent = "加载中…";
		$("preview-text").classList.add("hidden");
		$("preview-text").textContent = "";
		$("preview-image-wrap").classList.add("hidden");
		$("preview-modal").classList.remove("hidden");

		try {
			const response = await fetchFile(path, "preview");
			const type = response.headers.get("content-type") || "application/octet-stream";
			const size = Number(response.headers.get("x-file-size") || 0);
			const truncated = response.headers.get("x-truncated") === "1";
			const blob = await response.blob();
			const sizeLabel = size ? humanSize(size) : "";
			$("preview-meta").textContent = truncated ? `${sizeLabel} · 仅显示前 ${humanSize(blob.size)}` : sizeLabel;

			if (type.startsWith("image/")) {
				if (state.preview.url) URL.revokeObjectURL(state.preview.url);
				state.preview.url = URL.createObjectURL(blob);
				$("preview-image").src = state.preview.url;
				$("preview-image-wrap").classList.remove("hidden");
				return;
			}
			if (type.startsWith("text/")) {
				const text = await blob.text();
				$("preview-text").textContent = text;
				$("preview-text").classList.remove("hidden");
				return;
			}
			$("preview-text").textContent = "这个文件类型无法在线预览，请下载后查看。";
			$("preview-text").classList.remove("hidden");
		} catch (error) {
			$("preview-text").textContent = `预览失败：${error.message}`;
			$("preview-text").classList.remove("hidden");
			$("preview-meta").textContent = "";
		}
	}

	function toggleFilesPanel(force) {
		files.open = force === undefined ? !files.open : force;
		localStorage.setItem(FILES_KEY, files.open ? "1" : "0");
		$("term-main").classList.toggle("files-hidden", !files.open);
		if (files.open && !files.root && state.ws && state.ws.readyState === WebSocket.OPEN) {
			requestDir("~");
			renderTree();
		}
		fitTerminal();
	}

	/**
	 * Ends the Cloudflare Access session.
	 *
	 * Access clears its HttpOnly cookie only when /cdn-cgi/access/logout is
	 * visited, so JS cannot just delete it. A hidden same-origin iframe does the
	 * job without showing Access' logout page; if that is blocked we fall back to
	 * a top-level navigation to the team-domain logout endpoint.
	 */
	async function logout() {
		if (!confirm("退出登录？下次访问需要重新通过 Google 验证。")) return;
		teardownSession();

		const frame = document.createElement("iframe");
		frame.setAttribute("aria-hidden", "true");
		frame.style.cssText = "position:absolute;width:0;height:0;border:0;visibility:hidden";
		frame.src = "/cdn-cgi/access/logout";
		document.body.appendChild(frame);

		await new Promise((resolve) => setTimeout(resolve, 1400));

		let loggedOut = false;
		try {
			const probe = await fetch("/api/me", { credentials: "same-origin", redirect: "manual" });
			loggedOut = probe.type === "opaqueredirect" || probe.status === 401 || probe.status === 403 || probe.status === 302;
		} catch {
			loggedOut = true;
		}
		frame.remove();

		if (loggedOut) {
			location.assign("/");
			return;
		}
		// The iframe was blocked or the cookie survived: log out in the top frame.
		location.assign(state.me?.logoutUrl || "/cdn-cgi/access/logout");
	}

	/* --------------------------------------------------------------- servers */

	async function loadMe() {
		try {
			state.me = await api("/api/me");
			$("identity").textContent = state.me.email + (state.me.devBypass ? " · 本地开发" : "");
			$("logout").classList.toggle("hidden", !state.me.logoutUrl);
		} catch (error) {
			$("identity").textContent = "未认证";
			document.querySelector("#view-list .page").innerHTML =
				`<div class="empty"><div class="empty-icon">🔒</div><h2>需要 Cloudflare Access 认证</h2><p>${escapeHtml(error.message)}</p></div>`;
		}
	}

	async function loadServers(force = false) {
		if (state.servers && !force && Date.now() - state.loadedAt < 30_000) return state.servers;
		const { servers } = await api("/api/servers");
		state.servers = servers;
		state.loadedAt = Date.now();
		renderServers();
		return servers;
	}

	function serverById(id) {
		return (state.servers || []).find((server) => server.id === id);
	}

	function renderServers() {
		const servers = state.servers || [];
		$("summary").textContent = servers.length ? `共 ${servers.length} 台 · 点「连接」进入 Web 终端` : "还没有服务器";
		$("empty").classList.toggle("hidden", servers.length > 0);

		const list = $("list");
		list.innerHTML = "";
		for (const server of servers) {
			const card = document.createElement("article");
			card.className = "card";
			card.innerHTML = `
				<div class="card-head">
					<span class="card-title">${escapeHtml(server.name)}</span>
					<span class="card-note">${escapeHtml(server.note || "")}</span>
				</div>
				<a class="addr" href="/s/${server.id}/terminal" data-link>${escapeHtml(server.username)}@${escapeHtml(server.host)}:${server.port}</a>
				<div class="meta">
					<span class="tag">${server.authType === "key" ? "私钥" : "密码"}</span>
					${expiryTag(server)}
					<span class="tag ${server.hostKeyPinned ? "ok" : "warn"}">${server.hostKeyPinned ? "主机密钥已固定" : "主机密钥未固定"}</span>
					<span class="tag">最近连接 ${escapeHtml(fmtTime(server.lastUsedAt))}</span>
				</div>
				<div class="card-actions">
					<a class="btn primary sm" href="/s/${server.id}/terminal" data-link>连接</a>
					<button class="btn ghost sm" data-act="probe">测试</button>
					<button class="btn ghost sm" data-act="edit">编辑</button>
					<button class="btn danger sm" data-act="delete">删除</button>
				</div>`;
			card.querySelector('[data-act="probe"]').addEventListener("click", () => probe(server));
			card.querySelector('[data-act="edit"]').addEventListener("click", () => openForm(server));
			card.querySelector('[data-act="delete"]').addEventListener("click", () => remove(server));
			list.appendChild(card);
		}
	}

	/* ------------------------------------------------------------------ form */

	function openForm(server) {
		$("modal-title").textContent = server ? "编辑服务器" : "添加服务器";
		$("f-id").value = server ? server.id : "";
		$("f-name").value = server ? server.name : "";
		$("f-note").value = server ? server.note || "" : "";
		$("f-expires").value = server ? server.expiresOn || "" : "";
		$("f-host").value = server ? server.host : "";
		$("f-port").value = server ? String(server.port) : "22";
		$("f-username").value = server ? server.username : "root";
		$("f-auth").value = server ? server.authType : "password";
		$("f-credential").value = "";
		$("f-passphrase").value = "";
		$("form-error").textContent = "";
		$("f-credential").required = !server;
		syncAuthFields(server);
		$("modal").classList.remove("hidden");
		setTimeout(() => $("f-name").focus(), 30);
	}

	function syncAuthFields(server) {
		const auth = $("f-auth").value;
		const editing = Boolean(server);
		$("passphrase-wrap").hidden = auth !== "key";
		$("credential-label").textContent = auth === "key" ? "私钥（PEM / OpenSSH）" : "密码";
		$("f-credential").placeholder = auth === "key" ? "-----BEGIN OPENSSH PRIVATE KEY-----" : editing ? "留空表示保持不变" : "登录密码";
		$("f-credential").rows = auth === "key" ? 7 : 3;
		$("credential-hint").textContent =
			auth === "key"
				? "支持 RSA / ECDSA / Ed25519 私钥，AES-256-GCM 加密后存入 KV。"
				: "密码只用于建立 SSH 连接，AES-256-GCM 加密后存入 KV。";
	}

	function closeForm() {
		$("modal").classList.add("hidden");
	}

	async function submitForm(event) {
		event.preventDefault();
		const id = $("f-id").value;
		const payload = {
			name: $("f-name").value,
			note: $("f-note").value,
			host: $("f-host").value,
			port: Number($("f-port").value),
			username: $("f-username").value,
			authType: $("f-auth").value,
			expiresOn: $("f-expires").value.trim(),
		};
		const credential = $("f-credential").value;
		if (credential) payload.credential = credential;
		const passphrase = $("f-passphrase").value;
		if (passphrase) payload.passphrase = passphrase;

		$("form-error").textContent = "";
		$("save").disabled = true;
		try {
			if (id) {
				await api(`/api/servers/${id}`, { method: "PUT", body: JSON.stringify(payload) });
				toast("已保存");
			} else {
				await api("/api/servers", { method: "POST", body: JSON.stringify(payload) });
				toast("已添加");
			}
			closeForm();
			await loadServers(true);
		} catch (error) {
			$("form-error").textContent = error.message;
		} finally {
			$("save").disabled = false;
		}
	}

	async function remove(server) {
		if (!confirm(`删除 ${server.name}？凭据和主机密钥固定记录都会被移除。`)) return;
		try {
			await api(`/api/servers/${server.id}`, { method: "DELETE" });
			toast("已删除");
			await loadServers(true);
			if (currentRoute().id === server.id) navigate("/", { replace: true });
		} catch (error) {
			toast(error.message, true);
		}
	}

	function renderHints(hints) {
		const list = $("probe-hints");
		list.innerHTML = "";
		const items = (hints || []).filter(Boolean);
		list.classList.toggle("hidden", items.length === 0);
		for (const hint of items) {
			const li = document.createElement("li");
			li.textContent = hint;
			list.appendChild(li);
		}
	}

	async function probe(server) {
		$("probe-output").textContent = "检测中…（SSH 握手 + 系统信息，失败时自动做 TCP 诊断）";
		renderHints([]);
		$("probe-modal").classList.remove("hidden");
		try {
			const result = await api(`/api/servers/${server.id}/probe`, { method: "POST" });
			if (result.ok) {
				$("probe-output").textContent = `${result.output}\n\n— 往返 ${result.latencyMs} ms`;
				return;
			}
			const resolved = (result.resolved || []).length ? `\n\n解析地址：${result.resolved.join(", ")}` : "";
			const extra = result.diagnosis && result.diagnosis !== result.error ? `\n\n诊断：${result.diagnosis}` : "";
			$("probe-output").textContent = `失败（${result.latencyMs} ms）\n${result.error}${resolved}${extra}`;
			renderHints(result.hints);
		} catch (error) {
			$("probe-output").textContent = `失败\n${error.message}`;
			renderHints([]);
		}
	}

	/* -------------------------------------------------------------- terminal */

	// Hardcoded: Consolas is the only face that measures and renders consistently
	// here (Windows). A single family keeps xterm's canvas measurement and the DOM
	// rendering in sync — font *lists* are what caused the letter-spacing squeeze.
	// On machines without Consolas the drift check below falls back to `monospace`.
	const TERM_FONT = "Consolas";
	const FALLBACK_FONT = "monospace";

	function storedFontSize() {
		const value = Number(localStorage.getItem(FONT_KEY));
		return Number.isFinite(value) && value >= MIN_FONT && value <= MAX_FONT ? value : 14;
	}

	function terminalInstance() {
		if (state.term) return state.term;
		const TerminalCtor = window.Terminal || (window.Xterm && window.Xterm.Terminal);
		const FitCtor = window.FitAddon && (window.FitAddon.FitAddon || window.FitAddon);
		if (!TerminalCtor || !FitCtor) throw new Error("xterm.js 加载失败（CDN 不可达？）");

		state.fontSize = storedFontSize();
		const term = new TerminalCtor({
			fontFamily: TERM_FONT,
			fontSize: state.fontSize,
			fontWeight: "400",
			fontWeightBold: "700",
			lineHeight: 1.2,
			letterSpacing: 0,
			rescaleOverlappingGlyphs: true,
			cursorBlink: true,
			cursorStyle: "bar",
			scrollback: 8000,
			allowProposedApi: true,
			drawBoldTextInBrightColors: false,
			theme: {
				background: "#ffffff",
				foreground: "#10292d",
				cursor: "#1f7889",
				cursorAccent: "#ffffff",
				selectionBackground: "rgba(37,130,146,0.18)",
				black: "#10292d",
				red: "#b8412f",
				green: "#2f7d5e",
				yellow: "#8a6a12",
				blue: "#1f6f8b",
				magenta: "#7a4f8f",
				cyan: "#16697a",
				white: "#d7e5e8",
				brightBlack: "#7e999f",
				brightRed: "#c9553f",
				brightGreen: "#3f9573",
				brightYellow: "#a8811c",
				brightBlue: "#2b87a4",
				brightMagenta: "#93629f",
				brightCyan: "#258292",
				brightWhite: "#f2f7f8",
			},
		});
		const fit = new FitCtor();
		term.loadAddon(fit);
		term.open($("term-body"));
		term.onData((data) => send({ t: "i", d: data }));

		state.term = term;
		state.fit = fit;
		updateFontLabel();
		loadRenderers(term);

		if (typeof ResizeObserver !== "undefined") {
			state.resizeObserver = new ResizeObserver(() => scheduleFit());
			state.resizeObserver.observe($("term-body"));
		}

		document.fonts?.ready.then(() => {
			try {
				verifyTerminalFont();
				if (isTerminalView()) fitTerminal();
			} catch {
				/* ignore */
			}
		});
		return term;
	}

	function updateFontLabel() {
		$("term-font-dec").disabled = state.fontSize <= MIN_FONT;
		$("term-font-inc").disabled = state.fontSize >= MAX_FONT;
	}

	function changeFont(delta) {
		const next = Math.min(MAX_FONT, Math.max(MIN_FONT, (state.fontSize || 14) + delta));
		if (next === state.fontSize) return;
		state.fontSize = next;
		localStorage.setItem(FONT_KEY, String(next));
		if (state.term) state.term.options.fontSize = next;
		updateFontLabel();
		fitTerminal();
	}

	function setStatus(text, kind) {
		$("term-status").textContent = text;
		$("term-dot").className = "dot" + (kind ? " " + kind : "");
		$("term-meta").textContent = text;
	}

	function setMetric(id, value) {
		$(id).textContent = value;
	}

	function fitTerminal() {
		if (!state.fit || !state.term) return;
		try {
			state.fit.fit();
		} catch {
			/* hidden */
		}
		if (state.ws && state.ws.readyState === WebSocket.OPEN) {
			send({ t: "r", c: state.term.cols, r: state.term.rows });
		}
	}

	/** Debounced refit: the container changes size on rotation and on mobile keyboards. */
	function scheduleFit() {
		clearTimeout(state.fitTimer);
		state.fitTimer = setTimeout(() => {
			if (isTerminalView()) fitTerminal();
		}, 80);
	}

	function send(message) {
		if (state.ws && state.ws.readyState === WebSocket.OPEN) state.ws.send(JSON.stringify(message));
	}

	function isTerminalView() {
		return !$("view-terminal").classList.contains("hidden");
	}

	function currentRoute() {
		const path = location.pathname.replace(/\/+$/, "") || "/";
		const match = /^\/s\/([a-f0-9]{6,32})(?:\/terminal)?$/.exec(path);
		if (match) return { name: "terminal", id: match[1] };
		return { name: "list", id: null };
	}

	function navigate(path, options = {}) {
		if (path === location.pathname + location.search) {
			render();
			return;
		}
		if (options.replace) history.replaceState({}, "", path);
		else history.pushState({}, "", path);
		render();
	}

	async function enterTerminal(id) {
		if (state.session && state.session.id === id && state.ws) return; // already attached
		teardownSession();

		let server = serverById(id);
		if (!server) {
			try {
				await loadServers(true);
			} catch (error) {
				toast(error.message, true);
			}
			server = serverById(id);
		}
		if (!server) {
			toast("服务器不存在或已被删除", true);
			navigate("/", { replace: true });
			return;
		}

		state.session = server;
		state.sessionId = crypto.randomUUID();
		$("term-name").textContent = server.name;
		$("term-addr").textContent = `${server.username}@${server.host}:${server.port}`;
		document.title = `${server.name} · SSH Worker`;
		setStatus("连接中…", "");
		setMetric("metric-handshake", "—");
		setMetric("metric-rtt", "—");
		setMetric("metric-timer", "00:00:00");

		const term = terminalInstance();
		term.reset();
		term.write("\x1b[38;2;31;120;137m* 建立 SSH 连接…\x1b[0m\r\n");
		setTimeout(fitTerminal, 40);

		// Pre-flight through the Worker: readable errors instead of a bare WS failure.
		try {
			await api(`/api/servers/${server.id}/session`, {
				method: "POST",
				body: JSON.stringify({ sid: state.sessionId }),
			});
		} catch (error) {
			setStatus("失败", "err");
			term.write(`\r\n\x1b[38;2;184;65;47mx ${error.message}\x1b[0m\r\n`);
			return;
		}
		connectSocket(server);
	}

	function connectSocket(server) {
		if (state.ws) {
			state.ws.onclose = null;
			state.ws.close();
			state.ws = null;
		}
		const scheme = location.protocol === "https:" ? "wss:" : "ws:";
		const ws = new WebSocket(`${scheme}//${location.host}/api/servers/${server.id}/terminal?sid=${state.sessionId}`);
		state.ws = ws;

		ws.onopen = () => {
			setStatus("握手中…", "");
			fitTerminal();
		};

		ws.onmessage = (event) => {
			let message;
			try {
				message = JSON.parse(event.data);
			} catch {
				return;
			}
			const term = state.term;
			if (message.t === "o") {
				term.write(message.d);
				return;
			}
			if (message.t === "s") {
				setStatus(message.m, "");
				term.write(`\x1b[38;2;85;116;122m- ${message.m}\x1b[0m\r\n`);
				return;
			}
			if (message.t === "e") {
				setStatus(message.m, "err");
				term.write(`\r\n\x1b[38;2;184;65;47mx ${message.m}\x1b[0m\r\n`);
				return;
			}
			if (message.t === "ready") {
				setStatus("已连接", "live");
				setMetric("metric-handshake", fmtLatency(message.ms));
				resetFiles();
				startMetrics();
				verifyTerminalFont();
				focusTerminal();
				// Two passes: the first lays the screen out, the second recovers from
				// a container that was still 0-height when the socket opened.
				fitTerminal();
				requestAnimationFrame(() => fitTerminal());
				return;
			}
			if (message.t === "lsr") {
				onDirListing(message);
				return;
			}
			if (message.t === "pong") {
				state.lastPong = Date.now();
				if (message.n) setMetric("metric-rtt", fmtLatency(Date.now() - message.n));
				return;
			}
			if (message.t === "x") {
				setStatus(message.m || "已断开", "err");
				term.write(`\r\n\x1b[38;2;85;116;122m- ${message.m || "session closed"}\x1b[0m\r\n`);
			}
		};

		ws.onclose = (event) => {
			if (state.ws !== ws) return;
			state.ws = null;
			stopMetrics();
			resetFiles("会话已断开，点击「重连」");
			if (event.code === 1000) {
				setStatus("已断开", "");
			} else {
				setStatus(`连接断开 (${event.code})`, "err");
				if (event.code !== 1005 && event.code !== 1006 && state.term) {
					state.term.write(`\r\n\x1b[38;2;85;116;122m- closed ${event.code}\x1b[0m\r\n`);
				}
			}
		};

		ws.onerror = () => setStatus("网络错误", "err");
	}

	/**
	 * xterm sizes its grid from canvas measureText, then draws with real DOM text.
	 * If those two disagree (e.g. the canvas engine honours only the first font of
	 * the list), every span gets letter-spacing compensation and glyphs overlap.
	 * Compare both and fall back to the single generic family when they diverge.
	 */
	function verifyTerminalFont() {
		const term = state.term;
		if (!term) return;
		try {
			const rowsEl = $("term-body").querySelector(".xterm-screen") || $("term-body").querySelector(".xterm-rows");
			if (!rowsEl) return;
			const probe = document.createElement("div");
			probe.style.cssText = "position:absolute;top:-9999px;left:-9999px;visibility:hidden;white-space:pre;";
			probe.style.fontFamily = term.options.fontFamily;
			probe.style.fontSize = `${term.options.fontSize}px`;
			probe.style.fontWeight = term.options.fontWeight || "normal";
			probe.textContent = "0".repeat(term.cols);
			$("term-body").appendChild(probe);
			const domWidth = probe.getBoundingClientRect().width;
			probe.remove();
			const gridWidth = rowsEl.getBoundingClientRect().width;
			const drift = Math.abs(domWidth - gridWidth) / Math.max(1, gridWidth);
			if (drift > 0.04 && term.options.fontFamily !== FALLBACK_FONT) {
				term.options.fontFamily = FALLBACK_FONT;
				console.warn(`[ssh-worker] font metrics drift ${(drift * 100).toFixed(1)}%, switched to monospace`);
				fitTerminal();
			}
		} catch {
			/* best effort */
		}
	}

	/**
	 * WebGL first, DOM as the fallback. The WebGL renderer draws glyphs on a
	 * canvas at fixed cell coordinates, so it is immune to the per-span
	 * letter-spacing compensation the DOM renderer applies.
	 */
	function loadRenderers(term) {
		state.renderer = "dom";
		const WebglCtor = window.WebglAddon && (window.WebglAddon.WebglAddon || window.WebglAddon);
		if (!WebglCtor) return;
		try {
			const addon = new WebglCtor();
			// A lost context (GPU reset, too many contexts, driver hiccup) leaves the
			// terminal blank; dropping the addon restores the DOM renderer.
			addon.onContextLoss(() => {
				try {
					addon.dispose();
				} catch {
					/* ignore */
				}
				state.renderer = "dom";
				console.warn("[ssh-worker] WebGL context lost, falling back to the DOM renderer");
				fitTerminal();
			});
			term.loadAddon(addon);
			state.renderer = "webgl";
			window.__sshWorkerRenderer = "webgl";
		} catch (error) {
			state.renderer = "dom";
			window.__sshWorkerRenderer = "dom";
			// The addon appends its canvas before probing the context; drop the leftover.
			for (const canvas of term.element?.querySelectorAll(".xterm-screen canvas") || []) canvas.remove();
			console.warn("[ssh-worker] WebGL unavailable, using the DOM renderer:", error && error.message);
		}
	}

	/** Focus the terminal without letting the browser scroll the page to it. */
	function focusTerminal() {
		try {
			state.term.focus();
		} catch {
			/* ignore */
		}
		if (window.scrollY !== 0 || window.scrollX !== 0) window.scrollTo(0, 0);
	}

	function startMetrics() {
		stopMetrics();
		state.sessionStart = Date.now();
		state.lastPong = Date.now();
		state.clockTimer = setInterval(() => {
			if (!state.sessionStart) return;
			setMetric("metric-timer", fmtDuration(Date.now() - state.sessionStart));
			if (Date.now() - state.lastPong > 12_000) setMetric("metric-rtt", "—");
		}, 1000);
		state.pingTimer = setInterval(() => {
			const n = Date.now();
			send({ t: "p", n });
		}, 5000);
	}

	function stopMetrics() {
		clearInterval(state.pingTimer);
		clearInterval(state.clockTimer);
		state.pingTimer = null;
		state.clockTimer = null;
	}

	function teardownSession() {
		stopMetrics();
		closePreview();
		state.sessionStart = 0;
		if (state.ws) {
			state.ws.onclose = null;
			state.ws.close(1000, "route change");
			state.ws = null;
		}
		state.session = null;
	}

	async function copySelection() {
		const term = state.term;
		const selection = term ? term.getSelection() : "";
		if (!selection) {
			toast("先在终端里选中要复制的内容");
			return;
		}
		try {
			await navigator.clipboard.writeText(selection);
			toast(`已复制 ${selection.length} 个字符`);
		} catch {
			toast("浏览器拒绝写入剪贴板", true);
		}
	}

	async function pasteClipboard() {
		try {
			const text = await navigator.clipboard.readText();
			if (text) send({ t: "i", d: text });
		} catch {
			toast("浏览器拒绝读取剪贴板", true);
		}
	}

	/* ---------------------------------------------------------------- router */

	async function render() {
		const route = currentRoute();
		document.body.classList.toggle("is-terminal", route.name === "terminal");
		if (route.name === "terminal") {
			$("view-list").classList.add("hidden");
			$("view-terminal").classList.remove("hidden");
			await enterTerminal(route.id);
			return;
		}

		teardownSession();
		$("view-terminal").classList.add("hidden");
		$("view-list").classList.remove("hidden");
		document.title = "SSH Worker · VPS 控制台";
		try {
			await loadServers();
		} catch (error) {
			toast(error.message, true);
		}
	}

	function bindEvents() {
		$("add").addEventListener("click", () => openForm(null));
		$("add2").addEventListener("click", () => openForm(null));
		$("refresh").addEventListener("click", () => loadServers(true).catch((error) => toast(error.message, true)));
		$("logout").addEventListener("click", () => void logout());
		$("close-modal").addEventListener("click", closeForm);
		$("cancel").addEventListener("click", closeForm);
		$("form").addEventListener("submit", submitForm);
		$("f-auth").addEventListener("change", () => syncAuthFields({ id: $("f-id").value, authType: $("f-auth").value }));
		$("close-probe").addEventListener("click", () => $("probe-modal").classList.add("hidden"));
		$("close-preview").addEventListener("click", closePreview);
		$("preview-download").addEventListener("click", () => {
			if (state.preview.path) downloadFile(state.preview.path);
		});

		$("term-back").addEventListener("click", (event) => {
			event.preventDefault();
			navigate("/");
		});
		$("term-close").addEventListener("click", () => navigate("/"));
		$("term-copy").addEventListener("click", copySelection);
		$("term-paste").addEventListener("click", pasteClipboard);
		$("term-reconnect").addEventListener("click", () => {
			if (!state.session) return;
			const server = state.session;
			teardownSession();
			state.session = null;
			enterTerminal(server.id);
		});
		$("term-font-dec").addEventListener("click", () => changeFont(-1));
		$("term-files").addEventListener("click", () => toggleFilesPanel());
		$("files-refresh").addEventListener("click", () => {
			if (!files.root) {
				if (state.ws && state.ws.readyState === WebSocket.OPEN) requestDir("~");
				return;
			}
			const keep = [...files.expanded];
			const root = files.root;
			files.entries.clear();
			files.errors.clear();
			files.expanded = new Set(keep);
			requestDir(root);
			renderTree();
		});
		$("files-collapse").addEventListener("click", () => {
			files.expanded.clear();
			renderTree();
		});
		$("files-root").addEventListener("click", () => copyPath(files.home || files.root));
		$("files-tree").addEventListener("click", (event) => {
			const row = event.target.closest(".tree-row");
			if (!row) return;
			const path = row.dataset.path;
			const act = event.target.closest(".act");
			if (act) {
				if (act.dataset.act === "cd") insertCd(path);
				else if (act.dataset.act === "copy") copyPath(path);
				else if (act.dataset.act === "preview") previewFile(path);
				else if (act.dataset.act === "download") downloadFile(path);
				return;
			}
			if (row.classList.contains("is-dir")) toggleDir(path);
		});
		$("term-font-inc").addEventListener("click", () => changeFont(1));

		document.addEventListener("click", (event) => {
			const link = event.target.closest("a[data-link]");
			if (!link) return;
			if (event.metaKey || event.ctrlKey || event.shiftKey || event.button !== 0) return;
			event.preventDefault();
			navigate(link.getAttribute("href"));
		});

		window.addEventListener("popstate", () => render());
		window.addEventListener("resize", () => {
			if (isTerminalView()) fitTerminal();
		});
		document.addEventListener("keydown", (event) => {
			if (event.key === "Escape" && isTerminalView() && $("modal").classList.contains("hidden")) {
				event.preventDefault();
				navigate("/");
			}
		});
	}

	document.addEventListener("DOMContentLoaded", async () => {
		bindEvents();
		files.open = localStorage.getItem(FILES_KEY) !== "0";
		$("term-main").classList.toggle("files-hidden", !files.open);
		await loadMe();
		await render();
	});
})();
