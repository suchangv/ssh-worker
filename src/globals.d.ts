/**
 * ssh2 ships no types and we only touch a handful of surfaces.
 * Kept minimal on purpose: anything not listed here is a compile error.
 */
declare module "ssh2" {
	import type { Duplex } from "node:stream";

	export interface Algorithms {
		kex?: string[];
		cipher?: string[];
		hmac?: string[];
		compress?: string[];
		serverHostKey?: string[];
	}

	export interface ConnectConfig {
		sock?: Duplex;
		host?: string;
		port?: number;
		username: string;
		password?: string;
		privateKey?: string;
		passphrase?: string;
		tryKeyboard?: boolean;
		readyTimeout?: number;
		keepaliveInterval?: number;
		keepaliveCountMax?: number;
		algorithms?: Algorithms;
		hostVerifier?: (key: Uint8Array, verify?: (ok: boolean) => void) => boolean | void;
	}

	export interface Channel {
		write(data: string | Uint8Array): boolean;
		setWindow(rows: number, cols: number, height: number, width: number): void;
		stderr?: { on(event: "data", cb: (chunk: Uint8Array) => void): void };
		on(event: "data", cb: (chunk: Uint8Array) => void): void;
		on(event: "close", cb: () => void): void;
		on(event: string, cb: (...args: unknown[]) => void): void;
		end(): void;
	}

	export interface ReadEntry {
		filename: string;
		longname: string;
		attrs: {
			size: number;
			mtime: number;
			mode: number;
			isDirectory(): boolean;
			isFile(): boolean;
			isSymbolicLink(): boolean;
		};
	}

	export interface SFTPStats {
		size: number;
		mtime: number;
		mode: number;
		isDirectory(): boolean;
		isFile(): boolean;
		isSymbolicLink(): boolean;
	}

	export interface SFTPWrapper {
		realpath(path: string, cb: (err: Error | undefined, abs: string) => void): void;
		stat(path: string, cb: (err: Error | undefined, stats: SFTPStats) => void): void;
		createReadStream(path: string, options?: { start?: number; end?: number }): NodeJS.ReadableStream;
		readdir(path: string, cb: (err: Error | undefined, list: ReadEntry[]) => void): void;
		end(): void;
	}

	export interface ShellOptions {
		term?: string;
		cols?: number;
		rows?: number;
		env?: Record<string, string>;
	}

	export class Client {
		connect(config: ConnectConfig): void;
		end(): void;
		destroy(): void;
		exec(command: string, callback: (error: Error | undefined, stream: Channel) => void): void;
		shell(options: ShellOptions, callback: (error: Error | undefined, stream: Channel) => void): void;
		sftp(callback: (error: Error | undefined, sftp: SFTPWrapper) => void): void;
		on(event: "ready", cb: () => void): void;
		on(event: "error", cb: (error: Error) => void): void;
		on(event: "close", cb: () => void): void;
		on(event: "banner", cb: (message: string) => void): void;
		on(
			event: "keyboard-interactive",
			cb: (
				name: string,
				instructions: string,
				lang: string,
				prompts: Array<{ prompt: string; echo: boolean }>,
				finish: (answers: string[]) => void,
			) => void,
		): void;
	}
}
