/**
 * Bridges a Workers TCP socket (`cloudflare:sockets`) into a Node-style Duplex
 * stream, which is what `ssh2` accepts through its `sock` option.
 */
import { connect } from "cloudflare:sockets";
import { Duplex } from "node:stream";

const encoder = new TextEncoder();

export interface TcpStream {
	duplex: Duplex;
}

export function openTcpStream(host: string, port: number): TcpStream {
	const socket = connect({ hostname: host, port }, { allowHalfOpen: false });
	const writer = socket.writable.getWriter();

	let closed = false;
	/**
	 * Closing an already-finished socket makes workerd spin until the isolate
	 * OOMs (observed in local dev), so this runs at most once and never aborts
	 * the writer — `final()` already closes it in the normal path.
	 */
	const closeSocket = () => {
		if (closed) return;
		closed = true;
		try {
			void socket.close();
		} catch {
			/* already closed */
		}
	};

	const duplex = new Duplex({
		read() {
			/* data is pushed from the socket reader below */
		},
		write(chunk: Uint8Array | string, _encoding: string, callback: (error?: Error | null) => void) {
			const bytes = typeof chunk === "string" ? encoder.encode(chunk) : chunk;
			writer.write(bytes).then(
				() => callback(),
				(error: unknown) => callback(error instanceof Error ? error : new Error(String(error))),
			);
		},
		final(callback: (error?: Error | null) => void) {
			writer.close().then(
				() => {
					// Marked before destroy() can run: closing twice makes workerd spin.
					closed = true;
					callback();
				},
				(error: unknown) => {
					closed = true;
					callback(error instanceof Error ? error : new Error(String(error)));
				},
			);
		},
		destroy(error: Error | null, callback: (error?: Error | null) => void) {
			closeSocket();
			callback(error);
		},
	});

	socket.readable
		.pipeTo(
			new WritableStream<Uint8Array>({
				write(chunk) {
					duplex.push(chunk);
				},
				close() {
					duplex.push(null);
				},
				abort(reason) {
					duplex.destroy(reason instanceof Error ? reason : new Error(String(reason)));
				},
			}),
		)
		.catch((error: unknown) => {
			duplex.destroy(error instanceof Error ? error : new Error(String(error)));
		});

	return { duplex };
}
