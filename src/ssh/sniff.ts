/**
 * Content sniffing for file previews.
 *
 * Extensions are a poor signal: dotfiles (`.bashrc`, `.profile`, `.gitconfig`),
 * `Makefile`, `Dockerfile` and `id_rsa` have no useful suffix, while a `.dat`
 * may well be text. Images are the only case worth deciding by name; everything
 * else is read (up to a limit) and classified by its bytes, the same way `git`
 * decides whether a file is binary.
 */

const IMAGE_TYPES: Record<string, string> = {
	png: "image/png",
	jpg: "image/jpeg",
	jpeg: "image/jpeg",
	gif: "image/gif",
	webp: "image/webp",
	bmp: "image/bmp",
	ico: "image/x-icon",
	avif: "image/avif",
};

export function extensionOf(name: string): string {
	const index = name.lastIndexOf(".");
	return index < 0 ? "" : name.slice(index + 1).toLowerCase();
}

/** MIME type when the file is a previewable image, otherwise undefined. */
export function imageTypeFor(name: string): string | undefined {
	return IMAGE_TYPES[extensionOf(name)];
}

/**
 * True when the buffer looks binary: it contains a NUL byte, or an unusual
 * share of other control characters. Only the first 8 KiB are inspected, which
 * is what editors and git do.
 */
export function looksBinary(bytes: Uint8Array): boolean {
	const sample = bytes.subarray(0, 8192);
	if (sample.length === 0) return false;
	for (const byte of sample) {
		if (byte === 0) return true;
	}
	let control = 0;
	for (const byte of sample) {
		// allow \b \t \n \v \f \r and everything >= 0x20
		if (byte < 7 || (byte > 13 && byte < 32)) control += 1;
	}
	return control / sample.length > 0.05;
}
