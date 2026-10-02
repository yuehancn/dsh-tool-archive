// Shared minimal harness for the dsh-tool-archive tests.
//
// It rebuilds the plugin's `apply` against the REAL @deepseek-ai/dsh-tools, so
// schema normalization (`required` hoisting, `additionalProperties` on every
// nested object, type enforcement) is exercised for real rather than against a
// hand-written stub.
//
// `apply(ctx, config)` receives an already schema-resolved config, so this
// context runs the caller's options through the real `Config` first and fills
// every missing key with its default. Passing a partial object straight through
// would silently register zero tools.
//
// One injectable seam matters here and it lives on an object the caller holds:
// `readArchive`, which lets a test hand the parser bytes that never came from
// disk. `apply` reads it off `ctx.transport` at each call site rather than
// capturing it, so a test can swap it after `apply` has run.
import {
	readFile, writeFile, mkdir, readdir, stat, lstat, symlink, link, rm, readlink
} from "node:fs/promises";
import { createHash } from "node:crypto";
import {
	basename, dirname, join, posix, relative, resolve, sep
} from "node:path";
import z from "@deepseek-ai/schemastery";
import { defineTool } from "@deepseek-ai/dsh-tools";

const source = await readFile(new URL("../lib/index.js", import.meta.url), "utf8");

// The import lines are stripped and re-bound as `new Function` parameters, and
// the export statements are dropped because the builder below re-exports.
//
// The export regex must span lines: plugins in this series write their
// internals as a multi-line `export { … };` block, and a single-line pattern
// would leave the bare `export` keyword behind — which `new Function` rejects.
// The import pattern must span lines as well: this plugin splits its
// `node:fs/promises` import across three lines, and a line-anchored pattern
// leaves the trailing `} from "node:fs/promises";` behind as a syntax error
// that reads like a plugin bug and is not one.
const body = source
	.replace(/^import[\s\S]*?from\s+"[^"]+";$/gm, "")
	.replace(/^import\s+"[^"]+";$/gm, "")
	.replace(/^export \{[\s\S]*?\};$/gm, "");

const INTERNALS = [
	"BLOCK", "CHECKSUM_OFFSET", "CHECKSUM_LENGTH", "USTAR_MAGIC", "USTAR_VERSION",
	"USTAR_NAME_MAX", "USTAR_PREFIX_MAX", "TYPE_FLAGS", "DANGEROUS_TYPES",
	"DEFAULT_EXCLUDES", "PACK_MODE_FILE", "PACK_MODE_DIR",
	"octalField", "encodePath", "padField", "tarHeader", "tarTrailer",
	"paddedLength", "readOctal", "readString", "checkChecksum", "isZeroBlock",
	"parseTar", "sha256", "toPosix", "resolveWithin", "resolveEntry",
	"resolveSource", "excludeSet", "walkTree", "packTree", "treeDigest",
	"planExtraction", "writePlan", "diffManifests", "manifestFromArchive",
	"manifestFromTree", "humanBytes", "stamp", "archivePath", "assertReadable",
	"readlinkSafe"
];

const build = new Function(
	"z", "defineTool", "createHash",
	"readFile", "writeFile", "mkdir", "readdir", "stat", "lstat", "symlink", "link", "rm", "readlink",
	"basename", "dirname", "join", "posix", "relative", "resolve", "sep",
	`${body}\nreturn { Config, apply, inject, name, ${INTERNALS.join(", ")} };`
);

/** The plugin's real exports plus its internals, for white-box assertions. */
export const plugin = build(
	z, defineTool, createHash,
	readFile, writeFile, mkdir, readdir, stat, lstat, symlink, link, rm, readlink,
	basename, dirname, join, posix, relative, resolve, sep
);

/**
 * Build a minimal cordis-like context that records registered tools and owns
 * the injectable seam.
 *
 * `apply` is *not* called automatically — tests call it explicitly, so a
 * registration toggle can be asserted before and after.
 *
 * @param {object} [options] - partial plugin config; missing keys take defaults.
 * @returns {{tools: object, config: object, transport: object, names: () => string[], get: (n: string) => any, has: (n: string) => boolean}} the context.
 */
export function Context(options = {}) {
	const config = plugin.Config(options);
	const registry = new Map();
	const tools = {
		register(definition) {
			registry.set(definition.name, definition);
		}
	};
	return {
		tools,
		config,
		// `apply` is expected to reuse this object in place, so a test's later
		// assignment is visible to every closure the tools captured.
		transport: {},
		names: () => [...registry.keys()],
		get: (n) => registry.get(n),
		has: (n) => registry.has(n)
	};
}

/**
 * Run a tool call and capture either its value or the thrown error, so tests
 * can assert on modelled failure paths without try/catch noise.
 *
 * @param {any} definition - a tool definition exposing `execute`.
 * @param {object} args - tool arguments.
 * @param {object} [options] - extra execute options (e.g. a fake signal).
 * @returns {Promise<{value?: any, error?: string}>} the outcome.
 */
export async function call(definition, args, options = {}) {
	try {
		return { value: await definition.execute(args, { signal: options.signal }) };
	} catch (error) {
		return { error: String(error?.message ?? error) };
	}
}

/**
 * Assert that the injectable archive reader was actually reached.
 *
 * A suite whose reader log is still empty after a call means the plugin went
 * to disk instead — which is the real filesystem, not the fixture. Making that
 * a loud failure is cheaper than debugging a suite that "passed" against the
 * wrong bytes.
 *
 * @param {Array<object>} calls - the fake's read log.
 * @param {string} label - a description for the error message.
 */
export function assertReaderUsed(calls, label) {
	if (calls.length === 0) {
		throw new Error(`${label}: the injected archive reader was never called, so the suite read the real filesystem.`);
	}
}

/**
 * Build a fake archive reader that serves fixed bytes and records every call.
 *
 * @param {Buffer} buffer - the bytes to serve.
 * @returns {{readArchive: Function, calls: Array<string>}} the fake and its log.
 */
export function fakeReader(buffer) {
	const calls = [];
	const readArchive = async (file) => {
		calls.push(file);
		return buffer;
	};
	return { readArchive, calls };
}

/**
 * A tiny in-memory tar *writer* for fixtures, independent of the plugin's.
 *
 * Fixtures must not be built with the code under test: a writer bug that
 * produced a malformed header would be mirrored by the reader and every
 * round-trip assertion would pass on a broken format. This writer is
 * deliberately naive and independent — plain octal fields, no prefix support —
 * so agreement between the two means something.
 *
 * @param {Array<object>} entries - `{name, kind, data, mode, mtime, linkname, flag}`.
 * @returns {Buffer} the archive.
 */
export function writeFixtureTar(entries) {
	const blocks = [];
	const pad = (text, width) => {
		const buf = Buffer.alloc(width);
		Buffer.from(text, "utf8").copy(buf, 0, 0, width);
		return buf;
	};
	const octal = (value, width) => pad(Math.trunc(value).toString(8).padStart(width - 1, "0"), width).subarray(0, width - 1);

	for (const entry of entries) {
		const header = Buffer.alloc(512);
		const isDir = entry.kind === "directory";
		const name = isDir && !entry.name.endsWith("/") ? `${entry.name}/` : entry.name;
		pad(name, 100).copy(header, 0);
		octal(entry.mode ?? (isDir ? 0o755 : 0o644), 8).copy(header, 100);
		octal(entry.uid ?? 0, 8).copy(header, 108);
		octal(entry.gid ?? 0, 8).copy(header, 116);
		octal(entry.rawSize ?? (entry.data ? Buffer.byteLength(entry.data) : 0), 12).copy(header, 124);
		octal(entry.mtime ?? 0, 12).copy(header, 136);
		header.fill(0x20, 148, 156);
		header.write(entry.flag ?? (isDir ? "5" : "0"), 156, 1, "latin1");
		if (entry.linkname) pad(entry.linkname, 100).copy(header, 157);
		header.write("ustar", 257, "latin1");
		header.write("\u0000", 262, 1, "latin1");
		header.write("00", 263, "latin1");
		if (entry.prefix) pad(entry.prefix, 155).copy(header, 345);
		if (entry.corruptMagic) header.write("xxxxx", 257, "latin1");

		let sum = 0;
		for (const byte of header) sum += byte;
		header.write(sum.toString(8).padStart(6, "0"), 148, 6, "latin1");
		header.write("\u0000", 154, 1, "latin1");
		header.write(" ", 155, 1, "latin1");

		blocks.push(header);
		if (entry.data) {
			const data = Buffer.from(entry.data, "utf8");
			blocks.push(data);
			const padding = Math.ceil(data.length / 512) * 512 - data.length;
			if (padding > 0) blocks.push(Buffer.alloc(padding));
		}
	}
	blocks.push(Buffer.alloc(1024));
	return Buffer.concat(blocks);
}

/**
 * A tree on disk, written from a literal map, for packing tests.
 *
 * @param {string} root - the directory to create the tree under.
 * @param {object} files - `{ "a/b.txt": "content" }`; a value of `null` makes a directory.
 * @returns {Promise<string>} the root.
 */
export async function makeTree(root, files) {
	await rm(root, { recursive: true, force: true });
	await mkdir(root, { recursive: true });
	for (const [relPath, content] of Object.entries(files)) {
		const full = join(root, relPath);
		if (content === null) {
			await mkdir(full, { recursive: true });
		} else {
			await mkdir(dirname(full), { recursive: true });
			await writeFile(full, content, "utf8");
		}
	}
	return root;
}

export default { plugin, Context, call, fakeReader, assertReaderUsed, writeFixtureTar, makeTree };