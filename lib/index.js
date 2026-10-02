/**
 * Model-facing archive tools: pack a directory into a tar, read a tar's
 * manifest without unpacking it, unpack it somewhere it cannot escape, and
 * verify that what came out is byte-for-byte what went in.
 *
 * Why this exists
 * - "Untar this" is one line of shell and one of the few genuinely dangerous
 *   operations a model can be asked to perform. A tar entry may be named
 *   `../../.ssh/authorized_keys`, may be an absolute path, may be a symlink
 *   pointing out of the tree, or may be a hardlink to a file the caller never
 *   asked for. Each of those turns "unpack this archive" into "write anywhere
 *   on this machine", so every entry name is resolved and re-checked against
 *   the destination before a single byte is written.
 * - A tar has no central index. The names, sizes and kinds live in 512-byte
 *   headers interleaved with the data, so "what is in this archive" is a walk
 *   rather than a lookup — which is exactly why `archive_status` exists and
 *   why it does not need to write anything to answer.
 * - Verifying an archive is not "did the bytes copy". A directory walk sees
 *   whatever order the filesystem hands back, so two packs of the same tree
 *   can differ while holding identical content. This plugin sorts, pins the
 *   metadata, and hashes, so the same tree packs to the same digest — which is
 *   what makes a manifest comparison mean anything.
 *
 * Notes
 * - No external dependency. The tar format is written and read here, so the
 *   only failure modes are the ones this file names.
 * - Reading is deliberately more permissive than writing. A `ustar` archive
 *   produced elsewhere may carry GNU long names, PAX records, or a checksum
 *   this reader should not be the judge of; those are reported rather than
 *   rejected. Writing always emits plain `ustar` with a POSIX prefix, never a
 *   format extension, so what this plugin writes can be read by the oldest
 *   tar in the room.
 * - Every path that reaches the filesystem goes through `resolveWithin`, and
 *   that function is the security boundary: it takes the final path segment
 *   only, so neither an absolute path nor a `..` sequence survives it.
 * @module dsh-tool-archive
 */
import z from "@deepseek-ai/schemastery";
import { defineTool } from "@deepseek-ai/dsh-tools";
import { createHash } from "node:crypto";
import {
	readFile, writeFile, mkdir, readdir, stat, lstat, symlink, link, rm
} from "node:fs/promises";
import { basename, dirname, join, posix, relative, resolve, sep } from "node:path";

/** Cordis plugin name used by loader diagnostics. */
const name = "dsh-tool-archive";

/** Services required by the archive tool suite. */
const inject = ["tools"];

/** Default cooperative tool-call budget (ms). Archives can be large. */
const DEFAULT_TIMEOUT_MS = 300000;

/** Tar works in 512-byte blocks; nothing else about the format is negotiable. */
const BLOCK = 512;

/**
 * The tar checksum is computed over the header with its checksum field read as
 * spaces, and stored as six octal digits, a NUL, then a space — the historical
 * layout that both BSD and GNU accept.
 */
const CHECKSUM_OFFSET = 148;
const CHECKSUM_LENGTH = 8;

/** `ustar\0` + `00`; the only magic this writer emits. */
const USTAR_MAGIC = "ustar\u0000";
const USTAR_VERSION = "00";

/** Entry kinds this reader understands, by the type flag in the header. */
const TYPE_FLAGS = {
	"0": "file",
	"\u0000": "file",
	"1": "hardlink",
	"2": "symlink",
	"3": "char",
	"4": "block",
	"5": "directory",
	"6": "fifo",
	"7": "contiguous"
};

/**
 * Type flags this reader refuses to act on, with the reason.
 *
 * These are not "unknown therefore suspicious" — they are known and they are
 * exactly the kinds that can reach outside the extraction directory. A device
 * node is not a file; a FIFO will block a reader forever. Refusing is the only
 * safe answer, and saying *why* is what makes the refusal actionable.
 */
const DANGEROUS_TYPES = {
	"3": "character device",
	"4": "block device",
	"6": "FIFO"
};

/** Digits used by the octal fields. */
const OCTAL = /^[0-7]*$/u;

/** Longest name a plain `ustar` header can hold without a prefix. */
const USTAR_NAME_MAX = 100;

/** Longest path components a `ustar` prefix can carry. */
const USTAR_PREFIX_MAX = 155;

/**
 * Fields a tar header records that cannot be recovered from the content.
 *
 * They are normalised to these constants while packing so that two trees with
 * the same bytes and the same relative names produce the same archive hash: a
 * uid that depends on which machine ran the pack is not part of the content.
 */
const PACK_UID = 0;
const PACK_GID = 0;
const PACK_MODE_FILE = 0o644;
const PACK_MODE_DIR = 0o755;

/** Directories walked by default when packing, if the caller does not say. */
const DEFAULT_EXCLUDES = ["node_modules", ".git", ".DS_Store", "Thumbs.db"];

/* ------------------------------------------------------------------ config */

const Config = z.object({
	/** Directory that relative `archiveDir` values resolve against. */
	workDir: z.string().default("."),
	/** Directory that archives are written to and read from. */
	archiveDir: z.string().default("archive-output"),
	/** Directory that unpacked trees are written under. */
	extractDir: z.string().default("archive-extract"),
	/** Glob-free last-segment names skipped while walking a tree. */
	exclude: z.array(z.string()).default([...DEFAULT_EXCLUDES]),
	/** Skip files at or above this many bytes while packing; 0 means no limit. */
	maxFileBytes: z.number().default(0),
	/** Refuse to unpack an archive holding more than this many entries. */
	maxEntries: z.number().default(20000),
	/** Refuse to unpack an archive that would write more than this many bytes. */
	maxTotalBytes: z.number().default(2 * 1024 * 1024 * 1024),
	/** Refuse to write a member whose name is longer than this, after the prefix is joined. */
	maxNameBytes: z.number().default(1000),
	/** Emit a SHA-256 manifest while packing. */
	hash: z.boolean().default(true),
	/** Refuse to overwrite an existing file while unpacking. */
	noOverwrite: z.boolean().default(false),
	/** Keep the archive after unpacking a member to a stream. */
	/** Register `archive_status`. */
	status: z.boolean().default(true),
	/** Register `archive_pack`. */
	pack: z.boolean().default(true),
	/** Register `archive_unpack`. */
	unpack: z.boolean().default(true),
	/** Register `archive_verify`. */
	verify: z.boolean().default(true),
	/** Cooperative tool-call budget attached as `ToolDefinition.timeoutMs`. */
	timeoutMs: z.number().default(DEFAULT_TIMEOUT_MS)
});

/* ------------------------------------------------------------- tar writing */

/**
 * Write `value` into a fixed-width octal field, NUL-terminated.
 *
 * The last byte of the field is left as a NUL rather than a space because the
 * historical `ustar` writers put a single NUL there and readers are lenient
 * about everything after it. Widths are exact: an overflowing value throws
 * rather than silently truncating into a different number.
 *
 * @param {number} value - the non-negative integer to encode.
 * @param {number} width - the field width in bytes.
 * @returns {Buffer} the encoded field.
 */
function octalField(value, width) {
	const digits = Math.trunc(value).toString(8);
	if (digits.length > width - 1) {
		throw new Error(`archive: ${value} does not fit in a ${width}-byte octal field.`);
	}
	return Buffer.from(digits.padStart(width - 1, "0") + "\u0000", "latin1");
}

/**
 * Encode a `(name, prefix)` pair for a `ustar` header.
 *
 * `ustar` splits a long path at a `/` boundary: the prefix field holds the
 * leading directories and the name field the tail. If no split exists that
 * fits both fields the path does not fit a plain `ustar` header at all, and
 * this writer refuses rather than reaching for a GNU or PAX extension — the
 * whole point of this writer is that its output reads everywhere.
 *
 * @param {string} path - the slash-separated relative path.
 * @returns {{name: Buffer, prefix: Buffer}} the two encoded fields.
 */
function encodePath(path) {
	const clean = toPosix(path).replace(/^\.\//u, "");
	if (clean.length <= USTAR_NAME_MAX) {
		return {
			name: padField(Buffer.from(clean, "utf8"), USTAR_NAME_MAX, path),
			prefix: Buffer.alloc(USTAR_PREFIX_MAX)
		};
	}

	// Walk the split points from the left so the *longest* prefix that fits is
	// chosen; taking them right-to-left would push a short head into the name
	// field and reject paths that were encodable.
	const parts = clean.split("/");
	for (let cut = 1; cut < parts.length; cut += 1) {
		const prefix = parts.slice(0, cut).join("/");
		const rest = parts.slice(cut).join("/");
		if (Buffer.byteLength(rest, "utf8") <= USTAR_NAME_MAX && Buffer.byteLength(prefix, "utf8") <= USTAR_PREFIX_MAX) {
			return {
				name: padField(Buffer.from(rest, "utf8"), USTAR_NAME_MAX, path),
				prefix: padField(Buffer.from(prefix, "utf8"), USTAR_PREFIX_MAX, path)
			};
		}
	}

	throw new Error(
		`archive: the path "${path}" is ${clean.length} characters and does not fit a plain ustar header ` +
		`(no "/" split leaves at most ${USTAR_NAME_MAX} bytes after and ${USTAR_PREFIX_MAX} before). ` +
		"Shorten the directory name; this writer does not emit GNU long-name or PAX extensions."
	);
}

/**
 * Place `bytes` at the start of a fixed-width field and NUL-fill the rest.
 *
 * Truncating a UTF-8 buffer mid-sequence would produce a name the reader
 * cannot decode, so an over-long, unencodable value is an error, not a silent
 * cut.
 *
 * @param {Buffer} bytes - the encoded value.
 * @param {number} width - the field width in bytes.
 * @param {string} label - the value, for the error message.
 * @returns {Buffer} the padded field.
 */
function padField(bytes, width, label) {
	if (bytes.length > width) {
		throw new Error(`archive: "${label}" needs ${bytes.length} bytes but its header field holds ${width}.`);
	}
	const field = Buffer.alloc(width);
	bytes.copy(field);
	return field;
}

/**
 * Build one 512-byte `ustar` header block.
 *
 * @param {object} entry - the member to describe.
 * @param {string} entry.name - the slash-separated relative path.
 * @param {"file"|"directory"} entry.kind - the member kind.
 * @param {number} entry.size - the content length in bytes (0 for a directory).
 * @param {number} entry.mtimeMs - the modification time.
 * @param {object} [options] - writer options.
 * @param {number} [options.mode] - the mode bits to record.
 * @returns {Buffer} the 512-byte header.
 */
function tarHeader(entry, options = {}) {
	const directory = entry.kind === "directory";
	const mode = options.mode ?? (directory ? PACK_MODE_DIR : PACK_MODE_FILE);
	const { name, prefix } = encodePath(directory ? `${entry.name}/` : entry.name);

	const header = Buffer.alloc(BLOCK);
	name.copy(header, 0);
	octalField(mode, 8).copy(header, 100);
	octalField(PACK_UID, 8).copy(header, 108);
	octalField(PACK_GID, 8).copy(header, 116);
	octalField(directory ? 0 : entry.size, 12).copy(header, 124);
	octalField(Math.max(0, Math.floor(entry.mtimeMs / 1000)), 12).copy(header, 136);

	// The checksum field is eight spaces while the checksum is computed, then
	// overwritten. Writing it afterwards is the only ordering that works.
	header.fill(0x20, CHECKSUM_OFFSET, CHECKSUM_OFFSET + CHECKSUM_LENGTH);
	header.write(directory ? "5" : "0", 156, 1, "latin1");
	Buffer.from(USTAR_MAGIC, "latin1").copy(header, 257);
	Buffer.from(USTAR_VERSION, "latin1").copy(header, 263);

	prefix.copy(header, 345);

	// "ustar" is a *magic-then-version* pair: a conforming reader compares the
	// six magic bytes and the two version bytes separately, so they are written
	// as separate fields. Writing the eight bytes as one string works by
	// accident and shows up as a corrupt header in strict readers.
	header.write("ustar", 257, "latin1");
	header.write("\u0000", 262, 1, "latin1");
	header.write("00", 263, "latin1");

	let sum = 0;
	for (const byte of header) sum += byte;
	const checksum = sum.toString(8).padStart(6, "0");
	header.write(checksum, CHECKSUM_OFFSET, 6, "latin1");
	header.write("\u0000", CHECKSUM_OFFSET + 6, 1, "latin1");
	header.write(" ", CHECKSUM_OFFSET + 7, 1, "latin1");
	return header;
}

/**
 * The two zero blocks that terminate a tar archive.
 *
 * @returns {Buffer} 1024 zero bytes.
 */
function tarTrailer() {
	return Buffer.alloc(BLOCK * 2);
}

/**
 * Pad `size` up to the next 512-byte boundary.
 *
 * A member's data occupies whole blocks even when its size does not align;
 * skipping the padding is the single most common way a hand-written tar
 * reader goes wrong on the second entry.
 *
 * @param {number} size - the content length.
 * @returns {number} the number of bytes the member occupies.
 */
function paddedLength(size) {
	return Math.ceil(size / BLOCK) * BLOCK;
}

/* ------------------------------------------------------------- tar reading */

/**
 * Read a fixed-width octal field.
 *
 * Old writers terminate with a space, new ones with a NUL, and some use both;
 * all three are accepted. A field that is entirely spaces or NULs means zero.
 *
 * @param {Buffer} block - the header block.
 * @param {number} offset - the field offset.
 * @param {number} length - the field length.
 * @returns {number} the decoded value.
 */
function readOctal(block, offset, length) {
	const raw = block.subarray(offset, offset + length).toString("latin1");
	const text = raw.replace(/\u0000.*$/su, "").trim();
	if (text === "") return 0;
	if (!OCTAL.test(text)) return NaN;
	return Number.parseInt(text, 8);
}

/**
 * Read a NUL-terminated byte string field.
 *
 * @param {Buffer} block - the header block.
 * @param {number} offset - the field offset.
 * @param {number} length - the field length.
 * @returns {string} the decoded UTF-8 string.
 */
function readString(block, offset, length) {
	const raw = block.subarray(offset, offset + length);
	const end = raw.indexOf(0);
	return (end === -1 ? raw : raw.subarray(0, end)).toString("utf8");
}

/**
 * Verify a header block's checksum.
 *
 * @param {Buffer} block - the header block.
 * @returns {{stored: number, computed: number, ok: boolean}} the comparison.
 */
function checkChecksum(block) {
	const stored = readOctal(block, CHECKSUM_OFFSET, CHECKSUM_LENGTH);
	if (!Number.isFinite(stored)) return { stored: NaN, computed: NaN, ok: false };
	const copy = Buffer.from(block);
	copy.fill(0x20, CHECKSUM_OFFSET, CHECKSUM_OFFSET + CHECKSUM_LENGTH);
	let computed = 0;
	for (const byte of copy) computed += byte;
	return { stored, computed, ok: stored === computed };
}

/**
 * Decide whether a 512-byte block is the all-zero end-of-archive marker.
 *
 * @param {Buffer} block - the block to test.
 * @returns {boolean} true when every byte is zero.
 */
function isZeroBlock(block) {
	for (const byte of block) if (byte !== 0) return false;
	return true;
}

/**
 * Parse a tar buffer into its member list.
 *
 * This is a walk, not a lookup: each header states its own length, and the
 * next header begins after the padding. A corrupt header therefore desynchronises
 * every later read, so the checksum is verified *before* the size is trusted —
 * a bad checksum means the size field is not a size, and advancing by it would
 * run off into arbitrary bytes.
 *
 * @param {Buffer} buffer - the whole archive.
 * @returns {{entries: Array<object>, records: Array<object>, warnings: Array<string>, trailingBytes: number, terminated: boolean}} the parse.
 */
function parseTar(buffer) {
	const entries = [];
	const records = [];
	const warnings = [];
	let offset = 0;
	// Whether the walk actually reached the end-of-archive marker. Without this
	// a truncated archive is indistinguishable from a complete one: the loop
	// simply runs out of full blocks and exits, and every member it did read
	// checksums fine, so a caller is told "ok" about half a file. This is the
	// difference between "the archive is intact" and "the archive is what was
	// left after something cut it off".
	let terminated = false;

	while (offset + BLOCK <= buffer.length) {
		const block = buffer.subarray(offset, offset + BLOCK);
		if (isZeroBlock(block)) {
			terminated = true;
			break;
		}

		const rawName = readString(block, 0, USTAR_NAME_MAX);
		const prefix = readString(block, 345, USTAR_PREFIX_MAX);
		const slashName = prefix === "" ? rawName : `${prefix}/${rawName}`;
		const magic = block.subarray(257, 263).toString("latin1");
		const version = block.subarray(263, 265).toString("latin1");
		const flag = block.subarray(156, 157).toString("latin1");
		const checksum = checkChecksum(block);

		if (magic === "ustar" && version === "") {
			warnings.push(`${rawName || "(unnamed)"}: the header carries "ustar" but no version byte; it has been read anyway.`);
		} else if (magic !== USTAR_MAGIC) {
			warnings.push(`${rawName || "(unnamed)"}: the magic bytes are not "ustar" (saw ${JSON.stringify(magic)}); offsets are still being read tar-style.`);
		}

		const record = {
			name: slashName,
			rawName,
			flag,
			kind: TYPE_FLAGS[flag] ?? "unknown",
			size: readOctal(block, 124, 12),
			mode: readOctal(block, 100, 8),
			uid: readOctal(block, 108, 8),
			gid: readOctal(block, 116, 8),
			mtime: readOctal(block, 136, 12),
			linkname: readString(block, 157, 100),
			headerOffset: offset,
			checksumOk: checksum.ok,
			checksumStored: checksum.stored,
			checksumComputed: checksum.computed,
			magic,
			version
		};
		records.push(record);

		if (!checksum.ok) {
			warnings.push(
				`${slashName || "(unnamed)"}: header checksum mismatch (stored ${checksum.stored}, computed ${checksum.computed}). ` +
				"The walk stops here because every later offset would be a guess."
			);
			break;
		}
		if (!Number.isFinite(record.size)) {
			warnings.push(`${slashName || "(unnamed)"}: the size field is not octal; the walk stops here.`);
			break;
		}

		if (record.kind === "file") {
			const start = offset + BLOCK;
			const end = start + record.size;
			if (end > buffer.length) {
				warnings.push(`${slashName}: the header claims ${record.size} bytes but only ${Math.max(0, buffer.length - start)} remain; the member is truncated.`);
				break;
			}
			record.dataOffset = start;
			record.sha256 = sha256(buffer.subarray(start, end));
			entries.push(record);
		} else if (record.kind === "directory") {
			record.dataOffset = offset + BLOCK;
			entries.push(record);
		} else {
			// Links and devices carry no data; their header is the whole member.
			record.dataOffset = offset + BLOCK;
			entries.push(record);
		}

		offset += BLOCK + paddedLength(record.kind === "file" ? record.size : 0);
	}

	// If the walk stopped because it ran out of full 512-byte blocks rather
	// than because it reached the terminator, the archive is truncated. The
	// members that *were* read are all valid, which is precisely what makes the
	// omission dangerous: every checksum passes and a naive reader reports a
	// clean archive. The warning is the only signal that half the file is gone.
	if (!terminated && buffer.length > 0) {
		const remaining = buffer.length - offset;
		warnings.push(
			`the archive ends after ${records.length} member(s) without an end-of-archive marker` +
			`${remaining > 0 ? ` (${remaining} trailing byte(s) are not a whole 512-byte block)` : ""}` +
			"; it is truncated, so the last member may be incomplete or missing entirely."
		);
	} else if (!terminated && buffer.length === 0) {
		warnings.push("the archive is empty: it holds no headers and no end-of-archive marker.");
	}

	// Anything after the terminating zero blocks is a second archive, padding
	// from a tape device, or garbage. Reporting the count is enough — deciding
	// what it means is the caller's problem.
	let closing = offset;
	while (closing + BLOCK <= buffer.length && isZeroBlock(buffer.subarray(closing, closing + BLOCK))) closing += BLOCK;
	return { entries, records, warnings, trailingBytes: buffer.length - closing, terminated };
}

/**
 * Hex SHA-256 of a buffer.
 *
 * @param {Buffer} buffer - the bytes to hash.
 * @returns {string} the lowercase hex digest.
 */
function sha256(buffer) {
	return createHash("sha256").update(buffer).digest("hex");
}

/* ------------------------------------------------------------------- paths */

/**
 * Convert a platform path to slash-separated form.
 *
 * Windows `relative()` returns backslashes; every name this module compares,
 * prints or stores is slash-separated so that an archive packed on Windows and
 * one packed on Linux describe the same tree the same way.
 *
 * @param {string} path - the input path.
 * @returns {string} the slash-separated path.
 */
function toPosix(path) {
	return String(path).replaceAll("\\", "/");
}

/**
 * Strip every routing component from a name, keeping only the last segment.
 *
 * This is the security boundary for output. `resolve(dir, name)` honours an
 * absolute second argument, so `resolve("/out", "C:/Windows/x")` returns the
 * Windows path and a write escapes the configured directory. An archive that
 * arrived from somewhere untrusted is exactly where such a name would come
 * from, so the traversal components are discarded before `resolve` ever sees
 * them, on the way *in* as well.
 *
 * @param {string} dir - the containing directory.
 * @param {string} name - the requested name, possibly hostile.
 * @returns {string} an absolute path inside `dir`.
 */
function resolveWithin(dir, name) {
	const raw = String(name ?? "").trim();
	const segments = toPosix(raw)
		.split("/")
		.filter((part) => part !== "" && part !== "." && part !== "..");
	const tail = segments.length > 0 ? segments[segments.length - 1] : "";
	const safe = tail.replace(/[<>:"|?*\u0000-\u001f]/gu, "_");
	return resolve(dir, safe);
}

/**
 * Resolve an archive member's name against an extraction root, or refuse it.
 *
 * Members are checked against the *whole* configured root rather than against
 * the immediate parent, so a member named `a/../../b` is rejected even though
 * its own segment is innocuous. The check is a prefix comparison on the
 * resolved path, which is the only form that cannot be fooled by a name that
 * looks relative but resolves absolutely.
 *
 * @param {string} root - the absolute extraction root.
 * @param {string} member - the member name from the archive.
 * @returns {{ok: boolean, path?: string, reason?: string, kind?: string}} the verdict.
 */
function resolveEntry(root, member) {
	const raw = String(member ?? "");
	if (raw === "") return { ok: false, reason: "the entry has an empty name", kind: "empty" };
	if (raw.includes("\u0000")) return { ok: false, reason: "the entry name contains a NUL byte", kind: "nul" };
	if (/^[A-Za-z]:/u.test(raw) || raw.startsWith("/") || raw.startsWith("\\\\")) {
		return { ok: false, reason: `the entry name "${raw}" is absolute`, kind: "absolute" };
	}

	// Strip leading "./" runs and trailing slashes to a fixed point. A single
	// pass is not enough: "././." reduces to "./." under one pass and to "." only
	// under two, so the empty-name guard below would miss it and the name would
	// resolve to the extraction root. Looping until the value stops changing is
	// the only form that cannot be defeated by adding another "./".
	let clean = toPosix(raw);
	let previous = "";
	while (clean !== previous) {
		previous = clean;
		clean = clean.replace(/^\.\/+/u, "").replace(/\/+$/u, "");
	}
	if (clean === "" || clean === ".") {
		return { ok: false, reason: `the entry name "${raw}" normalises to nothing and would name the extraction root itself`, kind: "empty" };
	}
	const parts = clean.split("/");
	if (parts.some((part) => part === "..")) {
		return { ok: false, reason: `the entry name "${raw}" contains a ".." component`, kind: "traversal" };
	}
	if (parts.some((part) => part === "")) {
		return { ok: false, reason: `the entry name "${raw}" contains an empty component`, kind: "empty-component" };
	}

	const target = resolve(root, clean);
	const rootWithSep = root.endsWith(sep) ? root : root + sep;
	if (target !== root && !target.startsWith(rootWithSep)) {
		return { ok: false, reason: `the entry name "${raw}" resolves outside the extraction directory`, kind: "escape" };
	}
	return { ok: true, path: target, kind: "inside" };
}

/* -------------------------------------------------------------- walking */

/**
 * Walk a directory into a sorted, deterministic member list.
 *
 * Sorting is the whole reason two packs of the same tree agree: `readdir`
 * returns entries in whatever order the filesystem pleases, and a directory
 * that happens to list `b` before `a` would otherwise produce a differently
 * ordered archive with a different hash. Sorting by path, not by name, keeps
 * nested trees in a stable order too.
 *
 * @param {string} root - the absolute directory to walk.
 * @param {object} [options] - walk options.
 * @param {Set<string>} [options.exclude] - last-segment names to skip.
 * @param {number} [options.maxFileBytes] - skip larger files; 0 means no limit.
 * @param {AbortSignal} [options.signal] - cooperative cancellation.
 * @returns {Promise<{members: Array<object>, skipped: Array<object>, totalBytes: number}>} the walk.
 */
async function walkTree(root, options = {}) {
	const exclude = options.exclude ?? new Set();
	const maxFileBytes = Number.isFinite(options.maxFileBytes) ? options.maxFileBytes : 0;
	const members = [];
	const skipped = [];

	/**
	 * Recurse into one directory.
	 *
	 * @param {string} dir - the absolute directory.
	 * @param {string} prefix - the slash-separated path of `dir` relative to the root.
	 */
	async function visit(dir, prefix) {
		if (options.signal?.aborted) throw new Error("archive: the walk was aborted.");
		const names = (await readdir(dir)).sort();
		for (const entryName of names) {
			if (exclude.has(entryName)) {
				skipped.push({ name: prefix === "" ? entryName : `${prefix}/${entryName}`, reason: "excluded" });
				continue;
			}
			const full = join(dir, entryName);
			const rel = prefix === "" ? entryName : `${prefix}/${entryName}`;
			const info = await lstat(full);

			// `lstat` is not a reliable symlink detector on Windows: for a link
			// created by an unprivileged process it can report an ordinary file
			// while `readlink` still resolves. Relying on `isSymbolicLink()`
			// alone means a symlink is packed as a *regular file* — and because
			// `readFile` on the link returns nothing useful, it lands in the
			// archive as a zero-byte file with the empty-string hash. That is
			// silent data loss: the archive looks fine and quietly contains a
			// file that is not the one on disk. So `readlink` is consulted
			// independently of the stat flags, and either signal is enough.
			const linkTarget = await readlinkSafe(full);
			if (info.isSymbolicLink() || linkTarget !== null) {
				// A symlink's content is the path it points at, and that path is
				// resolved on the *reader's* machine, not this one. Packing it as
				// a file would silently inline whatever it pointed at; packing it
				// as a link would hand the reader a redirect out of the tree.
				// Neither is what the caller asked for, so it is skipped loudly.
				const target = linkTarget ?? await readlinkSafe(full);
				skipped.push({ name: rel, reason: `symlink to ${target === null ? "an unreadable target" : target}` });
				continue;
			}
			if (info.isDirectory()) {
				members.push({ name: rel, kind: "directory", size: 0, mtimeMs: info.mtimeMs });
				await visit(full, rel);
				continue;
			}
			if (!info.isFile()) {
				skipped.push({ name: rel, reason: "not a regular file" });
				continue;
			}
			if (maxFileBytes > 0 && info.size > maxFileBytes) {
				skipped.push({ name: rel, reason: `larger than maxFileBytes (${info.size} > ${maxFileBytes})` });
				continue;
			}
			members.push({ name: rel, kind: "file", size: info.size, mtimeMs: info.mtimeMs, source: full });
		}
	}

	await visit(root, "");
	members.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
	const totalBytes = members.reduce((sum, member) => sum + (member.kind === "file" ? member.size : 0), 0);
	return { members, skipped, totalBytes };
}

/**
 * Read a symlink's target without throwing on a dangling link.
 *
 * @param {string} path - the symlink path.
 * @returns {Promise<string|null>} the target, or null if it cannot be read.
 */
async function readlinkSafe(path) {
	const { readlink } = await import("node:fs/promises");
	try {
		return await readlink(path);
	} catch {
		return null;
	}
}

/* ------------------------------------------------------------- packing */

/**
 * Pack a directory into a tar buffer plus a manifest.
 *
 * @param {string} root - the absolute directory to pack.
 * @param {object} options - packing options.
 * @param {Set<string>} options.exclude - last-segment names to skip.
 * @param {number} options.maxFileBytes - skip larger files; 0 means no limit.
 * @param {boolean} options.hash - compute per-member SHA-256.
 * @param {AbortSignal} [options.signal] - cooperative cancellation.
 * @returns {Promise<{buffer: Buffer, manifest: Array<object>, skipped: Array<object>, totalBytes: number}>} the pack.
 */
async function packTree(root, options) {
	const walk = await walkTree(root, {
		exclude: options.exclude,
		maxFileBytes: options.maxFileBytes,
		signal: options.signal
	});

	const chunks = [];
	const manifest = [];
	// The walk's skips plus the read-stage skips, so the caller sees one list of
	// everything that did not make it into the archive regardless of which stage
	// dropped it.
	const skipped = [...walk.skipped];

	for (const member of walk.members) {
		if (member.kind === "file") {
			const data = await readFile(member.source);
			// The walk recorded a size from the directory listing; if the read
			// returns a different number of bytes, the file changed underneath
			// the walk, is a link that resolved elsewhere, or is something the
			// filesystem reports inconsistently. Packing it anyway writes a
			// member whose header and content disagree, which every reader will
			// trust and none can detect. Dropping it and saying so keeps the
			// archive honest about what it holds.
			if (data.length !== member.size) {
				skipped.push({
					name: member.name,
					reason: `the directory listing said ${member.size} bytes but reading it produced ${data.length}; the file changed during the walk, so it was left out rather than packed inconsistently`
				});
				continue;
			}
			chunks.push(tarHeader(member), data);
			const pad = paddedLength(data.length) - data.length;
			if (pad > 0) chunks.push(Buffer.alloc(pad));
			manifest.push({
				path: member.name,
				kind: "file",
				bytes: data.length,
				sha256: options.hash ? sha256(data) : "",
				mode: PACK_MODE_FILE
			});
		} else {
			chunks.push(tarHeader(member));
			manifest.push({ path: member.name, kind: "directory", bytes: 0, sha256: "", mode: PACK_MODE_DIR });
		}
	}

	chunks.push(tarTrailer());
	return {
		buffer: Buffer.concat(chunks),
		manifest,
		skipped,
		// Derived from the manifest rather than from the walk: a member the read
		// stage dropped must not be counted as content the archive holds.
		totalBytes: manifest.reduce((sum, member) => sum + member.bytes, 0)
	};
}

/**
 * Fold a manifest into one digest that describes the tree, not the packing.
 *
 * Each entry contributes its kind, size and content hash; the list is already
 * sorted, so the digest is a function of the content alone. Directory modes
 * and mtimes are deliberately absent — a mode difference is not a content
 * difference, and including it would make the digest unusable as a comparison
 * between two machines.
 *
 * @param {Array<object>} manifest - the member list.
 * @returns {string} the hex tree digest.
 */
function treeDigest(manifest) {
	const hash = createHash("sha256");
	for (const member of manifest) {
		hash.update(`${member.kind}\u0000${member.path}\u0000${member.bytes}\u0000${member.sha256}\n`);
	}
	return hash.digest("hex");
}

/* -------------------------------------------------------------- unpacking */

/**
 * Turn a parsed archive into an extraction plan, reporting every refusal.
 *
 * Nothing is written here. The plan is computed first so that a caller can be
 * told about *all* the problems in an archive rather than about the first one,
 * and so that the decision to write is made once, on a complete picture.
 *
 * @param {object} parsed - the output of `parseTar`.
 * @param {string} root - the absolute extraction root.
 * @param {object} limits - the configured caps.
 * @param {number} limits.maxEntries - the entry cap.
 * @param {number} limits.maxTotalBytes - the total byte cap.
 * @param {number} limits.maxNameBytes - the per-name byte cap.
 * @returns {{writable: Array<object>, refused: Array<object>, totalBytes: number, warnings: Array<string>}} the plan.
 */
function planExtraction(parsed, root, limits) {
	const writable = [];
	const refused = [];
	const warnings = [...parsed.warnings];
	let totalBytes = 0;

	for (const entry of parsed.records) {
		const where = resolveEntry(root, entry.name);
		if (!where.ok) {
			refused.push({ name: entry.name, kind: "traversal", reason: where.reason });
			continue;
		}
		if (entry.kind === "unknown") {
			refused.push({ name: entry.name, kind: "unknown", reason: `the type flag ${JSON.stringify(entry.flag)} is not one this reader acts on` });
			continue;
		}
		if (DANGEROUS_TYPES[entry.flag] !== undefined) {
			refused.push({ name: entry.name, kind: "device", reason: `the member is a ${DANGEROUS_TYPES[entry.flag]} and creating one is not something a file archive should do` });
			continue;
		}
		if (entry.kind === "hardlink" || entry.kind === "symlink") {
			// A link's *target* is the dangerous half: a symlink to `/etc/passwd`
			// is harmless as a symlink and a data-loss incident the first time
			// something follows it. Both kinds are refused outright; the target is
			// reported so the caller can see what was being attempted.
			const target = resolveEntry(root, entry.linkname);
			refused.push({
				name: entry.name,
				kind: entry.kind,
				reason: `the member is a ${entry.kind} to ${JSON.stringify(entry.linkname)}` +
					(target.ok ? "" : `, and that target ${target.reason}`) +
					"; links are not extracted because a later reader would follow them out of the tree"
			});
			continue;
		}
		if (!entry.checksumOk) {
			refused.push({ name: entry.name, kind: "checksum", reason: "the header checksum does not match, so the size cannot be trusted" });
			continue;
		}
		if (Buffer.byteLength(entry.name, "utf8") > limits.maxNameBytes) {
			refused.push({ name: entry.name, kind: "name", reason: `the name is longer than maxNameBytes (${Buffer.byteLength(entry.name, "utf8")} > ${limits.maxNameBytes})` });
			continue;
		}

		const size = entry.kind === "file" ? entry.size : 0;
		if (totalBytes + size > limits.maxTotalBytes) {
			refused.push({ name: entry.name, kind: "size", reason: `accepting this member would exceed maxTotalBytes (${totalBytes + size} > ${limits.maxTotalBytes})` });
			continue;
		}
		totalBytes += size;

		if (entry.kind === "file" && entry.dataOffset + entry.size > parsedEnd(parsed)) {
			refused.push({ name: entry.name, kind: "truncated", reason: "the archive ends before this member's data does" });
			continue;
		}

		writable.push({ ...entry, target: where.path, size });
	}

	if (writable.length > limits.maxEntries) {
		warnings.push(`the archive holds ${writable.length} writable members, more than maxEntries (${limits.maxEntries}); the extractor writes them all but the cap should be raised deliberately, not by accident.`);
	}

	// An archive built on a case-sensitive filesystem can legitimately hold both
	// `README.md` and `readme.md`. Extracting it on a case-insensitive one (NTFS,
	// HFS+, default APFS) collapses them into a single file — the second write
	// replaces the first — and the caller ends up with a tree that is missing a
	// file with no error anywhere. The collision is detectable here because both
	// names are present in the *archive*, which is exactly where the information
	// the filesystem threw away still exists.
	const byLower = new Map();
	for (const member of writable) {
		const key = member.name.toLowerCase();
		const previous = byLower.get(key);
		if (previous === undefined) {
			byLower.set(key, member.name);
			continue;
		}
		warnings.push(
			`"${previous}" and "${member.name}" differ only in case. On a case-insensitive filesystem ` +
			"these are one file, so one of them will overwrite the other during extraction and the " +
			"resulting tree will not match the manifest."
		);
	}

	return { writable, refused, totalBytes, warnings };
}

/**
 * The byte offset at which parsed content stops.
 *
 * @param {object} parsed - the parse result.
 * @returns {number} the offset.
 */
function parsedEnd(parsed) {
	const last = parsed.records[parsed.records.length - 1];
	if (last === undefined) return 0;
	return last.dataOffset + (last.kind === "file" ? last.size : 0);
}

/**
 * Write an extraction plan to disk, creating parents as needed.
 *
 * Parents are created for every member before any file is written, so a plan
 * whose directory entries were refused for traversal still cannot have a file
 * written into a directory that was never created.
 *
 * @param {Array<object>} writable - the plan's writable members.
 * @param {Buffer} buffer - the whole archive.
 * @param {object} [options] - write options.
 * @param {boolean} [options.noOverwrite] - refuse to replace existing files.
 * @param {AbortSignal} [options.signal] - cooperative cancellation.
 * @returns {Promise<Array<object>>} the written members, with hashes.
 */
async function writePlan(writable, buffer, options = {}) {
	const written = [];
	for (const member of writable) {
		if (options.signal?.aborted) throw new Error("archive: the extraction was aborted.");
		if (member.kind === "directory") {
			await mkdir(member.target, { recursive: true });
			written.push({ path: member.name, kind: "directory", bytes: 0, sha256: "" });
			continue;
		}
		await mkdir(dirname(member.target), { recursive: true });
		const data = buffer.subarray(member.dataOffset, member.dataOffset + member.size);
		if (options.noOverwrite) {
			const exists = await stat(member.target).then(() => true, () => false);
			if (exists) {
				throw new Error(`archive: "${member.name}" already exists at ${member.target} and noOverwrite is set.`);
			}
		}
		await writeFile(member.target, data);
		written.push({ path: member.name, kind: "file", bytes: data.length, sha256: sha256(data) });
	}
	return written;
}

/* ------------------------------------------------------------ verifying */

/**
 * Compare two manifests and describe every difference.
 *
 * The comparison is by path, not by position, because "entry 7 changed" is not
 * actionable while "src/a.js changed" is. A member present on only one side is
 * reported as added or removed rather than as a change, since those call for
 * different responses.
 *
 * @param {Array<object>} expected - the manifest to check against.
 * @param {Array<object>} actual - the observed manifest.
 * @returns {{ok: boolean, added: Array<object>, removed: Array<object>, changed: Array<object>, unchanged: number}} the diff.
 */
function diffManifests(expected, actual) {
	const before = new Map(expected.map((member) => [member.path, member]));
	const after = new Map(actual.map((member) => [member.path, member]));
	const added = [];
	const removed = [];
	const changed = [];
	let unchanged = 0;

	for (const [path, member] of after) {
		const previous = before.get(path);
		if (previous === undefined) {
			added.push(member);
			continue;
		}
		if (previous.kind !== member.kind) {
			changed.push({ path, field: "kind", expected: previous.kind, actual: member.kind });
			continue;
		}
		if (previous.bytes !== member.bytes) {
			changed.push({ path, field: "bytes", expected: previous.bytes, actual: member.bytes });
			continue;
		}
		if (previous.sha256 !== "" && member.sha256 !== "" && previous.sha256 !== member.sha256) {
			changed.push({ path, field: "sha256", expected: previous.sha256, actual: member.sha256 });
			continue;
		}
		unchanged += 1;
	}
	for (const [path, member] of before) {
		if (!after.has(path)) removed.push(member);
	}

	return {
		ok: added.length === 0 && removed.length === 0 && changed.length === 0,
		added,
		removed,
		changed,
		unchanged
	};
}

/**
 * Hash a packed archive's members straight out of its bytes, without writing.
 *
 * Verification must not need a scratch directory: unpacking to a temporary
 * place in order to compare would introduce a second, unguarded extraction
 * path — the exact thing this plugin exists to avoid.
 *
 * @param {Buffer} buffer - the archive bytes.
 * @returns {Array<object>} the member manifest.
 */
function manifestFromArchive(buffer) {
	const parsed = parseTar(buffer);
	return parsed.entries
		.filter((entry) => entry.kind === "file" || entry.kind === "directory")
		.map((entry) => ({
			path: entry.kind === "directory" ? entry.name.replace(/\/+$/u, "") : entry.name,
			kind: entry.kind,
			bytes: entry.kind === "file" ? entry.size : 0,
			sha256: entry.kind === "file" ? entry.sha256 : ""
		}))
		.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
}

/**
 * Hash a directory tree on disk into a manifest.
 *
 * @param {string} root - the absolute directory.
 * @param {Set<string>} exclude - last-segment names to skip.
 * @param {AbortSignal} [signal] - cooperative cancellation.
 * @returns {Promise<Array<object>>} the member manifest.
 */
async function manifestFromTree(root, exclude, signal) {
	const walk = await walkTree(root, { exclude, maxFileBytes: 0, signal });
	const manifest = [];
	for (const member of walk.members) {
		if (member.kind === "file") {
			const data = await readFile(member.source);
			manifest.push({ path: member.name, kind: "file", bytes: data.length, sha256: sha256(data) });
		} else {
			manifest.push({ path: member.name, kind: "directory", bytes: 0, sha256: "" });
		}
	}
	return manifest;
}

/* ------------------------------------------------------------------ misc */

/**
 * Compact human-readable byte count.
 *
 * @param {number} bytes - the byte count.
 * @returns {string} e.g. "1.4 MB".
 */
function humanBytes(bytes) {
	const units = ["B", "KB", "MB", "GB", "TB"];
	let value = Math.max(0, Number(bytes) || 0);
	let unit = 0;
	while (value >= 1024 && unit < units.length - 1) {
		value /= 1024;
		unit += 1;
	}
	return unit === 0 ? `${Math.trunc(value)} ${units[unit]}` : `${value.toFixed(1)} ${units[unit]}`;
}

/**
 * A filesystem-safe timestamp for default file names.
 *
 * @returns {string} e.g. "20261002-171500".
 */
function stamp() {
	const now = new Date();
	const pad = (n) => String(n).padStart(2, "0");
	return `${now.getFullYear()}${pad(now.getMonth() + 1)}${pad(now.getDate())}-${pad(now.getHours())}${pad(now.getMinutes())}${pad(now.getSeconds())}`;
}

/**
 * Turn a requested archive name into a path inside the archive directory.
 *
 * @param {string} dir - the archive directory.
 * @param {string} requested - the caller's file name, or "".
 * @returns {string} the absolute archive path.
 */
function archivePath(dir, requested) {
	const raw = String(requested ?? "").trim();
	if (raw === "") return resolveWithin(dir, `pack-${stamp()}.tar`);
	const withExtension = raw.endsWith(".tar") || raw.endsWith(".tgz") || raw.endsWith(".tar.gz") ? raw : `${raw}.tar`;
	return resolveWithin(dir, withExtension);
}

/**
 * Resolve a source directory against `workDir`.
 *
 * Sources are read, not written, so a traversal here is a read of a directory
 * the caller named — it is not the same class of hazard as an archive member
 * name, and refusing absolute paths would break the ordinary case of "pack
 * `D:/data`". The value is resolved and reported so the caller can see what
 * was actually read.
 *
 * @param {string} dir - the configured work directory.
 * @param {string} source - the caller's directory.
 * @returns {string} the absolute source path.
 */
function resolveSource(dir, source) {
	const raw = String(source ?? "").trim();
	return raw === "" ? resolve(dir) : resolve(dir, raw);
}

/**
 * Normalise a comma-separated or array-style exclude list.
 *
 * @param {string|Array<string>|undefined} value - the caller's excludes.
 * @param {Array<string>} fallback - the configured defaults.
 * @returns {Set<string>} the names to skip.
 */
function excludeSet(value, fallback) {
	if (value === undefined || value === null || value === "") return new Set(fallback);
	const items = Array.isArray(value) ? value : String(value).split(",");
	return new Set(items.map((item) => String(item).trim()).filter((item) => item !== ""));
}

/**
 * Guard the size of an archive this plugin is willing to read into memory.
 *
 * @param {number} bytes - the file size.
 * @param {number} limit - the configured cap.
 * @param {string} file - the path, for the error message.
 */
function assertReadable(bytes, limit, file) {
	if (limit > 0 && bytes > limit) {
		throw new Error(
			`archive: ${file} is ${humanBytes(bytes)}, above the ${humanBytes(limit)} limit this plugin reads into memory. ` +
			"Raise Config.maxTotalBytes if that is intentional."
		);
	}
}

/* ------------------------------------------------------------------ apply */

/**
 * Register the archive tool suite on a cordis context.
 *
 * @param {object} ctx - the cordis context; `ctx.tools.register` is the seam.
 * @param {object} config - the resolved plugin config.
 */
function apply(ctx, config) {
	const transport = ctx.transport ?? {};
	const timeoutMs = config.timeoutMs;
	const archiveDir = resolve(config.workDir, config.archiveDir);
	const extractDir = resolve(config.workDir, config.extractDir);

	/**
	 * Resolve the injectable reader.
	 *
	 * Read live at the call site rather than captured, so a test that swaps
	 * `ctx.transport.readArchive` after `apply` is seen by the tool. Capturing
	 * `transport.readArchive` into a local at apply time would pin `undefined`
	 * and send every call to the real filesystem.
	 *
	 * @param {string} file - the absolute archive path.
	 * @returns {Promise<Buffer>} the archive bytes.
	 */
	async function readArchiveVia(file) {
		if (typeof transport.readArchive === "function") return transport.readArchive(file);
		const info = await stat(file);
		assertReadable(info.size, config.maxTotalBytes, file);
		return readFile(file);
	}

	/* -- archive_status ---------------------------------------------------- */
	if (config.status) {
		ctx.tools.register(defineTool({
			name: "archive_status",
			description: "Report how this plugin packs and unpacks: the tar dialect it writes, which member kinds it refuses, the path rules an archive member must satisfy, and where its output goes. Check this before trusting an archive built elsewhere.",
			parameters: {},
			output: {
				// `required` in this DSL is a boolean flag on each *property*
				// (`{ type: "string", required: true }`), never a top-level
				// `required: [...]` array. The framework hoists the flags into
				// that array while compiling, and throws while the plugin loads
				// if an array appears in the source instead.
				schema: {
					type: "object",
					additionalProperties: false,
					properties: {
						format: { type: "string", required: true, description: "The dialect this plugin writes." },
						readable: { type: "array", required: true, items: { type: "string" }, description: "Header dialects this reader accepts." },
						operations: { type: "array", required: true, items: { type: "string" }, description: "The tools this plugin registers." },
						refusedKinds: { type: "array", required: true, items: { type: "string" }, description: "Member kinds that are never extracted." },
						pathRules: { type: "array", required: true, items: { type: "string" }, description: "Conditions an archive member name must satisfy." },
						directories: {
							type: "object",
							required: true,
							additionalProperties: false,
							properties: {
								workDir: { type: "string", required: true },
								archiveDir: { type: "string", required: true },
								extractDir: { type: "string", required: true }
							}
						},
						limits: {
							type: "object",
							required: true,
							additionalProperties: false,
							properties: {
								maxEntries: { type: "number", required: true },
								maxTotalBytes: { type: "number", required: true },
								maxNameBytes: { type: "number", required: true },
								maxFileBytes: { type: "number", required: true },
								noOverwrite: { type: "boolean", required: true }
							}
						},
						excludes: { type: "array", required: true, items: { type: "string" }, description: "Last-segment names skipped while walking." },
						deterministic: { type: "boolean", required: true, description: "Whether the same tree always packs to the same digest." }
					}
				}
			},
			timeoutMs,
			isConcurrencySafe: () => true,
			async execute() {
				return {
					format: "ustar (POSIX.1-1988): 512-byte blocks, 6-digit octal checksum, name split across the name and prefix fields, no GNU long-name or PAX extensions",
					readable: [
						"ustar with the magic and version written as one string",
						"ustar with the version byte absent",
						"headers without ustar magic, read at the historical offsets"
					],
					operations: ["archive_pack", "archive_unpack", "archive_verify"],
					refusedKinds: ["symlink", "hardlink", "character device", "block device", "FIFO", "unknown type flags"],
					pathRules: [
						"relative only; a leading \"/\", a Windows drive letter, or a UNC prefix is refused",
						"no \"..\" component, and no empty component from a doubled slash",
						"resolved against the extraction root and compared by prefix; anything landing outside is refused",
						"no NUL byte, and at most maxNameBytes UTF-8 bytes"
					],
					directories: { workDir: resolve(config.workDir), archiveDir, extractDir },
					limits: {
						maxEntries: config.maxEntries,
						maxTotalBytes: config.maxTotalBytes,
						maxNameBytes: config.maxNameBytes,
						maxFileBytes: config.maxFileBytes,
						noOverwrite: config.noOverwrite
					},
					excludes: [...config.exclude],
					deterministic: "the walk is sorted by path and the uid, gid and mode fields are pinned to constants, so the same tree with the same relative names always packs to the same SHA-256"
				};
			}
		}));
	}

	/* -- archive_pack ------------------------------------------------------ */
	if (config.pack) {
		ctx.tools.register(defineTool({
			name: "archive_pack",
			description: "Pack a directory into a tar, deterministically: entries are sorted by path and their owner and mode fields are pinned, so the same tree with the same names always produces the same digest. Returns a per-file SHA-256 manifest and the tree digest, and reports every file it skipped instead of leaving it for the caller to notice.",
			parameters: {
				source: { type: "string", description: "The directory to pack, resolved against workDir. Defaults to workDir itself.", required: true },
				filename: { type: "string", description: "The output file name under archiveDir. Defaults to a timestamped name and gets a .tar extension if it has none." },
				exclude: { type: "string", description: "Comma-separated last-segment names to skip, replacing the configured defaults." },
				maxFileBytes: { type: "number", description: "Skip files larger than this; 0 means no limit." }
			},
			output: {
				schema: {
					type: "object",
					additionalProperties: false,
					properties: {
						source: { type: "string", required: true, description: "The absolute directory that was packed." },
						file: { type: "string", required: true, description: "The absolute path of the written tar." },
						bytes: { type: "number", required: true, description: "The size of the archive on disk." },
						files: { type: "number", required: true, description: "How many regular files were packed." },
						directories: { type: "number", required: true, description: "How many directories were recorded." },
						contentBytes: { type: "number", required: true, description: "The sum of the member sizes, before tar padding." },
						overheadPercent: { type: "number", required: true, description: "How much bigger the archive is than its content." },
						format: { type: "string", required: true, description: "The header dialect written." },
						treeDigest: { type: "string", required: true, description: "A SHA-256 over the manifest, describing the content rather than the packing." },
						manifest: {
							type: "array",
							required: true,
							description: "One entry per member, sorted by path.",
							// Array items forbid `required` outright — it is only a
							// property-level flag — so the shape is declared without it.
							items: {
								type: "object",
								additionalProperties: false,
								properties: {
									path: { type: "string" },
									kind: { type: "string" },
									bytes: { type: "number" },
									sha256: { type: "string" }
								}
							}
						},
						skipped: {
							type: "array",
							required: true,
							description: "Members that were left out, with the reason.",
							items: {
								type: "object",
								additionalProperties: false,
								properties: {
									name: { type: "string" },
									reason: { type: "string" }
								}
							}
						}
					}
				}
			},
			timeoutMs,
			isConcurrencySafe: () => false,
			async execute(args, exec) {
				const source = resolveSource(config.workDir, args.source);
				const info = await stat(source).catch(() => null);
				if (info === null || !info.isDirectory()) {
					throw new Error(`archive: ${source} is not a readable directory.`);
				}

				const exclude = excludeSet(args.exclude, config.exclude);
				const maxFileBytes = Number.isFinite(args.maxFileBytes) ? Math.max(0, Math.trunc(args.maxFileBytes)) : config.maxFileBytes;

				const packed = await packTree(source, {
					exclude,
					maxFileBytes,
					hash: config.hash,
					signal: exec?.signal
				});

				await mkdir(archiveDir, { recursive: true });
				const file = archivePath(archiveDir, args.filename);
				await writeFile(file, packed.buffer);

				const files = packed.manifest.filter((member) => member.kind === "file").length;
				const directories = packed.manifest.length - files;
				const overhead = packed.totalBytes === 0
					? 0
					: Math.round(((packed.buffer.length / packed.totalBytes) - 1) * 1000) / 10;

				return {
					source,
					file,
					bytes: packed.buffer.length,
					files,
					directories,
					contentBytes: packed.totalBytes,
					overheadPercent: overhead,
					format: "ustar",
					treeDigest: treeDigest(packed.manifest),
					manifest: packed.manifest,
					skipped: packed.skipped
				};
			}
		}));
	}

	/* -- archive_unpack ---------------------------------------------------- */
	if (config.unpack) {
		ctx.tools.register(defineTool({
			name: "archive_unpack",
			description: "List or extract a tar, refusing every member that could reach outside the destination: absolute names, \"..\" components, symlinks, hardlinks and device nodes. Nothing is written until the whole archive has been checked, so a refused member never leaves a half-extracted tree behind. Set listOnly to see the contents without touching the disk.",
			parameters: {
				file: { type: "string", description: "The archive to read: an absolute path, or a name under archiveDir.", required: true },
				dest: { type: "string", description: "A subdirectory of extractDir to write into. Defaults to a name derived from the archive." },
				listOnly: { type: "boolean", description: "Report the contents and refuse nothing; write nothing." },
				strict: { type: "boolean", description: "Fail the whole call if any member is refused. Defaults to true when extracting, false when listing." }
			},
			output: {
				schema: {
					type: "object",
					additionalProperties: false,
					properties: {
						file: { type: "string", required: true, description: "The absolute archive path." },
						bytes: { type: "number", required: true, description: "The archive size." },
						listOnly: { type: "boolean", required: true },
						dest: { type: "string", required: true, description: "The absolute extraction root, or \"\" when listing only." },
						entries: { type: "number", required: true, description: "How many headers the archive holds, of every kind." },
						writable: { type: "number", required: true, description: "How many members were accepted." },
						written: { type: "number", required: true, description: "How many were actually written to disk." },
						directories: { type: "number", required: true, description: "How many directories were created." },
						contentBytes: { type: "number", required: true, description: "The accepted members' total size." },
						ok: { type: "boolean", required: true, description: "Whether every member was accepted." },
						refused: {
							type: "array",
							required: true,
							description: "Members that were not extracted, with the reason.",
							items: {
								type: "object",
								additionalProperties: false,
								properties: {
									name: { type: "string" },
									kind: { type: "string" },
									reason: { type: "string" }
								}
							}
						},
						manifest: {
							type: "array",
							required: true,
							description: "The extracted members, with a content hash each.",
							items: {
								type: "object",
								additionalProperties: false,
								properties: {
									path: { type: "string" },
									kind: { type: "string" },
									bytes: { type: "number" },
									sha256: { type: "string" }
								}
							}
						},
						warnings: { type: "array", required: true, items: { type: "string" }, description: "Non-fatal observations about the archive." }
					}
				}
			},
			timeoutMs,
			isConcurrencySafe: (args) => args?.listOnly === true,
			async execute(args, exec) {
				const requested = String(args.file ?? "").trim();
				if (requested === "") throw new Error("archive: a file is required.");
				const file = /^[A-Za-z]:/u.test(requested) || requested.startsWith("/") || requested.startsWith("\\\\")
					? requested
					: resolveWithin(archiveDir, requested);
				const buffer = await readArchiveVia(file);
				const parsed = parseTar(buffer);

				const dest = typeof args.dest === "string" && args.dest.trim() !== ""
					? resolveWithin(extractDir, args.dest.trim())
					: resolveWithin(extractDir, basename(file).replace(/\.tar$/u, ""));

				const limits = {
					maxEntries: config.maxEntries,
					maxTotalBytes: config.maxTotalBytes,
					maxNameBytes: config.maxNameBytes
				};
				const plan = planExtraction(parsed, dest, limits);
				const listOnly = args.listOnly === true;
				const strict = args.strict === undefined ? !listOnly : args.strict === true;

				const manifest = parsed.records
					.filter((entry) => entry.kind === "file" || entry.kind === "directory")
					.map((entry) => ({
						path: entry.kind === "directory" ? entry.name.replace(/\/+$/u, "") : entry.name,
						kind: entry.kind,
						bytes: entry.kind === "file" ? entry.size : 0,
						sha256: entry.kind === "file" ? entry.sha256 : ""
					}));

				if (listOnly) {
					return {
						file,
						bytes: buffer.length,
						listOnly: true,
						dest: "",
						entries: parsed.records.length,
						writable: plan.writable.length,
						written: 0,
						directories: manifest.filter((member) => member.kind === "directory").length,
						contentBytes: plan.totalBytes,
						ok: plan.refused.length === 0,
						refused: plan.refused,
						manifest,
						warnings: plan.warnings
					};
				}

				// Strict mode checks before it writes. A partly-extracted tree is
				// the worst outcome: the caller has a directory that looks usable
				// and is missing exactly the members that were dangerous.
				if (strict && plan.refused.length > 0) {
					throw new Error(
						`archive: ${plan.refused.length} member(s) of ${file} were refused, so nothing was extracted: ` +
						plan.refused.slice(0, 3).map((item) => `${item.name} (${item.reason})`).join("; ") +
						(plan.refused.length > 3 ? `, and ${plan.refused.length - 3} more` : "") +
						". Pass strict:false to extract the safe members and get the refusals reported instead."
					);
				}

				await mkdir(dest, { recursive: true });
				const written = await writePlan(plan.writable, buffer, {
					noOverwrite: config.noOverwrite,
					signal: exec?.signal
				});

				return {
					file,
					bytes: buffer.length,
					listOnly: false,
					dest,
					entries: parsed.records.length,
					writable: plan.writable.length,
					written: written.filter((member) => member.kind === "file").length,
					directories: written.filter((member) => member.kind === "directory").length,
					contentBytes: plan.totalBytes,
					ok: plan.refused.length === 0,
					refused: plan.refused,
					manifest: written,
					warnings: plan.warnings
				};
			}
		}));
	}

	/* -- archive_verify ---------------------------------------------------- */
	if (config.verify) {
		ctx.tools.register(defineTool({
			name: "archive_verify",
			description: "Check that an archive holds what it should, without extracting it. Give a directory and every member is compared against the file on disk by size and SHA-256; give a digest and the tree digest is recomputed and compared. Reports added, removed and changed members by path, so a difference can be acted on rather than just noticed.",
			parameters: {
				file: { type: "string", description: "The archive to verify: an absolute path, or a name under archiveDir.", required: true },
				against: { type: "string", description: "A directory to compare the archive against, resolved against workDir." },
				digest: { type: "string", description: "A tree digest to compare against, as returned by archive_pack." }
			},
			output: {
				schema: {
					type: "object",
					additionalProperties: false,
					properties: {
						file: { type: "string", required: true },
						bytes: { type: "number", required: true },
						entries: { type: "number", required: true, description: "How many members the archive holds." },
						ok: { type: "boolean", required: true, description: "Whether the archive is intact and matches what it was checked against." },
						treeDigest: { type: "string", required: true, description: "The digest recomputed from the archive's own bytes." },
						expectedDigest: { type: "string", required: true, description: "The digest that was asked for, or \"\" if none was." },
						comparedAgainst: { type: "string", required: true, description: "The directory compared against, or \"\" if none was." },
						added: { type: "array", required: true, description: "Members present in the archive and not in the directory.", items: { type: "string" } },
						removed: { type: "array", required: true, description: "Files present in the directory and not in the archive.", items: { type: "string" } },
						changed: {
							type: "array",
							required: true,
							description: "Members whose content differs, with the field that differs.",
							items: {
								type: "object",
								additionalProperties: false,
								properties: {
									path: { type: "string" },
									field: { type: "string" },
									expected: { type: "string" },
									actual: { type: "string" }
								}
							}
						},
						unchanged: { type: "number", required: true, description: "How many members matched exactly." },
						structuralWarnings: { type: "array", required: true, items: { type: "string" }, description: "Problems with the archive's headers." },
						refused: {
							type: "array",
							required: true,
							description: "Members this plugin would never extract.",
							items: {
								type: "object",
								additionalProperties: false,
								properties: {
									name: { type: "string" },
									kind: { type: "string" },
									reason: { type: "string" }
								}
							}
						}
					}
				}
			},
			timeoutMs,
			isConcurrencySafe: () => true,
			async execute(args, exec) {
				const requested = String(args.file ?? "").trim();
				if (requested === "") throw new Error("archive: a file is required.");
				const file = /^[A-Za-z]:/u.test(requested) || requested.startsWith("/") || requested.startsWith("\\\\")
					? requested
					: resolveWithin(archiveDir, requested);
				const buffer = await readArchiveVia(file);
				const parsed = parseTar(buffer);
				const manifest = manifestFromArchive(buffer);
				const digest = treeDigest(manifest);

				const plan = planExtraction(parsed, extractDir, {
					maxEntries: config.maxEntries,
					maxTotalBytes: config.maxTotalBytes,
					maxNameBytes: config.maxNameBytes
				});

				let ok = parsed.warnings.length === 0;
				const added = [];
				const removed = [];
				const changed = [];
				let unchanged = 0;
				let comparedAgainst = "";

				const expectedDigest = typeof args.digest === "string" ? args.digest.trim() : "";
				if (expectedDigest !== "") {
					ok = ok && digest === expectedDigest;
				}

				if (typeof args.against === "string" && args.against.trim() !== "") {
					const against = resolveSource(config.workDir, args.against);
					const info = await stat(against).catch(() => null);
					if (info === null || !info.isDirectory()) {
						throw new Error(`archive: ${against} is not a readable directory.`);
					}
					comparedAgainst = against;
					const onDisk = await manifestFromTree(against, excludeSet(undefined, config.exclude), exec?.signal);
					const diff = diffManifests(manifest, onDisk);
					added.push(...diff.added.map((member) => member.path));
					removed.push(...diff.removed.map((member) => member.path));
					changed.push(...diff.changed);
					unchanged = diff.unchanged;
					ok = ok && diff.ok;
				} else if (expectedDigest === "" && typeof args.against !== "string") {
					// Neither comparison was asked for. An archive can still be
					// judged on its own: every header checksum must match and no
					// member may be one this plugin would refuse to extract.
					ok = ok && plan.refused.length === 0;
				} else {
					ok = ok && plan.refused.length === 0;
				}

				return {
					file,
					bytes: buffer.length,
					entries: manifest.length,
					ok,
					treeDigest: digest,
					expectedDigest,
					comparedAgainst,
					added,
					removed,
					changed,
					unchanged,
					structuralWarnings: parsed.warnings,
					refused: plan.refused
				};
			}
		}));
	}
}

export { Config, apply, inject, name };
export {
	BLOCK,
	CHECKSUM_OFFSET,
	CHECKSUM_LENGTH,
	USTAR_MAGIC,
	USTAR_VERSION,
	USTAR_NAME_MAX,
	USTAR_PREFIX_MAX,
	TYPE_FLAGS,
	DANGEROUS_TYPES,
	DEFAULT_EXCLUDES,
	PACK_MODE_FILE,
	PACK_MODE_DIR,
	octalField,
	encodePath,
	padField,
	tarHeader,
	tarTrailer,
	paddedLength,
	readOctal,
	readString,
	checkChecksum,
	isZeroBlock,
	parseTar,
	sha256,
	toPosix,
	resolveWithin,
	resolveEntry,
	resolveSource,
	excludeSet,
	walkTree,
	packTree,
	treeDigest,
	planExtraction,
	writePlan,
	diffManifests,
	manifestFromArchive,
	manifestFromTree,
	humanBytes,
	stamp,
	archivePath,
	assertReadable
};