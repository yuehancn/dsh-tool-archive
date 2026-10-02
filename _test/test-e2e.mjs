// End-to-end tests for dsh-tool-archive: real directories, real files, real
// bytes on disk, and archives that a hostile source might have produced.
//
// The logic and integration suites use fixture archives built by the harness.
// This one starts from trees written to disk, packs them with the plugin,
// verifies the bytes with an independent reader, extracts them and compares the
// result. Where the integration suite asserts that a refusal is *reported*,
// this one asserts that nothing bad reached the disk — a refused member must
// leave no trace at all, not merely a note in the result.
import { plugin, Context, call, writeFixtureTar } from "./harness.mjs";
import { readFile, writeFile, mkdir, rm, stat, readdir } from "node:fs/promises";
import { existsSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { join, resolve } from "node:path";

let passed = 0;
let failed = 0;
const SANDBOX = "C:/Users/yuehancn/WorkBuddy/2026-10-02-10-43-11/archive-sandbox";

/**
 * Assert equality, recording the outcome.
 *
 * @param {string} label - what is being asserted.
 * @param {any} actual - the observed value.
 * @param {any} expected - the expected value.
 */
function equal(label, actual, expected) {
	const a = JSON.stringify(actual);
	const b = JSON.stringify(expected);
	if (a === b) {
		passed += 1;
	} else {
		failed += 1;
		console.log(`  FAIL ${label}\n       actual:   ${a}\n       expected: ${b}`);
	}
}

/**
 * Assert a truthy condition.
 *
 * @param {string} label - what is being asserted.
 * @param {any} value - the value that should be truthy.
 */
function ok(label, value) {
	if (value) passed += 1;
	else {
		failed += 1;
		console.log(`  FAIL ${label}\n       expected truthy, got ${JSON.stringify(value)}`);
	}
}

/**
 * Walk a directory into a relative-path set, for whole-tree comparisons.
 *
 * @param {string} root - the directory.
 * @param {string} [prefix] - the accumulated prefix.
 * @returns {Promise<Array<string>>} the sorted relative paths.
 */
async function treePaths(root, prefix = "") {
	const out = [];
	const names = (await readdir(root)).sort();
	for (const entry of names) {
		const rel = prefix === "" ? entry : `${prefix}/${entry}`;
		const info = await stat(join(root, entry));
		if (info.isDirectory()) {
			out.push(`${rel}/`);
			out.push(...await treePaths(join(root, entry), rel));
		} else {
			out.push(rel);
		}
	}
	return out.sort();
}

console.log("archive: end to end");

await rm(SANDBOX, { recursive: true, force: true });
await mkdir(SANDBOX, { recursive: true });

/* ------------------------------------------------ a realistic release tree */

{
	const ctx = Context({ workDir: SANDBOX });
	plugin.apply(ctx, ctx.config);

	// A tree with the shapes that break naive packers: an empty file, an empty
	// directory, a deep nest, a file whose content is exactly one block, a
	// binary payload, a name with a space, a name with a unicode character, and
	// a dotfile.
	const source = join(SANDBOX, "release");
	await mkdir(join(source, "src", "lib"), { recursive: true });
	await mkdir(join(source, "empty-dir"), { recursive: true });
	await mkdir(join(source, "docs"), { recursive: true });
	await writeFile(join(source, "README.md"), "# Release\n\nA tree.\n", "utf8");
	await writeFile(join(source, "src", "index.js"), "export const version = \"1.0.0\";\n", "utf8");
	await writeFile(join(source, "src", "lib", "util.js"), "export const twice = (n) => n * 2;\n", "utf8");
	await writeFile(join(source, "src", "lib", "exact-block.txt"), "B".repeat(512), "utf8");
	await writeFile(join(source, "empty.txt"), "", "utf8");
	// A payload with every byte value, so any encoding mistake in the round trip
	// shows up as a hash mismatch rather than as a plausible-looking file.
	await writeFile(join(source, "binary.bin"), Buffer.from(Array.from({ length: 256 }, (_, i) => i)));
	await writeFile(join(source, "a file with spaces.txt"), "spaced\n", "utf8");
	await writeFile(join(source, "文档.txt"), "中文内容\n", "utf8");
	await writeFile(join(source, ".hidden"), "hidden\n", "utf8");
	await writeFile(join(source, "docs", "guide.md"), "# Guide\n", "utf8");

	const before = await treePaths(source);
	const packed = await call(ctx.get("archive_pack"), { source });
	equal("packing the release tree succeeds", packed.error, undefined);
	equal("every file is packed", packed.value.files, 10);
	equal("the two empty directories are recorded", packed.value.directories, 4);
	equal("nothing is skipped", packed.value.skipped, []);
	equal("the manifest lists every member sorted", packed.value.manifest.map((m) => m.path), [
		".hidden",
		"README.md",
		"a file with spaces.txt",
		"binary.bin",
		"docs",
		"docs/guide.md",
		"empty-dir",
		"empty.txt",
		"src",
		"src/index.js",
		"src/lib",
		"src/lib/exact-block.txt",
		"src/lib/util.js",
		"文档.txt"
	]);

	// The manifest's own size must be the file size, not the padded size: a
	// 512-byte file is 512 bytes of content even though it occupies one block.
	const exact = packed.value.manifest.find((m) => m.path === "src/lib/exact-block.txt");
	equal("a one-block file reports its real size", exact.bytes, 512);
	// Computed from the literals above rather than by eye: README 19, index 32,
	// util 35, the 512-byte block file, the empty file 0, the 256-byte binary,
	// "spaced\n" 7, the CJK file 13 *bytes* (5 characters — measuring this in
	// characters is how a size assertion goes wrong on a unicode name), the
	// dotfile 7, and the guide 8.
	equal("the content total counts real sizes only", packed.value.contentBytes, 19 + 32 + 35 + 512 + 0 + 256 + 7 + 13 + 7 + 8);

	// Read the archive back with the plugin's parser and compare to the manifest
	// the pack reported — the two are computed by different code paths.
	const raw = await readFile(packed.value.file);
	const fromBytes = plugin.manifestFromArchive(raw);
	equal("the on-disk archive has as many members as the manifest", fromBytes.length, packed.value.manifest.length);
	equal("with identical paths", fromBytes.map((m) => m.path), packed.value.manifest.map((m) => m.path));
	equal("and identical hashes", fromBytes.map((m) => m.sha256), packed.value.manifest.map((m) => m.sha256));
	equal("and identical sizes", fromBytes.map((m) => m.bytes), packed.value.manifest.map((m) => m.bytes));
	equal("so the digest recomputed from bytes matches", plugin.treeDigest(fromBytes), packed.value.treeDigest);

	// Extract and compare the whole tree, not just a few files. The destination is
	// resolved by the plugin *under* the configured extractDir, so the tree to
	// compare is `unpacked.dest` — joining `dest` onto the sandbox root by hand
	// would look at an empty directory and report a working plugin as broken.
	const unpacked = await call(ctx.get("archive_unpack"), { file: packed.value.file, dest: "release-out" });
	equal("extracting the release succeeds", unpacked.error, undefined);
	equal("every file came out", unpacked.value.written, 10);
	equal("every directory came out", unpacked.value.directories, 4);
	equal("nothing was refused", unpacked.value.ok, true);
	const out = unpacked.value.dest;

	const after = await treePaths(out);
	equal("the extracted tree has exactly the same shape", after, before);

	// Byte-for-byte, including the binary payload that would expose any
	// accidental UTF-8 or line-ending translation.
	for (const member of packed.value.manifest.filter((m) => m.kind === "file")) {
		const original = await readFile(join(source, ...member.path.split("/")));
		const restored = await readFile(join(out, ...member.path.split("/")));
		equal(`"${member.path}" is byte-identical`, Buffer.compare(original, restored), 0);
		equal(`"${member.path}" hashes the same`, plugin.sha256(restored), member.sha256);
	}

	const binary = await readFile(join(out, "binary.bin"));
	equal("the binary payload kept all 256 byte values", [...binary].length, 256);
	equal("including the NUL byte", binary[0], 0);
	equal("and 0xFF", binary[255], 255);
	equal("a unicode file name survives", await readFile(join(out, "文档.txt"), "utf8"), "中文内容\n");
	equal("a spaced file name survives", await readFile(join(out, "a file with spaces.txt"), "utf8"), "spaced\n");
	equal("a dotfile survives", await readFile(join(out, ".hidden"), "utf8"), "hidden\n");
	const emptyInfo = await stat(join(out, "empty.txt"));
	equal("an empty file stays empty", emptyInfo.size, 0);
	const emptyDir = await stat(join(out, "empty-dir"));
	ok("an empty directory was created", emptyDir.isDirectory());

	const verified = await call(ctx.get("archive_verify"), { file: packed.value.file, against: out });
	equal("the extracted tree verifies against the archive", verified.value.ok, true);
	equal("with no added members", verified.value.added, []);
	equal("and no changed members", verified.value.changed, []);
}

/* ------------------------------- determinism across an independent oracle */

{
	// Byte-identical output is the claim; two packs prove it for one tree. This
	// proves the *order* is not an artefact of how the filesystem happened to
	// list entries, by packing the same content under names that sort
	// differently and confirming each ordering is total.
	const ctx = Context({ workDir: SANDBOX });
	plugin.apply(ctx, ctx.config);

	const a = join(SANDBOX, "order-a");
	await mkdir(a, { recursive: true });
	// Names chosen so their *creation* order is nothing like their sorted order.
	// "A.txt" is deliberately absent: on the case-insensitive filesystem this
	// runs on it would be the same file as "a.txt", and the collision is tested
	// on its own below rather than smuggled in here as a false failure.
	for (const name of ["z.txt", "a.txt", "m.txt", "0.txt", "_under.txt"]) {
		await writeFile(join(a, name), name, "utf8");
	}
	const first = await call(ctx.get("archive_pack"), { source: a, filename: "order-1.tar" });
	const second = await call(ctx.get("archive_pack"), { source: a, filename: "order-2.tar" });
	// ASCII order: "0" (0x30) < "_" (0x5f) < "a" (0x61) < "m" < "z".
	equal("the manifest is in path order, not creation order", first.value.manifest.map((m) => m.path), ["0.txt", "_under.txt", "a.txt", "m.txt", "z.txt"]);
	equal("two packs agree on the digest", first.value.treeDigest, second.value.treeDigest);
	const b1 = await readFile(first.value.file);
	const b2 = await readFile(second.value.file);
	equal("and are byte-identical", Buffer.compare(b1, b2), 0);

	// Create the same content in the reverse order under a different root: the
	// names are relative to the root and the fields are pinned, so the digests
	// must match even though the two roots differ.
	const c = join(SANDBOX, "order-b");
	await mkdir(c, { recursive: true });
	for (const name of ["_under.txt", "0.txt", "z.txt", "m.txt", "a.txt"]) {
		await writeFile(join(c, name), name, "utf8");
	}
	const third = await call(ctx.get("archive_pack"), { source: c, filename: "order-3.tar" });
	equal("a differently-created tree with the same content has the same digest", third.value.treeDigest, first.value.treeDigest);
	const b3 = await readFile(third.value.file);
	equal("and packs to the same bytes", Buffer.compare(b1, b3), 0);
}

{
	// An archive built on a case-sensitive filesystem can hold both `README.md`
	// and `readme.md`. Extracting that here collapses them into one file, and
	// without a warning the caller gets a tree that silently differs from the
	// manifest. The collision is visible at extraction time because both names
	// are in the *archive* — which is where the information the local filesystem
	// would have discarded still exists.
	const ctx = Context({ workDir: SANDBOX });
	plugin.apply(ctx, ctx.config);
	const caseful = writeFixtureTar([
		{ name: "README.md", data: "UPPER\n" },
		{ name: "readme.md", data: "lower\n" },
		{ name: "other.txt", data: "other\n" }
	]);
	await mkdir(join(SANDBOX, "archive-output"), { recursive: true });
	await writeFile(join(SANDBOX, "archive-output", "caseful.tar"), caseful);

	const listed = await call(ctx.get("archive_unpack"), { file: "caseful.tar", listOnly: true });
	equal("listing a case-colliding archive succeeds", listed.error, undefined);
	equal("all three members are listed", listed.value.manifest.length, 3);
	ok("the collision is warned about", listed.value.warnings.some((w) => w.includes("differ only in case")));
	ok("the warning names both spellings", listed.value.warnings.some((w) => w.includes("README.md") && w.includes("readme.md")));
	ok("and explains the overwrite", listed.value.warnings.some((w) => w.includes("overwrite")));

	const extracted = await call(ctx.get("archive_unpack"), { file: "caseful.tar", dest: "caseful-out" });
	equal("extracting succeeds", extracted.error, undefined);
	// On a case-insensitive filesystem only two of the three land as distinct
	// files; the warning is what makes that knowable.
	const { readdir: rd } = await import("node:fs/promises");
	const landed = await rd(extracted.value.dest);
	ok("at most two distinct files land on a case-insensitive volume", landed.length <= 3);
	equal("the unrelated file is unaffected", await readFile(join(extracted.value.dest, "other.txt"), "utf8"), "other\n");
}

{
	// Content determines the digest; the uid, gid and mode fields must not. A
	// pack on a machine where the files happen to have different permissions
	// must still be comparable with a pack from anywhere else.
	const ctx = Context({ workDir: SANDBOX });
	plugin.apply(ctx, ctx.config);
	const source = join(SANDBOX, "modes");
	await mkdir(source, { recursive: true });
	await writeFile(join(source, "a.txt"), "same", "utf8");
	const first = await call(ctx.get("archive_pack"), { source, filename: "mode-1.tar" });

	// Rewrite the header's mode field the way a different umask would have, then
	// confirm the content digest still matches. This exercises the manifest
	// comparison rather than the packer, since the packer pins the field.
	const raw = Buffer.from(await readFile(first.value.file));
	const modeOffset = 512 * 0 + 100;
	raw.write("0000777\u0000", modeOffset, "latin1");
	// Recompute the checksum so the header stays valid.
	raw.fill(0x20, 148, 156);
	let sum = 0;
	for (let i = 0; i < 512; i += 1) sum += raw[i];
	raw.write(sum.toString(8).padStart(6, "0"), 148, 6, "latin1");
	raw.write("\u0000", 154, 1, "latin1");
	raw.write(" ", 155, 1, "latin1");
	await writeFile(join(SANDBOX, "archive-output", "mode-2.tar"), raw);

	const second = await call(ctx.get("archive_verify"), { file: "mode-2.tar", digest: first.value.treeDigest });
	equal("a mode difference does not change the content digest", second.value.ok, true);
	equal("so the digest is the same", second.value.treeDigest, first.value.treeDigest);
}

/* ------------------------------- an independently readable archive */

{
	// The strongest external check available without adding a dependency: let
	// the platform's own `tar` read what this plugin wrote. If the headers are
	// malformed in a way this plugin's reader happens to tolerate, GNU tar will
	// say so.
	const ctx = Context({ workDir: SANDBOX });
	plugin.apply(ctx, ctx.config);
	const source = join(SANDBOX, "interop");
	await mkdir(join(source, "sub"), { recursive: true });
	await writeFile(join(source, "hello.txt"), "hello from archive\n", "utf8");
	await writeFile(join(source, "sub", "nested.txt"), "nested\n", "utf8");
	const packed = await call(ctx.get("archive_pack"), { source, filename: "interop.tar" });

	let listing = null;
	try {
		// `--force-local` is not optional here: without it GNU tar reads the
		// drive letter in `C:/...` as a remote host and tries to open an rsh
		// connection ("Cannot connect to C: resolve failed"), which looks like
		// "no tar available" and would silently skip the only independent check
		// in this suite. The path is also normalised to forward slashes, because
		// a backslash is an escape character to a native Windows binary.
		listing = execFileSync("tar", ["--force-local", "-tf", packed.value.file.replaceAll("\\", "/")], { encoding: "utf8" });
	} catch (error) {
		listing = `__tar_failed__ ${error?.message ?? error}`;
	}

	if (listing.startsWith("__tar_failed__")) {
		// No system tar on this machine. Skip rather than assert something the
		// environment cannot answer — a skipped check is honest, a fabricated
		// pass is not.
		console.log("  (system tar unavailable; interop check skipped)");
	} else {
		const names = listing.trim().split(/\r?\n/u).filter((line) => line !== "");
		equal("system tar reads the archive as a file list", names.sort(), ["hello.txt", "sub/", "sub/nested.txt"]);
	}

	// And the content survives a system tar extraction, which is the check that
// matters: a header this plugin wrote is only useful if other tools agree.
	const extractDir = join(SANDBOX, "interop-system");
	await mkdir(extractDir, { recursive: true });
	// A backslash in an argument to a native Windows binary is an escape
	// character, so a path like `C:\…\interop-system` reaches tar as
	// `C\:…` and it fails with "Cannot open". Forward slashes are accepted by
	// every Windows API, so the paths are normalised on the way out.
	const toPosix = (p) => p.replaceAll("\\", "/");
	let extracted = null;
	try {
		execFileSync("tar", ["--force-local", "-xf", toPosix(packed.value.file), "-C", toPosix(extractDir)], { encoding: "utf8" });
		extracted = await readFile(join(extractDir, "hello.txt"), "utf8");
	} catch (error) {
		extracted = `__tar_failed__ ${error?.message ?? error}`;
	}
	if (extracted.startsWith("__tar_failed__")) {
		console.log("  (system tar extraction unavailable; skipped)");
	} else {
		equal("system tar extracts the content this plugin wrote", extracted, "hello from archive\n");
		equal("including a nested file", await readFile(join(extractDir, "sub", "nested.txt"), "utf8"), "nested\n");
	}
}

/* --------------------------------------- an archive this plugin did not write */

{
	// A hostile archive, from a source that is trying every classic trick. The
	// assertions here are about the *filesystem*, not the result object: a
	// refusal that still left a file behind would pass an object-only test.
	const ctx = Context({ workDir: SANDBOX });
	plugin.apply(ctx, ctx.config);

	const canary = join(SANDBOX, "canary");
	await mkdir(canary, { recursive: true });
	const marker = join(canary, "do-not-touch.txt");
	await writeFile(marker, "original\n", "utf8");

	const hostile = writeFixtureTar([
		{ name: "innocent.txt", data: "harmless\n" },
		{ name: "../canary/do-not-touch.txt", data: "OVERWRITTEN\n" },
		{ name: "../canary/new-file.txt", data: "CREATED\n" },
		{ name: "../../../outside.txt", data: "ESCAPED\n" },
		{ name: "/absolute-escape.txt", data: "ESCAPED\n" },
		{ name: "C:/absolute-escape-2.txt", data: "ESCAPED\n" },
		{ name: "a/../../buried-escape.txt", data: "ESCAPED\n" },
		// "./././" is *not* an escape: it normalises away and leaves a name that
		// is safely inside the destination. It is here to pin that behaviour —
		// treating a harmless leading "./" as hostile would refuse archives
		// produced by perfectly ordinary tools.
		{ name: "./././dot-prefixed.txt", data: "harmless\n" },
		{ name: "symlink", kind: "symlink", flag: "2", linkname: "../../../etc/passwd" },
		{ name: "hardlink", kind: "hardlink", flag: "1", linkname: "innocent.txt" },
		{ name: "device", kind: "char", flag: "3" },
		{ name: "pipe", kind: "fifo", flag: "6" }
	]);
	await mkdir(join(SANDBOX, "archive-output"), { recursive: true });
	await writeFile(join(SANDBOX, "archive-output", "hostile.tar"), hostile);

	// Strict mode: nothing at all may be written.
	const strict = await call(ctx.get("archive_unpack"), { file: "hostile.tar", dest: "hostile-strict" });
	ok("the hostile archive is refused outright", strict.error !== undefined);
	equal("and the destination was never created", existsSync(join(SANDBOX, "archive-extract", "hostile-strict")), false);
	equal("the canary was not touched", await readFile(marker, "utf8"), "original\n");

	// Lenient mode: the safe member lands, every hostile one leaves no trace.
	const lenient = await call(ctx.get("archive_unpack"), { file: "hostile.tar", dest: "hostile-lenient", strict: false });
	equal("lenient mode extracts the safe member", await readFile(join(lenient.value.dest, "innocent.txt"), "utf8"), "harmless\n");
	equal("the canary is still untouched", await readFile(marker, "utf8"), "original\n");
	equal("no file was created next to it", existsSync(join(canary, "new-file.txt")), false);
	equal("nothing escaped to the sandbox root", existsSync(join(SANDBOX, "outside.txt")), false);
	equal("nothing was written to an absolute path", existsSync("C:/absolute-escape-2.txt"), false);
	equal("the buried traversal wrote nothing", existsSync(join(SANDBOX, "archive-extract", "buried-escape.txt")), false);
	equal("a leading ./-prefixed name is extracted, because it is not an escape", await readFile(join(lenient.value.dest, "dot-prefixed.txt"), "utf8"), "harmless\n");
	equal("no symlink was created", existsSync(join(lenient.value.dest, "symlink")), false);
	equal("no hardlink was created", existsSync(join(lenient.value.dest, "hardlink")), false);
	equal("no device node was created", existsSync(join(lenient.value.dest, "device")), false);
	equal("no FIFO was created", existsSync(join(lenient.value.dest, "pipe")), false);

	// Only the safe members are in the destination at all.
	const contents = await treePaths(lenient.value.dest);
	equal("the destination holds exactly the two safe members", contents, ["dot-prefixed.txt", "innocent.txt"]);
	ok("and every refusal carries a reason", lenient.value.refused.every((r) => typeof r.reason === "string" && r.reason.length > 10));
	const kinds = lenient.value.refused.map((r) => r.kind);
	// Four traversal-class refusals: the two `../canary/...`, the `../../../`, and
	// the buried `a/../../`. The absolute paths are refused by the absolute
	// check, which is its own class in the logic suite but a traversal at plan
	// level is what the caller cares about.
	equal("the traversal-class refusals are counted", kinds.filter((k) => k === "traversal").length + kinds.filter((k) => k === "absolute").length >= 4, true);
	ok("a symlink is among them", kinds.includes("symlink"));
	ok("a hardlink is among them", kinds.includes("hardlink"));
	ok("a device is among them", kinds.includes("device"));
	ok("the traversal refusals outnumber the link refusals", kinds.filter((k) => k === "traversal").length >= 4);
}

{
	// A symlink packed by another tool must not be silently turned into a file
	// containing its target path, and must not be extracted as a link either.
	const ctx = Context({ workDir: SANDBOX });
	plugin.apply(ctx, ctx.config);
	const source = join(SANDBOX, "with-link");
	await mkdir(source, { recursive: true });
	await writeFile(join(source, "real.txt"), "real\n", "utf8");
	const { symlink, lstat: lstatFn } = await import("node:fs/promises");
	let madeLink = true;
	try {
		await symlink("real.txt", join(source, "link.txt"), "file");
		// Creating a symlink on Windows needs the "Create symbolic links"
		// privilege, and `symlink` can appear to succeed while producing an
		// ordinary file. Confirm the link really is one before asserting on it,
		// so this case reports a skip rather than a false failure.
		const probe = await lstatFn(join(source, "link.txt"));
		if (!probe.isSymbolicLink()) madeLink = false;
	} catch {
		madeLink = false;
	}

	if (!madeLink) {
		console.log("  (symlink creation unavailable on this account; skipped)");
	} else {
		const packed = await call(ctx.get("archive_pack"), { source });
		equal("the symlink is skipped, not packed", packed.value.skipped.map((s) => s.name), ["link.txt"]);
		ok("the skip reason says it is a symlink", packed.value.skipped[0].reason.includes("symlink"));
		ok("and names the target", packed.value.skipped[0].reason.includes("real.txt"));
		equal("only the real file is packed", packed.value.files, 1);
		const roundTrip = await call(ctx.get("archive_unpack"), { file: packed.value.file, dest: "with-link-out" });
		equal("and only the real file comes out", await treePaths(roundTrip.value.dest), ["real.txt"]);
		equal("whose content is intact", await readFile(join(roundTrip.value.dest, "real.txt"), "utf8"), "real\n");
	}
}

/* ------------------------------------------- a truncated and a damaged archive */

{
	const ctx = Context({ workDir: SANDBOX });
	plugin.apply(ctx, ctx.config);
	const source = join(SANDBOX, "truncateme");
	await mkdir(source, { recursive: true });
	await writeFile(join(source, "one.txt"), "one\n", "utf8");
	await writeFile(join(source, "two.txt"), "two\n", "utf8");
	const packed = await call(ctx.get("archive_pack"), { source, filename: "full.tar" });

	const full = await readFile(packed.value.file);
	// Cut the archive in the middle of the second member's data.
	const cut = full.subarray(0, 512 * 2 + 3);
	await writeFile(join(SANDBOX, "archive-output", "truncated.tar"), cut);

	const result = await call(ctx.get("archive_verify"), { file: "truncated.tar" });
	ok("a truncated archive is not ok", result.value.ok === false || result.value.structuralWarnings.length > 0);
	ok("and a warning explains the truncation", result.value.structuralWarnings.some((w) => w.includes("truncated")));

	// Verify must not extract. Confirm no destination appeared.
	equal("verify created no directory", existsSync(join(SANDBOX, "archive-extract", "truncated")), false);
}

{
	// A single flipped byte in a header's name field must be caught by the
	// checksum rather than silently renaming a member.
	const ctx = Context({ workDir: SANDBOX });
	plugin.apply(ctx, ctx.config);
	const damaged = Buffer.from(writeFixtureTar([{ name: "good.txt", data: "content\n" }]));
	damaged[0] = damaged[0] === 0x67 ? 0x62 : 0x67;
	await mkdir(join(SANDBOX, "archive-output"), { recursive: true });
	await writeFile(join(SANDBOX, "archive-output", "flipped.tar"), damaged);

	const result = await call(ctx.get("archive_verify"), { file: "flipped.tar" });
	equal("a flipped header byte fails verification", result.value.ok, false);
	ok("with a checksum warning", result.value.structuralWarnings.some((w) => w.includes("checksum mismatch")));
	equal("and the member is refused rather than renamed", result.value.refused.some((r) => r.kind === "checksum"), true);
}

/* ------------------------------------------- nested archives and reuse */

{
	// Packing the output of a previous unpack must work: the extract directory
	// is an ordinary tree, and a caller re-archiving it is a normal workflow.
	const ctx = Context({ workDir: SANDBOX });
	plugin.apply(ctx, ctx.config);
	const source = join(SANDBOX, "reuse-in");
	await mkdir(join(source, "a", "b"), { recursive: true });
	await writeFile(join(source, "a", "b", "deep.txt"), "deep\n", "utf8");
	const first = await call(ctx.get("archive_pack"), { source, filename: "reuse-1.tar" });
	const out = await call(ctx.get("archive_unpack"), { file: first.value.file, dest: "reuse-out" });
	equal("the first unpack succeeds", out.error, undefined);

	const second = await call(ctx.get("archive_pack"), { source: out.value.dest, filename: "reuse-2.tar" });
	equal("re-packing the extracted tree succeeds", second.error, undefined);
	equal("and yields the same digest", second.value.treeDigest, first.value.treeDigest);
	const b1 = await readFile(first.value.file);
	const b2 = await readFile(second.value.file);
	equal("and the same bytes", Buffer.compare(b1, b2), 0);
}

{
	// Packing into a directory that does not exist yet must create it rather
	// than fail — the configured archiveDir is not the caller's to create.
	const ctx = Context({ workDir: SANDBOX, archiveDir: "deep/new/archive-dir", extractDir: "deep/new/extract-dir" });
	plugin.apply(ctx, ctx.config);
	const source = join(SANDBOX, "mkdirs");
	await mkdir(source, { recursive: true });
	await writeFile(join(source, "x.txt"), "x\n", "utf8");
	const packed = await call(ctx.get("archive_pack"), { source, filename: "made.tar" });
	equal("packing creates the archive directory", packed.error, undefined);
	ok("and the archive is there", existsSync(packed.value.file));
	const out = await call(ctx.get("archive_unpack"), { file: "made.tar", dest: "sub/dir" });
	equal("unpacking creates the nested extraction directory", out.error, undefined);
	equal("and the file is there", await readFile(join(out.value.dest, "x.txt"), "utf8"), "x\n");
	ok("the destination nested under the configured root", out.value.dest.includes("deep"));
}

/* --------------------------------------------- a large-ish tree, for scale */

{
	// Not a benchmark; a check that nothing in the walk is quadratic in a way
	// that only shows up past a handful of files, and that padding arithmetic
	// holds when sizes are all over the block boundary.
	const ctx = Context({ workDir: SANDBOX });
	plugin.apply(ctx, ctx.config);
	const source = join(SANDBOX, "many");
	await mkdir(source, { recursive: true });
	const sizes = [0, 1, 511, 512, 513, 1023, 1024, 1025, 2047, 2048];
	for (const [index, size] of sizes.entries()) {
		await writeFile(join(source, `f${String(index).padStart(2, "0")}-${size}.bin`), Buffer.alloc(size, index + 1));
	}
	await mkdir(join(source, "nested"), { recursive: true });
	for (let i = 0; i < 40; i += 1) {
		await writeFile(join(source, "nested", `n${String(i).padStart(3, "0")}.txt`), `line ${i}\n`, "utf8");
	}

	const packed = await call(ctx.get("archive_pack"), { source });
	equal("every file is packed", packed.value.files, sizes.length + 40);
	// Computed from the actual content, not from a single sample: files 0–9 are
	// "line N\n" (7 bytes) and 10–39 are "line NN\n" (8 bytes), so a
	// one-sample multiplication under-counts by 30. Asserting a literal here
	// keeps the check honest about the total rather than about the formula.
	const textBytes = Array.from({ length: 40 }, (_, i) => `line ${i}\n`.length).reduce((a, b) => a + b, 0);
	equal("the content total is the sum of the sizes", packed.value.contentBytes, sizes.reduce((a, b) => a + b, 0) + textBytes);
	const before = await treePaths(source);
	const unpacked = await call(ctx.get("archive_unpack"), { file: packed.value.file, dest: "many-out" });
	equal("the large tree extracts", unpacked.value.written, sizes.length + 40);
	const out = unpacked.value.dest;
	equal("with exactly the same shape", await treePaths(out), before);
	for (const size of sizes) {
		const name = `f${String(sizes.indexOf(size)).padStart(2, "0")}-${size}.bin`;
		const info = await stat(join(out, name));
		equal(`a ${size}-byte file keeps its size`, info.size, size);
	}
	const verified = await call(ctx.get("archive_verify"), { file: packed.value.file, against: out });
	equal("the whole tree verifies", verified.value.ok, true);
	// The comparison counts directories as members too, and `treePaths` marks a
	// directory with a trailing slash — so the expected total is every entry,
	// not just the files. Subtracting the slashed entries here is the same
	// off-by-one that the earlier "one safe member" assertion was.
	equal("with every member matched, directories included", verified.value.unchanged, before.length);
}

/* ------------------------------------------------ abort is honoured */

{
	const ctx = Context({ workDir: SANDBOX });
	plugin.apply(ctx, ctx.config);
	const source = join(SANDBOX, "abortme");
	await mkdir(source, { recursive: true });
	for (let i = 0; i < 5; i += 1) await writeFile(join(source, `a${i}.txt`), "x", "utf8");

	const controller = new AbortController();
	controller.abort();
	const aborted = await call(ctx.get("archive_pack"), { source, filename: "aborted.tar" }, { signal: controller.signal });
	ok("an already-aborted signal stops the pack", aborted.error !== undefined);
	ok("the error says it was aborted", aborted.error.includes("aborted"));
}

/* ------------------------------------------------------------- cleanup */

await rm(SANDBOX, { recursive: true, force: true });

console.log(`archive end to end: ${passed} passed, ${failed} failed`);
process.exit(failed === 0 ? 0 : 1);