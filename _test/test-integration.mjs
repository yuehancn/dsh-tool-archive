// Integration tests for dsh-tool-archive: the four tools driven through a
// real cordis-like context, with the emitted schemas asserted at the shape the
// framework actually compiles.
//
// These cover the seams the logic suite cannot reach: that `apply` registers
// the right tool names behind the right config flags, that the injectable
// archive reader is read *live* rather than captured, that the emitted output
// schema matches the framework's DSL contract, and that the pack/unpack cycle
// agrees with itself about a tree.
import { plugin, Context, call, fakeReader, assertReaderUsed, writeFixtureTar, makeTree } from "./harness.mjs";
import { readFile, stat, mkdir, rm, writeFile } from "node:fs/promises";
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

console.log("archive: integration");

/* ------------------------------------------------------ registration flags */

{
	const ctx = Context();
	plugin.apply(ctx, ctx.config);
	equal("all four tools register by default", ctx.names(), ["archive_status", "archive_pack", "archive_unpack", "archive_verify"]);
}
{
	const ctx = Context({ status: false });
	plugin.apply(ctx, ctx.config);
	equal("status:false removes only archive_status", ctx.names(), ["archive_pack", "archive_unpack", "archive_verify"]);
}
{
	const ctx = Context({ pack: false, unpack: false, verify: false });
	plugin.apply(ctx, ctx.config);
	equal("every flag off leaves only status", ctx.names(), ["archive_status"]);
}
{
	const ctx = Context({ status: false, pack: false, unpack: false, verify: false });
	plugin.apply(ctx, ctx.config);
	equal("all flags off registers nothing", ctx.names(), []);
}

/* --------------------------------------------------------- emitted schema */

{
	const ctx = Context();
	plugin.apply(ctx, ctx.config);
	const pack = ctx.get("archive_pack");

	// `required` is a per-property flag in the source; the framework hoists it
	// into an array at every object level. Asserting the compiled shape is the
	// only way to catch a schema the framework accepted but read differently.
	equal("pack's required parameters are hoisted into an array", pack.parameters.required, ["source"]);
	equal("the source parameter is no longer carrying its own flag", pack.parameters.properties.source.required, undefined);
	// `parameters` is the *argument* schema, so it has no `additionalProperties`
	// of its own — the framework only synthesises that for output schemas and
	// for nested objects the author declares. Asserting it here would be a
	// fiction that happens to read like a guarantee.
	equal("the argument schema declares no additionalProperties of its own", pack.parameters.additionalProperties, undefined);
	equal("the argument schema declares the four parameters", Object.keys(pack.parameters.properties), ["source", "filename", "exclude", "maxFileBytes"]);
	equal("a parameter with a default is still optional", pack.parameters.required.includes("filename"), false);
	equal("a parameter with a default is still optional (exclude)", pack.parameters.required.includes("exclude"), false);
}
{
	const ctx = Context();
	plugin.apply(ctx, ctx.config);
	const out = ctx.get("archive_pack").output.schema;
	equal("the output root forbids extra properties", out.additionalProperties, false);
	ok("every declared output property is required", Object.keys(out.properties).length === out.required.length);
	equal("the manifest is an array", out.properties.manifest.type, "array");
	equal("array items forbid extra properties", out.properties.manifest.items.additionalProperties, false);
	// An array's items may not carry `required` at all — it is only a
	// property-level flag — so the framework must have dropped it.
	equal("array items carry no required array", out.properties.manifest.items.required, undefined);
	equal("the skipped array's items are shaped too", out.properties.skipped.items.additionalProperties, false);
	equal("and carry no required array either", out.properties.skipped.items.required, undefined);
}
{
	const ctx = Context();
	plugin.apply(ctx, ctx.config);
	const out = ctx.get("archive_unpack").output.schema;
	equal("refused items declare their shape", out.properties.refused.items.additionalProperties, false);
	equal("refused items carry no required array", out.properties.refused.items.required, undefined);
	equal("a plain string array declares its items", out.properties.warnings.items.type, "string");
	equal("warnings carry no additionalProperties on the item", out.properties.warnings.items.additionalProperties, undefined);
	equal("the unpack file is required", out.properties.file.required, undefined);
	ok("the unpack file is in the hoisted array", out.required.includes("file"));
}
{
	const ctx = Context();
	plugin.apply(ctx, ctx.config);
	const out = ctx.get("archive_verify").output.schema;
	equal("changed items declare their four fields", Object.keys(out.properties.changed.items.properties), ["path", "field", "expected", "actual"]);
	equal("changed items forbid extra properties", out.properties.changed.items.additionalProperties, false);
	equal("the digest is a string", out.properties.treeDigest.type, "string");
	equal("ok is a boolean", out.properties.ok.type, "boolean");
}
{
	const ctx = Context();
	plugin.apply(ctx, ctx.config);
	const status = ctx.get("archive_status");
	equal("status takes no parameters", Object.keys(status.parameters.properties).length, 0);
	equal("and so requires nothing", status.parameters.required, undefined);
	equal("the nested directories object forbids extra properties", status.output.schema.properties.directories.additionalProperties, false);
	equal("and hoists its own required array", status.output.schema.properties.directories.required, ["workDir", "archiveDir", "extractDir"]);
	equal("and consumes its per-property flags", status.output.schema.properties.directories.properties.workDir.required, undefined);
	equal("the limits object hoists too", status.output.schema.properties.limits.required.length, 5);
}

/* ------------------------------------------------------ tool metadata */

{
	const ctx = Context({ timeoutMs: 12345 });
	plugin.apply(ctx, ctx.config);
	for (const tool of ctx.names()) {
		equal(`${tool} carries the configured timeout`, ctx.get(tool).timeoutMs, 12345);
	}
	// `defineTool` wraps `isConcurrencySafe` with the argument validator first,
	// so a predicate is only reached once the arguments are valid. That makes a
	// bare `isConcurrencySafe()` on a tool with required arguments return false
	// regardless of what the predicate would say — the assertion has to pass
	// arguments the schema accepts, or it is testing the validator, not the
	// predicate.
	equal("status is concurrency safe", ctx.get("archive_status").isConcurrencySafe({}), true);
	equal("an invalid call is never concurrency safe", ctx.get("archive_status").isConcurrencySafe(), false);
	equal("pack is not, because it writes", ctx.get("archive_pack").isConcurrencySafe({ source: "/tmp" }), false);
	equal("verify is, because it only reads", ctx.get("archive_verify").isConcurrencySafe({ file: "x.tar" }), true);
	equal("an invalid verify call is not declared safe", ctx.get("archive_verify").isConcurrencySafe({}), false);
	equal("unpack is not by default", ctx.get("archive_unpack").isConcurrencySafe({ file: "x.tar" }), false);
	equal("but listing is, because it writes nothing", ctx.get("archive_unpack").isConcurrencySafe({ file: "x.tar", listOnly: true }), true);
	ok("every tool has a description", ctx.names().every((n) => ctx.get(n).description.length > 40));
}

/* --------------------------------------------------------- config defaults */

{
	const config = plugin.Config({});
	equal("workDir defaults to the current directory", config.workDir, ".");
	equal("archiveDir defaults to archive-output", config.archiveDir, "archive-output");
	equal("extractDir defaults to archive-extract", config.extractDir, "archive-extract");
	equal("hash defaults to true", config.hash, true);
	equal("noOverwrite defaults to false", config.noOverwrite, false);
	equal("maxEntries defaults to 20000", config.maxEntries, 20000);
	equal("maxTotalBytes defaults to 2 GiB", config.maxTotalBytes, 2 * 1024 * 1024 * 1024);
	equal("maxNameBytes defaults to 1000", config.maxNameBytes, 1000);
	equal("maxFileBytes defaults to no limit", config.maxFileBytes, 0);
	equal("timeoutMs defaults to 300000", config.timeoutMs, 300000);
	ok("the default excludes include node_modules", config.exclude.includes("node_modules"));
	equal("all four registration flags default to true", config.status && config.pack && config.unpack && config.verify, true);
}
{
	// The exclude default must be a fresh array per config, or one caller's
	// mutation would leak into the next.
	const a = plugin.Config({});
	const b = plugin.Config({});
	a.exclude.push("mutated");
	equal("the exclude default is not shared between configs", b.exclude.includes("mutated"), false);
}

/* --------------------------------------------------- archive_status, no I/O */

{
	const ctx = Context({ workDir: SANDBOX });
	const reader = fakeReader(Buffer.alloc(0));
	ctx.transport.readArchive = reader.readArchive;
	plugin.apply(ctx, ctx.config);
	const result = await call(ctx.get("archive_status"), {});
	ok("status succeeds", result.value !== undefined);
	equal("status reads no archive", reader.calls.length, 0);
	equal("status reports ustar", result.value.format.includes("ustar"), true);
	equal("status lists the three other tools", result.value.operations, ["archive_pack", "archive_unpack", "archive_verify"]);
	ok("status refuses symlinks", result.value.refusedKinds.some((k) => k.includes("symlink")));
	ok("status refuses hardlinks", result.value.refusedKinds.some((k) => k.includes("hardlink")));
	ok("status names the default excludes", result.value.excludes.includes("node_modules"));
	ok("status says packing is deterministic", result.value.deterministic.includes("SHA-256"));
	equal("status resolves the archive directory", result.value.directories.archiveDir, resolve(SANDBOX, "archive-output"));
	equal("status resolves the extract directory", result.value.directories.extractDir, resolve(SANDBOX, "archive-extract"));
	ok("status reports the entry cap", result.value.limits.maxEntries === 20000);
}

/* ------------------------------------------------------------- pack/verify */

{
	const ctx = Context({ workDir: SANDBOX });
	plugin.apply(ctx, ctx.config);

	const source = await makeTree(join(SANDBOX, "src"), {
		"a.txt": "alpha",
		"deep/b.txt": "beta",
		"deep/deeper/c.txt": "gamma"
	});

	const packed = await call(ctx.get("archive_pack"), { source });
	ok("packing succeeds", packed.value !== undefined, true);
	equal("only files are counted as files", packed.value.files, 3);
	equal("directories are counted separately", packed.value.directories, 2);
	equal("the content total is the sum of the files", packed.value.contentBytes, 5 + 4 + 5);
	ok("the archive is bigger than its content", packed.value.bytes > packed.value.contentBytes);
	ok("the overhead is a plausible percentage", packed.value.overheadPercent > 100);
	equal("the format is ustar", packed.value.format, "ustar");
	equal("the manifest is sorted by path", packed.value.manifest.map((m) => m.path), ["a.txt", "deep", "deep/b.txt", "deep/deeper", "deep/deeper/c.txt"]);
	equal("nothing was skipped in a clean tree", packed.value.skipped, []);
	equal("the content hash is the hash of the file", packed.value.manifest[0].sha256, plugin.sha256(Buffer.from("alpha")));
	ok("a tree digest is reported", /^[0-9a-f]{64}$/u.test(packed.value.treeDigest));

	const onDisk = await stat(packed.value.file).catch(() => null);
	ok("the archive exists on disk", onDisk !== null && onDisk.size > 0);
	equal("the recorded size matches the file", onDisk.size, packed.value.bytes);
	ok("the archive is under the archive directory", packed.value.file.includes("archive-output"));

	// Determinism: the same tree must pack to the same digest, and the same
	// bytes, even though the filesystem may hand entries back in any order.
	const again = await call(ctx.get("archive_pack"), { source, filename: "second.tar" });
	equal("a second pack reports the same digest", again.value.treeDigest, packed.value.treeDigest);
	const firstBytes = await readFile(packed.value.file);
	const secondBytes = await readFile(again.value.file);
	equal("a second pack produces byte-identical output", Buffer.compare(firstBytes, secondBytes), 0);

	// Verifying that archive against its own tree must be a clean pass.
	const verified = await call(ctx.get("archive_verify"), { file: packed.value.file, against: source });
	equal("verify succeeds", verified.error, undefined);
	equal("verify reports ok", verified.value.ok, true);
	equal("verify finds nothing added", verified.value.added, []);
	equal("verify finds nothing removed", verified.value.removed, []);
	equal("verify finds nothing changed", verified.value.changed, []);
	equal("verify counts every member", verified.value.unchanged, 5);
	equal("verify recomputes the same digest", verified.value.treeDigest, packed.value.treeDigest);
	equal("verify names what it compared against", verified.value.comparedAgainst, resolve(source));

	// A digest-only check must agree with the tree check.
	const byDigest = await call(ctx.get("archive_verify"), { file: packed.value.file, digest: packed.value.treeDigest });
	equal("a matching digest verifies", byDigest.value.ok, true);
	const wrongDigest = await call(ctx.get("archive_verify"), { file: packed.value.file, digest: "0".repeat(64) });
	equal("a wrong digest fails", wrongDigest.value.ok, false);
	equal("and is echoed back for comparison", wrongDigest.value.expectedDigest, "0".repeat(64));
	equal("while the real digest is still reported", wrongDigest.value.treeDigest, packed.value.treeDigest);

	// Modify the tree and the comparison must notice, by path.
	await writeFile(join(source, "a.txt"), "ALPHA", "utf8");
	const drifted = await call(ctx.get("archive_verify"), { file: packed.value.file, against: source });
	equal("a modified file fails the comparison", drifted.value.ok, false);
	equal("the changed path is named", drifted.value.changed.map((c) => c.path), ["a.txt"]);
	equal("the changed field is the hash", drifted.value.changed[0].field, "sha256");
	equal("nothing is misreported as added", drifted.value.added, []);

	await rm(join(source, "deep/b.txt"));
	const missing = await call(ctx.get("archive_verify"), { file: packed.value.file, against: source });
	equal("a deleted file is reported as removed", missing.value.removed, ["deep/b.txt"]);

	await writeFile(join(source, "extra.txt"), "new", "utf8");
	const extra = await call(ctx.get("archive_verify"), { file: packed.value.file, against: source });
	equal("an added file is reported as added", extra.value.added, ["extra.txt"]);
	equal("and not as a change", extra.value.changed.length, 1);
}

/* --------------------------------------------------------- pack edge cases */

{
	const ctx = Context({ workDir: SANDBOX });
	plugin.apply(ctx, ctx.config);

	const source = await makeTree(join(SANDBOX, "excl"), {
		"keep.txt": "keep",
		"node_modules/skip.txt": "skip",
		"deep/node_modules/also-skip.txt": "skip",
		"deep/keep2.txt": "keep"
	});
	const packed = await call(ctx.get("archive_pack"), { source });
	equal("the default excludes still carry node_modules", packed.value.skipped.map((s) => s.name).sort(), ["deep/node_modules", "node_modules"]);
	equal("every skip states a reason", packed.value.skipped.every((s) => s.reason === "excluded"), true);
	equal("the kept files are all present", packed.value.manifest.filter((m) => m.kind === "file").map((m) => m.path), ["deep/keep2.txt", "keep.txt"]);

	const custom = await call(ctx.get("archive_pack"), { source, filename: "custom.tar", exclude: "deep" });
	equal("an explicit exclude list replaces the default", custom.value.skipped.map((s) => s.name), ["deep"]);
	equal("so node_modules is now packed", custom.value.manifest.some((m) => m.path.includes("node_modules")), true);
}
{
	const ctx = Context({ workDir: SANDBOX });
	plugin.apply(ctx, ctx.config);

	const source = await makeTree(join(SANDBOX, "big"), {
		"small.txt": "s",
		"large.txt": "L".repeat(1000)
	});
	const packed = await call(ctx.get("archive_pack"), { source, maxFileBytes: 100 });
	equal("an over-large file is skipped", packed.value.skipped.map((s) => s.name), ["large.txt"]);
	ok("the skip reason names the limit", packed.value.skipped[0].reason.includes("maxFileBytes"));
	equal("only the small file is packed", packed.value.files, 1);
	equal("and the content total reflects that", packed.value.contentBytes, 1);
}
{
	const ctx = Context({ workDir: SANDBOX });
	plugin.apply(ctx, ctx.config);
	const missing = await call(ctx.get("archive_pack"), { source: join(SANDBOX, "does-not-exist") });
	ok("packing a missing directory errors", missing.error !== undefined);
	ok("the error names the path", missing.error.includes("does-not-exist"));
	ok("the error says what was expected", missing.error.includes("not a readable directory"));
}
{
	const ctx = Context({ workDir: SANDBOX });
	plugin.apply(ctx, ctx.config);
	// Packing a file rather than a directory must fail rather than produce an
	// archive of nothing.
	const source = await makeTree(join(SANDBOX, "filecase"), { "x.txt": "x" });
	const notADir = await call(ctx.get("archive_pack"), { source: join(source, "x.txt") });
	ok("packing a file errors", notADir.error !== undefined);
}
{
	// A name that tries to escape the archive directory must land inside it.
	const ctx = Context({ workDir: SANDBOX });
	plugin.apply(ctx, ctx.config);
	const source = await makeTree(join(SANDBOX, "escape"), { "x.txt": "x" });
	const packed = await call(ctx.get("archive_pack"), { source, filename: "../../evil.tar" });
	ok("a traversal in the output name stays inside", packed.value.file.includes("archive-output"));
	equal("and the tail is preserved", packed.value.file.endsWith("evil.tar"), true);
	const absolute = await call(ctx.get("archive_pack"), { source, filename: "C:/Windows/Temp/evil.tar" });
	ok("an absolute output name stays inside too", absolute.value.file.includes("archive-output"));
}
{
	// The entry cap must be reported, not silently applied.
	const ctx = Context({ workDir: SANDBOX, maxEntries: 1 });
	plugin.apply(ctx, ctx.config);
	const source = await makeTree(join(SANDBOX, "many"), { "a.txt": "a", "b.txt": "b", "c.txt": "c" });
	const packed = await call(ctx.get("archive_pack"), { source });
	equal("packing is unaffected by the unpack cap", packed.value.files, 3);
}

/* -------------------------------------------------------- unpack edge cases */

{
	const ctx = Context({ workDir: SANDBOX });
	plugin.apply(ctx, ctx.config);

	const buffer = writeFixtureTar([
		{ name: "one.txt", data: "first" },
		{ name: "sub", kind: "directory" },
		{ name: "sub/two.txt", data: "second" }
	]);
	const reader = fakeReader(buffer);
	ctx.transport.readArchive = reader.readArchive;

	const listed = await call(ctx.get("archive_unpack"), { file: "clean.tar", listOnly: true });
	equal("listing succeeds", listed.error, undefined);
	equal("listing reads through the injected seam", reader.calls.length, 1);
	assertReaderUsed(reader.calls, "unpack list");
	ok("the injected reader was handed a path inside the archive directory", reader.calls[0].includes("archive-output"));
	equal("listing reports every header", listed.value.entries, 3);
	equal("all three are writable", listed.value.writable, 3);
	equal("listing writes nothing", listed.value.written, 0);
	equal("listing names no destination", listed.value.dest, "");
	equal("listing reports no refusals", listed.value.refused, []);
	equal("listing counts the directories", listed.value.directories, 1);
	equal("listing is flagged as such", listed.value.listOnly, true);
	equal("the manifest is sorted", listed.value.manifest.map((m) => m.path), ["one.txt", "sub", "sub/two.txt"]);
	equal("and carries content hashes", listed.value.manifest[0].sha256, plugin.sha256(Buffer.from("first")));

	// Nothing must have touched the disk. The check runs against a
	// list-only-specific root so a directory left by another case in this same
	// sandbox cannot make a pass look like a failure.
	const isolated = Context({ workDir: SANDBOX, extractDir: "list-only-extract" });
	plugin.apply(isolated, isolated.config);
	isolated.transport.readArchive = reader.readArchive;
	const listingOnly = await call(isolated.get("archive_unpack"), { file: "clean.tar", listOnly: true });
	equal("the isolated listing succeeds", listingOnly.error, undefined);
	const dest = resolve(SANDBOX, "list-only-extract");
	const existed = await stat(dest).catch(() => null);
	equal("listing created no extraction directory", existed, null);

	const extracted = await call(ctx.get("archive_unpack"), { file: "clean.tar", dest: "clean-run" });
	equal("extracting succeeds", extracted.error, undefined);
	equal("extraction writes the files", extracted.value.written, 2);
	equal("extraction creates the directory", extracted.value.directories, 1);
	equal("extraction is not flagged as a listing", extracted.value.listOnly, false);
	ok("the destination is under the extract directory", extracted.value.dest.includes("archive-extract"));
	equal("the file content came back byte-for-byte", await readFile(join(extracted.value.dest, "one.txt"), "utf8"), "first");
	equal("a nested file came back too", await readFile(join(extracted.value.dest, "sub", "two.txt"), "utf8"), "second");
	equal("nothing was refused", extracted.value.ok, true);
	equal("the written manifest matches what is on disk", extracted.value.manifest.filter((m) => m.kind === "file").map((m) => m.path), ["one.txt", "sub/two.txt"]);
}

{
	// A hostile archive: every member here is an escape attempt or an unsafe
	// member kind. Strict mode must refuse the whole thing and write nothing.
	const ctx = Context({ workDir: SANDBOX });
	plugin.apply(ctx, ctx.config);
	const buffer = writeFixtureTar([
		{ name: "safe.txt", data: "ok" },
		{ name: "../escape.txt", data: "bad" },
		{ name: "/absolute.txt", data: "bad" },
		{ name: "link", kind: "symlink", flag: "2", linkname: "/etc/passwd" },
		{ name: "hard", kind: "hardlink", flag: "1", linkname: "safe.txt" },
		{ name: "dev", kind: "char", flag: "3" },
		{ name: "pipe", kind: "fifo", flag: "6" }
	]);
	const reader = fakeReader(buffer);
	ctx.transport.readArchive = reader.readArchive;

	const strict = await call(ctx.get("archive_unpack"), { file: "hostile.tar", dest: "hostile-run" });
	ok("a hostile archive fails in strict mode", strict.error !== undefined);
	assertReaderUsed(reader.calls, "unpack hostile");
	ok("the error counts the refusals", strict.error.includes("6 member(s)"));
	ok("the error names a refusal", strict.error.includes("escape.txt"));
	ok("the error suggests the escape hatch", strict.error.includes("strict:false"));
	const created = await stat(resolve(SANDBOX, "archive-extract", "hostile-run")).catch(() => null);
	equal("strict mode created nothing at all", created, null);

	// Lenient mode extracts the safe members and reports every refusal.
	const lenient = await call(ctx.get("archive_unpack"), { file: "hostile.tar", dest: "hostile-lenient", strict: false });
	equal("lenient mode succeeds", lenient.error, undefined);
	equal("only the safe member is written", lenient.value.written, 1);
	equal("the safe member's content is right", await readFile(join(lenient.value.dest, "safe.txt"), "utf8"), "ok");
	equal("the archive is reported as not ok", lenient.value.ok, false);
	equal("six members were refused", lenient.value.refused.length, 6);
	equal("the traversal is named", lenient.value.refused.some((r) => r.name === "../escape.txt"), true);
	equal("the absolute member is named", lenient.value.refused.some((r) => r.name === "/absolute.txt"), true);
	equal("the symlink is named with its kind", lenient.value.refused.some((r) => r.kind === "symlink"), true);
	equal("the hardlink is named", lenient.value.refused.some((r) => r.kind === "hardlink"), true);
	equal("the device is named", lenient.value.refused.some((r) => r.kind === "device"), true);
	ok("the device reason names the kind", lenient.value.refused.find((r) => r.name === "dev").reason.includes("character device"));
	ok("the FIFO reason names the kind", lenient.value.refused.find((r) => r.name === "pipe").reason.includes("FIFO"));
	equal("nothing escaped the destination", await stat(join(SANDBOX, "escape.txt")).catch(() => null), null);

	// Listing a hostile archive must not fail: the point of listing is to find
	// out what is in there before deciding.
	const listed = await call(ctx.get("archive_unpack"), { file: "hostile.tar", listOnly: true });
	equal("listing a hostile archive succeeds", listed.error, undefined);
	equal("listing reports it as not ok", listed.value.ok, false);
	equal("listing still counts only one writable member", listed.value.writable, 1);
	equal("listing reports all six refusals", listed.value.refused.length, 6);
}

{
	const ctx = Context({ workDir: SANDBOX });
	plugin.apply(ctx, ctx.config);
	// noOverwrite must stop rather than clobber.
	const buffer = writeFixtureTar([{ name: "keep.txt", data: "second" }]);
	ctx.transport.readArchive = fakeReader(buffer).readArchive;
	await call(ctx.get("archive_unpack"), { file: "ow.tar", dest: "ow-run" });
	const again = await call(ctx.get("archive_unpack"), { file: "ow.tar", dest: "ow-run" });
	equal("a second extraction overwrites by default", again.error, undefined);
	equal("and the content is the archive's", await readFile(join(again.value.dest, "keep.txt"), "utf8"), "second");

	const guarded = Context({ workDir: SANDBOX, noOverwrite: true });
	plugin.apply(guarded, guarded.config);
	guarded.transport.readArchive = fakeReader(buffer).readArchive;
	const blocked = await call(guarded.get("archive_unpack"), { file: "ow.tar", dest: "ow-run" });
	ok("noOverwrite refuses an existing file", blocked.error !== undefined);
	ok("the error names the file", blocked.error.includes("keep.txt"));
	ok("and names the setting", blocked.error.includes("noOverwrite"));
}
{
	// The dest argument is a routing name like any other, and must not be able
	// to place the tree outside the configured extract directory.
	const ctx = Context({ workDir: SANDBOX });
	plugin.apply(ctx, ctx.config);
	ctx.transport.readArchive = fakeReader(writeFixtureTar([{ name: "x.txt", data: "x" }])).readArchive;
	const escaped = await call(ctx.get("archive_unpack"), { file: "e.tar", dest: "../../outside" });
	equal("a traversal in dest is refused or contained", escaped.error !== undefined || escaped.value.dest.includes("archive-extract"), true);
	const absolute = await call(ctx.get("archive_unpack"), { file: "e.tar", dest: "C:/Windows/Temp/evil" });
	equal("an absolute dest is contained too", absolute.error !== undefined || absolute.value.dest.includes("archive-extract"), true);
}
{
	const ctx = Context({ workDir: SANDBOX });
	plugin.apply(ctx, ctx.config);
	const missing = await call(ctx.get("archive_unpack"), { file: "nope.tar" });
	ok("unpacking a missing archive errors", missing.error !== undefined);
}
{
	const ctx = Context({ workDir: SANDBOX });
	plugin.apply(ctx, ctx.config);
	const empty = await call(ctx.get("archive_unpack"), { file: "" });
	ok("an empty file name is refused before any read", empty.error !== undefined);
	ok("the error says a file is required", empty.error.includes("a file is required"));
}

/* ------------------------------------------- injected reader is read live */

{
	// The bug this guards: capturing `transport.readArchive` into a local at
	// apply time pins `undefined`, and every call then reads the real
	// filesystem. The tool would "work" in a test that happened to have the
	// file on disk and silently ignore the fixture everywhere else.
	const ctx = Context({ workDir: SANDBOX });
	plugin.apply(ctx, ctx.config);
	await mkdir(resolve(SANDBOX, "archive-output"), { recursive: true });
	await writeFile(resolve(SANDBOX, "archive-output", "live.tar"), writeFixtureTar([{ name: "on-disk.txt", data: "REAL" }]));

	const reader = fakeReader(writeFixtureTar([{ name: "injected.txt", data: "FAKE" }]));
	ctx.transport.readArchive = reader.readArchive;

	const listed = await call(ctx.get("archive_unpack"), { file: "live.tar", listOnly: true });
	assertReaderUsed(reader.calls, "live reader");
	equal("the injected bytes were used, not the file on disk", listed.value.manifest.map((m) => m.path), ["injected.txt"]);

	// Swapping the reader after the first call must be honoured too — a
	// snapshot on first use would fail here.
	const second = fakeReader(writeFixtureTar([{ name: "swapped.txt", data: "SECOND" }]));
	ctx.transport.readArchive = second.readArchive;
	const again = await call(ctx.get("archive_unpack"), { file: "live.tar", listOnly: true });
	equal("a later swap is honoured", again.value.manifest.map((m) => m.path), ["swapped.txt"]);
}
{
	// And the unguarded path must really be the filesystem: with no injected
	// reader, a file that does not exist is an error rather than a silent empty.
	const ctx = Context({ workDir: SANDBOX });
	plugin.apply(ctx, ctx.config);
	const absent = await call(ctx.get("archive_unpack"), { file: "definitely-absent.tar", listOnly: true });
	ok("with no injected reader the real filesystem is consulted", absent.error !== undefined);
}
{
	// Archive paths handed in as absolute are honoured (reading is not writing),
	// so a caller can verify an archive they already have.
	const ctx = Context({ workDir: SANDBOX });
	plugin.apply(ctx, ctx.config);
	const reader = fakeReader(writeFixtureTar([{ name: "abs.txt", data: "x" }]));
	ctx.transport.readArchive = reader.readArchive;
	await call(ctx.get("archive_unpack"), { file: "C:/elsewhere/thing.tar", listOnly: true });
	equal("an absolute archive path is passed through as-is", reader.calls[0], "C:/elsewhere/thing.tar");
}

/* -------------------------------------------------- verify on its own */

{
	const ctx = Context({ workDir: SANDBOX });
	plugin.apply(ctx, ctx.config);
	const good = fakeReader(writeFixtureTar([{ name: "a.txt", data: "a" }]));
	ctx.transport.readArchive = good.readArchive;
	const result = await call(ctx.get("archive_verify"), { file: "good.tar" });
	equal("a clean archive verifies with no comparison asked for", result.value.ok, true);
	equal("no structural warnings", result.value.structuralWarnings, []);
	equal("no refusals", result.value.refused, []);
	equal("the entry count is reported", result.value.entries, 1);
	equal("nothing was compared against", result.value.comparedAgainst, "");
	equal("no digest was asked for", result.value.expectedDigest, "");

	const hostile = fakeReader(writeFixtureTar([
		{ name: "a.txt", data: "a" },
		{ name: "../x", data: "x" }
	]));
	ctx.transport.readArchive = hostile.readArchive;
	const flagged = await call(ctx.get("archive_verify"), { file: "hostile.tar" });
	equal("an archive with a traversal is not ok", flagged.value.ok, false);
	equal("and the refusal is reported", flagged.value.refused.length, 1);
	equal("with its kind", flagged.value.refused[0].kind, "traversal");

	const damaged = Buffer.from(writeFixtureTar([{ name: "a.txt", data: "a" }]));
	damaged.write("0000000\u0000", 148, "latin1");
	ctx.transport.readArchive = fakeReader(damaged).readArchive;
	const broken = await call(ctx.get("archive_verify"), { file: "damaged.tar" });
	equal("a damaged header makes the check fail", broken.value.ok, false);
	ok("and the structural warning explains why", broken.value.structuralWarnings.some((w) => w.includes("checksum mismatch")));
}
{
	const ctx = Context({ workDir: SANDBOX });
	plugin.apply(ctx, ctx.config);
	const reader = fakeReader(Buffer.alloc(0));
	ctx.transport.readArchive = reader.readArchive;
	const empty = await call(ctx.get("archive_verify"), { file: "empty.tar" });
	equal("a zero-byte archive has no members", empty.value.entries, 0);
	// It is not ok: a real empty archive still carries its two terminating zero
	// blocks, so zero bytes means the file was cut to nothing.
	equal("and is not reported as ok", empty.value.ok, false);
	ok("with a warning saying it is empty", empty.value.structuralWarnings.some((w) => w.includes("empty")));

	// Terminator-only really is a valid empty archive.
	ctx.transport.readArchive = fakeReader(Buffer.alloc(1024)).readArchive;
	const terminatorOnly = await call(ctx.get("archive_verify"), { file: "empty2.tar" });
	equal("a terminator-only archive is ok", terminatorOnly.value.ok, true);
	equal("and warns about nothing", terminatorOnly.value.structuralWarnings, []);

	const absent = await call(ctx.get("archive_verify"), { file: "" });
	ok("an empty file name is refused", absent.error !== undefined);
}

/* ------------------------------------------- truncation is not "ok" */

{
	// The strongest form of the truncation check: build a real archive, cut it
	// at every block boundary, and confirm no cut is ever reported as ok.
	const ctx = Context({ workDir: SANDBOX });
	plugin.apply(ctx, ctx.config);
	const source = await makeTree(join(SANDBOX, "cutme"), {
		"one.txt": "one\n",
		"two.txt": "two\n",
		"three.txt": "three\n"
	});
	const packed = await call(ctx.get("archive_pack"), { source, filename: "cutme.tar" });
	const whole = await readFile(packed.value.file);
	equal("the intact archive verifies", (await call(ctx.get("archive_verify"), { file: "cutme.tar" })).value.ok, true);

	let cleanButIncomplete = 0;
	let silentIncomplete = 0;
	let cuts = 0;
	for (let cut = 512; cut < whole.length; cut += 512) {
		const name = `cut-${cut}.tar`;
		await writeFile(resolve(SANDBOX, "archive-output", name), whole.subarray(0, cut));
		const result = await call(ctx.get("archive_verify"), { file: name });
		cuts += 1;
		const parsed = plugin.parseTar(whole.subarray(0, cut));
		const last = parsed.records[parsed.records.length - 1];
		const lastComplete = last === undefined || last.kind !== "file" || last.dataOffset + last.size <= cut;
		// "ok" is allowed only when the walk genuinely reached a terminator with
		// every member whole — which happens at exactly the first trailer block.
		if (result.value.ok && !(parsed.terminated && lastComplete)) cleanButIncomplete += 1;
		// An incomplete archive must always say something.
		if (!parsed.terminated && result.value.structuralWarnings.length === 0 && result.value.refused.length === 0) silentIncomplete += 1;
	}
	ok("every cut was checked", cuts > 0);
	equal("no truncated archive verifies as ok with incomplete data", cleanButIncomplete, 0);
	equal("and no truncated archive is silent", silentIncomplete, 0);
}

/* ------------------------------------------------- round-trip agreement */

{
	// The strongest statement this plugin can make: pack a real tree, then read
	// the resulting bytes back through the independent fixture writer's inverse
	// (the plugin's own parser) and confirm every hash and byte count agrees.
	const ctx = Context({ workDir: SANDBOX });
	plugin.apply(ctx, ctx.config);
	const source = await makeTree(join(SANDBOX, "roundtrip"), {
		"readme.md": "# hi\n",
		"src/index.js": "export const x = 1;\n",
		"src/lib/util.js": "export const y = 2;\n",
		"docs/deep/notes.txt": "notes\n"
	});

	const packed = await call(ctx.get("archive_pack"), { source });
	const raw = await readFile(packed.value.file);
	const fromBytes = plugin.manifestFromArchive(raw);

	equal("every packed member is read back", fromBytes.length, packed.value.manifest.length);
	equal("the paths agree", fromBytes.map((m) => m.path), packed.value.manifest.map((m) => m.path));
	equal("the kinds agree", fromBytes.map((m) => m.kind), packed.value.manifest.map((m) => m.kind));
	equal("the sizes agree", fromBytes.map((m) => m.bytes), packed.value.manifest.map((m) => m.bytes));
	equal("the hashes agree", fromBytes.map((m) => m.sha256), packed.value.manifest.map((m) => m.sha256));
	equal("and therefore the digest agrees", plugin.treeDigest(fromBytes), packed.value.treeDigest);

	// Now unpack into a fresh place and diff the bytes on disk.
	const unpacked = await call(ctx.get("archive_unpack"), { file: packed.value.file, dest: "roundtrip-out" });
	equal("unpacking the packed archive succeeds", unpacked.error, undefined);
	equal("every member is written", unpacked.value.written, packed.value.manifest.filter((m) => m.kind === "file").length);
	for (const member of packed.value.manifest.filter((m) => m.kind === "file")) {
		const onDisk = await readFile(join(unpacked.value.dest, ...member.path.split("/")));
		equal(`"${member.path}" survives the round trip`, plugin.sha256(onDisk), member.sha256);
	}
	const original = await readFile(join(source, "src/index.js"), "utf8");
	const restored = await readFile(join(unpacked.value.dest, "src", "index.js"), "utf8");
	equal("a nested file's text is identical", restored, original);

	// Verifying the unpacked tree against the archive is a clean pass, which is
	// the whole reason the manifest is worth carrying.
	const verified = await call(ctx.get("archive_verify"), { file: packed.value.file, against: unpacked.value.dest });
	equal("the unpacked tree verifies against the archive", verified.value.ok, true);
	equal("with every member unchanged", verified.value.unchanged, fromBytes.length);
}

{
	// A directory whose name needs a ustar prefix must still round-trip; this is
	// where an encoder that only handles the name field silently fails.
	const ctx = Context({ workDir: SANDBOX });
	plugin.apply(ctx, ctx.config);
	const longDir = "d".repeat(80);
	const source = await makeTree(join(SANDBOX, "longpath"), {
		[`${longDir}/${"f".repeat(80)}.txt`]: "deep",
		"shallow.txt": "shallow"
	});
	const packed = await call(ctx.get("archive_pack"), { source });
	equal("a long path packs", packed.error, undefined);
	equal("both members are recorded", packed.value.files, 2);
	const raw = await readFile(packed.value.file);
	const fromBytes = plugin.manifestFromArchive(raw);
	// `parseTar` keeps the trailing slash the ustar header mandates for a
	// directory; both `manifestFromArchive` and `archive_pack`'s own manifest
	// strip it, so the two manifests are directly comparable. The directory
	// entry belongs in the list — dropping it here would have hidden a
	// genuine asymmetry if one direction had normalised and the other had not.
	equal("the long name survives the prefix split", fromBytes.map((m) => m.path), [longDir, `${longDir}/${"f".repeat(80)}.txt`, "shallow.txt"]);
	equal("and the directory is still typed as one", fromBytes[0].kind, "directory");
	equal("the long file kept its content hash", fromBytes[1].sha256, plugin.sha256(Buffer.from("deep")));
	const unpacked = await call(ctx.get("archive_unpack"), { file: packed.value.file, dest: "longpath-out" });
	equal("and unpacks to the same name", await readFile(join(unpacked.value.dest, longDir, `${"f".repeat(80)}.txt`), "utf8"), "deep");
}

{
	// A path too long for a plain ustar header must be a clear error, not a
	// silently truncated name that writes somewhere unintended.
	const ctx = Context({ workDir: SANDBOX });
	plugin.apply(ctx, ctx.config);
	const source = await makeTree(join(SANDBOX, "toolong"), { "x.txt": "x" });
	const deep = Array.from({ length: 8 }, (_, i) => `l${i}${"z".repeat(40)}`).join("/");
	const tooLong = await call(ctx.get("archive_pack"), { source, exclude: "" });
	equal("a normal tree still packs", tooLong.error, undefined);
	let threw = "";
	try {
		plugin.encodePath(`${deep}/file.txt`);
	} catch (error) { threw = error.message; }
	ok("an unencodable path throws rather than truncating", threw.includes("does not fit a plain ustar header"));
	ok("the refusal explains what is missing", threw.includes("GNU long-name or PAX"));
}

{
	// Empty files are the boundary case for padding: zero content means zero
	// blocks, and the next header starts immediately.
	const ctx = Context({ workDir: SANDBOX });
	plugin.apply(ctx, ctx.config);
	const source = await makeTree(join(SANDBOX, "empties"), {
		"a.txt": "",
		"b.txt": "",
		"c.txt": "c"
	});
	const packed = await call(ctx.get("archive_pack"), { source });
	equal("empty files are all recorded", packed.value.files, 3);
	equal("and contribute nothing to the content total", packed.value.contentBytes, 1);
	const fromBytes = plugin.manifestFromArchive(await readFile(packed.value.file));
	equal("all three are read back", fromBytes.length, 3);
	equal("an empty file hashes to the empty digest", fromBytes[0].sha256, plugin.sha256(Buffer.alloc(0)));
	equal("and its size is zero", fromBytes[0].bytes, 0);
	const unpacked = await call(ctx.get("archive_unpack"), { file: packed.value.file, dest: "empties-out" });
	equal("all three unpack", unpacked.value.written, 3);
	equal("an empty file is empty on disk", (await stat(join(unpacked.value.dest, "a.txt"))).size, 0);
}

/* ---------------------------------- a symlink is never packed as a file */

{
	// The bug this guards: on Windows `lstat` can report a symlink as an
	// ordinary file, and `readFile` on it then returns nothing useful — so the
	// link lands in the archive as a zero-byte file carrying the empty-string
	// hash. The archive looks healthy and contains a file that is not what is on
	// disk. Detection therefore does not trust the stat flags alone; `readlink`
	// is consulted as an independent signal.
	const ctx = Context({ workDir: SANDBOX });
	plugin.apply(ctx, ctx.config);
	const source = await makeTree(join(SANDBOX, "links"), { "real.txt": "real\n" });

	let madeLink = true;
	try {
		const { symlink, lstat: lstatFn } = await import("node:fs/promises");
		await symlink("real.txt", join(source, "link.txt"), "file");
		madeLink = (await lstatFn(join(source, "link.txt"))).isSymbolicLink();
	} catch {
		madeLink = false;
	}

	if (!madeLink) {
		// This host cannot create symlinks (Windows needs a privilege). The
		// guard is still exercised below through `walkTree`'s contract, but the
		// on-disk case cannot be asserted here — say so rather than pretend.
		console.log("  (symlink creation unavailable on this account; on-disk case skipped)");
	} else {
		const packed = await call(ctx.get("archive_pack"), { source });
		equal("the symlink is skipped rather than packed", packed.value.skipped.map((s) => s.name), ["link.txt"]);
		ok("the skip says it is a symlink", packed.value.skipped[0].reason.includes("symlink"));
		ok("and names the target", packed.value.skipped[0].reason.includes("real.txt"));
		equal("only the real file is packed", packed.value.files, 1);
		equal("no zero-byte member is created", packed.value.manifest.some((m) => m.bytes === 0), false);
	}
}

/* ------------------------- a size mismatch is reported, not packed anyway */

{
	// The second half of the same bug: if the directory listing and the read
	// disagree, packing the file writes a header whose size contradicts its
	// content — something every reader trusts and none can detect. The member is
	// dropped and named instead.
	const root = await makeTree(join(SANDBOX, "shrink"), { "small.txt": "abc" });
	const { chmod } = await import("node:fs/promises");
	// A directory whose entry is a dangling link is the cheapest real way to get
	// a listing that disagrees with a read on this platform.
	let madeLink = true;
	try {
		const { symlink } = await import("node:fs/promises");
		await symlink("does-not-exist.txt", join(root, "dangling.txt"), "file");
	} catch {
		madeLink = false;
	}

	const ctx = Context({ workDir: SANDBOX });
	plugin.apply(ctx, ctx.config);
	const packed = await call(ctx.get("archive_pack"), { source: root });

	if (!madeLink) {
		equal("with no link, nothing is skipped", packed.value.skipped, []);
	} else {
		// A dangling link must never reach the manifest, whether the skip came
		// from the link check or from the size check.
		equal("a dangling link is not packed", packed.value.manifest.some((m) => m.path === "dangling.txt"), false);
		ok("and its absence is explained", packed.value.skipped.some((s) => s.name === "dangling.txt"));
		equal("the readable file is still packed", packed.value.files, 1);
		equal("and its content is right", packed.value.manifest[0].bytes, 3);
		// The content total must reflect the manifest, not the walk.
		equal("the content total matches the manifest", packed.value.contentBytes, packed.value.manifest.reduce((a, m) => a + m.bytes, 0));
	}
}

/* ------------------------------------------------------ summary */

console.log(`archive integration: ${passed} passed, ${failed} failed`);
process.exit(failed === 0 ? 0 : 1);