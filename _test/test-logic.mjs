// White-box tests for the pure functions behind dsh-tool-archive.
//
// These are where correctness is not obvious from a passing tool call: the
// octal field encoder, the ustar name/prefix split, the checksum, the
// 512-byte block walk, and above all the path guard that decides whether an
// archive member is allowed to reach the filesystem. Testing the guard through
// a tool call would mean writing a hostile archive to disk to find out whether
// it was refused; here the verdict is a return value.
import { plugin, writeFixtureTar } from "./harness.mjs";
import { resolve } from "node:path";

let passed = 0;
let failed = 0;

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

console.log("archive: logic");

/* ------------------------------------------------------------ octalField */

equal("octal of 0 fills with zeros", plugin.octalField(0, 8).toString("latin1"), "0000000\u0000");
equal("octal of 8 is 10", plugin.octalField(8, 8).toString("latin1"), "0000010\u0000");
equal("octal of 511 is 777", plugin.octalField(511, 8).toString("latin1"), "0000777\u0000");
equal("an 11-byte size field holds 2^33-1", plugin.octalField(8589934591, 12).toString("latin1"), "77777777777\u0000");
{
	let threw = "";
	try { plugin.octalField(8 ** 11, 12); } catch (error) { threw = error.message; }
	ok("an overflowing value throws instead of truncating", threw.includes("does not fit"));
	ok("the overflow message names the width", threw.includes("12-byte"));
}
{
	// The failure that matters: a truncating encoder would write 77777777777
	// for a value that does not fit, producing an archive that reads back as a
	// *smaller* file with no error anywhere.
	let threw = false;
	try { plugin.octalField(8589934592, 12); } catch { threw = true; }
	ok("exactly one above the field maximum throws, not wraps", threw);
}

/* ------------------------------------------------------------- padField */

equal("padField fills the rest with NUL", plugin.padField(Buffer.from("ab"), 6, "x").toString("latin1"), "ab\u0000\u0000\u0000\u0000");
equal("padField of a full field is the field", plugin.padField(Buffer.from("abcd"), 4, "x").toString("latin1"), "abcd");
{
	let threw = "";
	try { plugin.padField(Buffer.from("abcdef"), 4, "too-long"); } catch (error) { threw = error.message; }
	ok("padField throws rather than cutting mid-value", threw.includes("needs 6 bytes"));
	ok("the message names the offending value", threw.includes("too-long"));
}

/* ------------------------------------------------------------ encodePath */

{
	const short = plugin.encodePath("readme.md");
	equal("a short name goes in the name field", short.name.toString("utf8").replace(/\u0000+$/u, ""), "readme.md");
	equal("and the prefix field stays empty", short.prefix.toString("utf8").replace(/\u0000+$/u, ""), "");
}
{
	const long = plugin.encodePath(`${"d".repeat(80)}/${"f".repeat(80)}.txt`);
	equal("a long path splits at the slash", long.name.toString("utf8").replace(/\u0000+$/u, ""), `${"f".repeat(80)}.txt`);
	equal("and the head becomes the prefix", long.prefix.toString("utf8").replace(/\u0000+$/u, ""), "d".repeat(80));
}
{
	// A 100-byte name fits with no prefix at all; 101 does not. The boundary is
	// where a hand-written encoder goes wrong by one.
	equal("a 100-byte name needs no prefix", plugin.encodePath("a".repeat(100)).prefix.toString("utf8").replace(/\u0000+$/u, ""), "");
	let threw = "";
	try { plugin.encodePath("a".repeat(300)); } catch (error) { threw = error.message; }
	ok("an unsplittable 300-byte path throws", threw.includes("does not fit a plain ustar header"));
	ok("the refusal names the extension it will not emit", threw.includes("GNU long-name or PAX"));
}
{
	// Longest-prefix-first matters. Here the head (`a...a/b...b`, 171 bytes)
	// exceeds the 155-byte prefix field but the *shorter* head does not, so
	// cutting at the first slash and giving up would reject an encodable path.
	const three = plugin.encodePath(`${"a".repeat(120)}/${"b".repeat(30)}/${"c".repeat(40)}.txt`);
	equal("a three-part path falls back to a shorter prefix that fits", three.prefix.toString("utf8").replace(/\u0000+$/u, "").length, 120);
	equal("and puts the tail in the name field", three.name.toString("utf8").replace(/\u0000+$/u, "").length, 75);
	const tail = three.name.toString("utf8").replace(/\u0000+$/u, "");
	equal("the tail keeps every remaining component", tail.endsWith(`/${"c".repeat(40)}.txt`), true);
}

/* ------------------------------------------------------------ tarHeader */

{
	const header = plugin.tarHeader({ name: "hello.txt", kind: "file", size: 12, mtimeMs: 1600000000000 });
	equal("a header is exactly one block", header.length, 512);
	equal("the type flag for a file is 0", header.subarray(156, 157).toString("latin1"), "0");
	equal("the magic is ustar plus a NUL", header.subarray(257, 263).toString("latin1"), "ustar\u0000");
	equal("the version is 00", header.subarray(263, 265).toString("latin1"), "00");
	equal("the size goes in the size field", plugin.readOctal(header, 124, 12), 12);
	equal("the mtime is truncated to seconds", plugin.readOctal(header, 136, 12), 1600000000);
	equal("the mode is the pinned file mode", plugin.readOctal(header, 100, 8), 0o644);
	equal("the uid is pinned to 0", plugin.readOctal(header, 108, 8), 0);
	equal("the gid is pinned to 0", plugin.readOctal(header, 116, 8), 0);
	const sums = plugin.checkChecksum(header);
	ok("the checksum verifies", sums.ok);
	equal("the stored checksum is six octal digits plus NUL and space", header.subarray(148, 156).toString("latin1").slice(6), "\u0000 ");
}
{
	const dir = plugin.tarHeader({ name: "sub", kind: "directory", size: 0, mtimeMs: 0 });
	equal("a directory gets the 5 flag", dir.subarray(156, 157).toString("latin1"), "5");
	equal("a directory name carries a trailing slash", plugin.readString(dir, 0, 100), "sub/");
	equal("a directory records size 0 even if given one", plugin.readOctal(dir, 124, 12), 0);
	equal("a directory gets the pinned directory mode", plugin.readOctal(dir, 100, 8), 0o755);
}
{
	// The magic and version are separate fields in the standard. Writing the
	// eight bytes as one string works by accident and breaks strict readers,
	// so the byte layout is pinned here rather than only the decoded string.
	const header = plugin.tarHeader({ name: "x", kind: "file", size: 0, mtimeMs: 0 });
	equal("byte 262 is the NUL that ends the magic", header[262], 0);
	equal("byte 263 is the first version digit", header[263], 0x30);
	equal("byte 264 is the second version digit", header[264], 0x30);
}

/* --------------------------------------------------------- readOctal/readString */

{
	const block = Buffer.alloc(512);
	block.write("0000012\u0000", 100, "latin1");
	equal("readOctal handles a NUL terminator", plugin.readOctal(block, 100, 8), 10);
	block.write("0000012 ", 100, "latin1");
	equal("readOctal handles a trailing space", plugin.readOctal(block, 100, 8), 10);
	block.write("        ", 100, "latin1");
	equal("an all-space field reads as zero", plugin.readOctal(block, 100, 8), 0);
	block.fill(0, 100, 108);
	equal("an all-NUL field reads as zero", plugin.readOctal(block, 100, 8), 0);
	block.write("0000099\u0000", 100, "latin1");
	ok("a non-octal field reads as NaN rather than as a wrong number", Number.isNaN(plugin.readOctal(block, 100, 8)));
}
{
	const named = Buffer.alloc(512);
	named.write("name\u0000junk", 0, "latin1");
	equal("readString stops at the NUL", plugin.readString(named, 0, 100), "name");
	equal("readString of an empty field is empty", plugin.readString(Buffer.alloc(512), 0, 100), "");

	// The field is decoded as UTF-8, not latin1: a member named in Chinese or
	// with an accent must survive, and a latin1 decode would produce replacement
	// characters that then fail the "does this name stay inside" comparison.
	// Each case gets a fresh block — copying over a previous value would leave
	// its tail behind and the assertion would pass or fail for the wrong reason.
	const accented = Buffer.alloc(512);
	Buffer.from("héllo", "utf8").copy(accented, 0);
	equal("readString decodes UTF-8", plugin.readString(accented, 0, 100), "héllo");

	const cjk = Buffer.alloc(512);
	Buffer.from("文档.tar", "utf8").copy(cjk, 0);
	equal("readString decodes multi-byte CJK", plugin.readString(cjk, 0, 100), "文档.tar");

	// The NUL is found by byte offset, not by character index, so a multi-byte
	// value followed by padding truncates at the right place.
	const single = Buffer.alloc(512);
	Buffer.from("é", "utf8").copy(single, 0);
	equal("readString stops right after a multi-byte value", plugin.readString(single, 0, 100), "é");

	// A four-byte emoji plus a NUL: the byte search must not split a surrogate
	// pair, which a character-index search would.
	const emoji = Buffer.alloc(512);
	Buffer.from("🚀x\u0000y", "utf8").copy(emoji, 0);
	equal("readString handles a four-byte code point", plugin.readString(emoji, 0, 100), "🚀x");
}

/* -------------------------------------------------------- checkChecksum */

{
	const header = plugin.tarHeader({ name: "a", kind: "file", size: 0, mtimeMs: 0 });
	ok("a fresh header checksums", plugin.checkChecksum(header).ok);
	const damaged = Buffer.from(header);
	damaged[0] = 0x62;
	const sums = plugin.checkChecksum(damaged);
	equal("a damaged header does not checksum", sums.ok, false);
	ok("the mismatch reports both values", Number.isFinite(sums.stored) && Number.isFinite(sums.computed));
}

/* ------------------------------------------------------------ isZeroBlock */

ok("an all-zero block is the terminator", plugin.isZeroBlock(Buffer.alloc(512)));
ok("a block with one non-zero byte is not", !plugin.isZeroBlock(Buffer.concat([Buffer.alloc(511), Buffer.from([1])])));

/* -------------------------------------------------------------- toPosix */

equal("backslashes become slashes", plugin.toPosix("a\\b\\c"), "a/b/c");
equal("forward slashes are left alone", plugin.toPosix("a/b"), "a/b");
equal("a mixed path is normalised", plugin.toPosix("a\\b/c"), "a/b/c");

/* ---------------------------------------------------------- resolveWithin */

{
	const dir = resolve("C:/base/out");
	equal("a plain name lands in the directory", plugin.resolveWithin(dir, "a.tar"), resolve(dir, "a.tar"));
	equal("a relative subpath keeps only the last segment", plugin.resolveWithin(dir, "x/y/a.tar"), resolve(dir, "a.tar"));
	// The whole point: an absolute *second* argument to path.resolve wins, so a
	// name that arrives from an archive must lose its routing before resolve.
	equal("a Windows absolute path is stripped to its tail", plugin.resolveWithin(dir, "C:/Windows/system32/evil.tar"), resolve(dir, "evil.tar"));
	equal("a Unix absolute path is stripped", plugin.resolveWithin(dir, "/etc/passwd"), resolve(dir, "passwd"));
	equal("a traversal is stripped", plugin.resolveWithin(dir, "../../escape.tar"), resolve(dir, "escape.tar"));
	equal("a backslashed traversal is stripped", plugin.resolveWithin(dir, "..\\..\\escape.tar"), resolve(dir, "escape.tar"));
	equal("an empty name falls back to the directory itself", plugin.resolveWithin(dir, ""), dir);
	equal("a dots-only name falls back to the directory", plugin.resolveWithin(dir, ".."), dir);
	const sanitised = plugin.resolveWithin(dir, 'a<b>c|d?e*f"g.tar');
	equal("characters illegal on Windows are replaced", sanitised, resolve(dir, "a_b_c_d_e_f_g.tar"));
	const named = plugin.resolveWithin(dir, "a\u0000b.tar");
	ok("a NUL byte does not survive into the result", !named.includes("\u0000"));
}
{
	// Every one of these is an attempt to leave the directory. None may succeed.
	const dir = resolve("C:/base/out");
	const attempts = [
		"C:/Windows/system32/evil",
		"/etc/shadow",
		"\\\\server\\share\\evil",
		"../../../../../../evil",
		"a/../../evil",
		"....//....//evil",
		"./././evil"
	];
	let allInside = true;
	for (const attempt of attempts) {
		const result = plugin.resolveWithin(dir, attempt);
		if (!result.startsWith(resolve(dir) + "\\") && result !== resolve(dir)) allInside = false;
	}
	ok("no escape attempt produces a path outside the directory", allInside);
}

/* ---------------------------------------------------------- resolveEntry */

{
	const root = resolve("C:/base/extract");
	equal("a plain member is inside", plugin.resolveEntry(root, "a.txt").ok, true);
	equal("a nested member is inside", plugin.resolveEntry(root, "a/b/c.txt").ok, true);
	equal("a leading ./ is accepted", plugin.resolveEntry(root, "./a.txt").ok, true);
	equal("a trailing slash is accepted", plugin.resolveEntry(root, "dir/").ok, true);

	equal("an absolute member is refused", plugin.resolveEntry(root, "/etc/passwd").kind, "absolute");
	equal("a drive-letter member is refused", plugin.resolveEntry(root, "C:/Windows/x").kind, "absolute");
	equal("a UNC member is refused", plugin.resolveEntry(root, "\\\\srv\\share").kind, "absolute");
	equal("a .. member is refused", plugin.resolveEntry(root, "../x").kind, "traversal");
	equal("a buried .. member is refused", plugin.resolveEntry(root, "a/../../x").kind, "traversal");
	equal(".. that stays inside is still refused", plugin.resolveEntry(root, "a/../b").kind, "traversal");
	equal("an empty name is refused", plugin.resolveEntry(root, "").kind, "empty");
	equal("a NUL in the name is refused", plugin.resolveEntry(root, "a\u0000b").kind, "nul");
	equal("a doubled slash is refused", plugin.resolveEntry(root, "a//b").kind, "empty-component");
	equal("an absolute member gets a reason naming the name", plugin.resolveEntry(root, "/etc/passwd").reason.includes("/etc/passwd"), true);
}
{
	// The kind that matters most: a name that looks relative but resolves
	// absolutely. `\\.\` and a bare drive-relative name are both refused.
	const root = resolve("C:/base/extract");
	equal("a drive-relative name is refused", plugin.resolveEntry(root, "C:x").ok, false);
	equal("a forward-slash absolute is refused", plugin.resolveEntry(root, "/x/y").ok, false);
	// "." is the extraction root itself. A `.` component is filtered out during
	// normalisation (the same way `./a.txt` is accepted), so a *bare* "." leaves
	// nothing behind and lands on the root. Refusing it is the safe call: writing
	// "the root" as a member means re-creating the destination.
	equal("a bare dot is refused", plugin.resolveEntry(root, ".").kind, "empty");
	equal("a bare dot is refused with a reason", plugin.resolveEntry(root, ".").reason.includes("extraction root"), true);
	equal("a bare ./ is refused too", plugin.resolveEntry(root, "./").kind, "empty");
	equal("a bare ././. is refused too", plugin.resolveEntry(root, "././.").kind, "empty");
	// A name that only *looks* like it escapes: "a..b" contains no ".."
	// component, so it must be allowed through.
	equal("a name containing dots but no .. component is allowed", plugin.resolveEntry(root, "a..b.txt").ok, true);
	equal("a dotfile is allowed", plugin.resolveEntry(root, ".hidden").ok, true);
}

/* ------------------------------------------------------------ parseTar */

{
	const buffer = writeFixtureTar([
		{ name: "a.txt", data: "hello" },
		{ name: "dir", kind: "directory" },
		{ name: "dir/b.txt", data: "world!" }
	]);
	const parsed = plugin.parseTar(buffer);
	equal("every header becomes a record", parsed.records.length, 3);
	equal("every content member becomes an entry", parsed.entries.length, 3);
	equal("no warnings for a clean archive", parsed.warnings, []);
	equal("the first name is read", parsed.records[0].name, "a.txt");
	equal("the first kind is file", parsed.records[0].kind, "file");
	equal("the first size is read", parsed.records[0].size, 5);
	equal("the directory kind is read", parsed.records[1].kind, "directory");
	equal("a directory name keeps its trailing slash", parsed.records[1].name, "dir/");
	equal("the second file's size is read", parsed.records[2].size, 6);
	equal("every checksum passes", parsed.records.every((r) => r.checksumOk), true);
	equal("the content hash is the hash of the content", parsed.records[0].sha256, plugin.sha256(Buffer.from("hello")));
	equal("the second file's hash is over its own bytes", parsed.records[2].sha256, plugin.sha256(Buffer.from("world!")));
	equal("nothing trails the terminator", parsed.trailingBytes, 0);
}
{
	// Padding is the classic walk bug: the second entry is only found if the
	// first member's data is rounded up to a block boundary.
	const buffer = writeFixtureTar([
		{ name: "one", data: "x" },
		{ name: "two", data: "y" }
	]);
	const parsed = plugin.parseTar(buffer);
	equal("a one-byte member is still followed by the next", parsed.records.map((r) => r.name), ["one", "two"]);
	equal("both are found despite padding", parsed.records.length, 2);
	equal("an exact-block member is handled too", plugin.parseTar(writeFixtureTar([
		{ name: "a", data: "z".repeat(512) },
		{ name: "b", data: "q" }
	])).records.map((r) => r.name), ["a", "b"]);
}
{
	const buffer = writeFixtureTar([{ name: "bad.txt", data: "hi", corrupt_size: true }]);
	// Rewrite the checksum field so it cannot match: a damaged header must stop
	// the walk rather than have its size trusted.
	const damaged = Buffer.from(buffer);
	damaged.write("0000000\u0000", 148, "latin1");
	const parsed = plugin.parseTar(damaged);
	equal("a bad checksum stops the walk", parsed.records.length, 1);
	equal("the record reports the failure", parsed.records[0].checksumOk, false);
	ok("a warning explains the stop", parsed.warnings.some((w) => w.includes("checksum mismatch")));
	ok("the warning says later offsets would be guesses", parsed.warnings.some((w) => w.includes("guess")));
}
{
	const parsed = plugin.parseTar(writeFixtureTar([{ name: "x", data: "y" }]));
	equal("a finished archive reports no trailing bytes", parsed.trailingBytes, 0);
	// The walk stops at the first all-zero block, so the terminator itself and
	// any padding after it are *not* consumed as content and are not counted as
	// trailing either — they are the expected end, not a surprise. Only bytes
	// that are neither a header nor zero-fill would show up here.
	const padded = Buffer.concat([writeFixtureTar([{ name: "x", data: "y" }]), Buffer.alloc(2048)]);
	equal("zero-fill after the terminator is not counted as trailing", plugin.parseTar(padded).trailingBytes, 0);
	equal("nor is it mistaken for content", plugin.parseTar(padded).records.length, 1);
	const withJunk = Buffer.concat([writeFixtureTar([{ name: "x", data: "y" }]), Buffer.from("\u0001".repeat(16))]);
	equal("bytes that are neither a header nor zero-fill are reported", plugin.parseTar(withJunk).trailingBytes, 16);
}
{
	// An empty buffer is a truncated archive, not a valid empty one: a real
	// empty archive still carries its two terminating zero blocks, so "zero
	// bytes" means "something cut the file to nothing". Reporting that as a
	// clean parse would be the same failure as reporting a half-file as clean.
	const parsed = plugin.parseTar(Buffer.alloc(0));
	equal("an empty buffer parses to no members", parsed.records.length, 0);
	equal("and is not treated as terminated", parsed.terminated, false);
	equal("and warns that it is empty", parsed.warnings.length, 1);
	ok("the warning explains the emptiness", parsed.warnings[0].includes("empty"));

	// A buffer holding only the terminator is a legitimately empty archive.
	const onlyTerminator = plugin.parseTar(Buffer.alloc(1024));
	equal("terminator-only parses to no members", onlyTerminator.records.length, 0);
	equal("and counts as terminated", onlyTerminator.terminated, true);
	equal("and produces no warnings", onlyTerminator.warnings.length, 0);
}
{
	// A truncated member must be reported, not silently materialised as a
	// shorter file — that is how a corrupted download becomes a corrupt tree.
	const whole = writeFixtureTar([{ name: "big.txt", data: "z".repeat(2048) }]);
	const cut = whole.subarray(0, 512 + 100);
	const parsed = plugin.parseTar(cut);
	ok("a truncated member warns", parsed.warnings.some((w) => w.includes("truncated") || w.includes("only")));
}
{
	const parsed = plugin.parseTar(writeFixtureTar([
		{ name: "up.txt", data: "hi", prefix: "deep/nested" }
	]));
	equal("a prefix is joined to the name", parsed.records[0].name, "deep/nested/up.txt");
}
{
	const parsed = plugin.parseTar(writeFixtureTar([
		{ name: "up.txt", data: "hi", prefix: "deep", corruptMagic: true }
	]));
	ok("a non-ustar magic warns rather than throwing", parsed.warnings.some((w) => w.includes("magic")));
	equal("the offsets are still read tar-style", parsed.records[0].name, "deep/up.txt");
}
{
	const parsed = plugin.parseTar(writeFixtureTar([
		{ name: "link", kind: "symlink", flag: "2", linkname: "/etc/passwd" }
	]));
	equal("a symlink header is recognised", parsed.records[0].kind, "symlink");
	equal("its target is read", parsed.records[0].linkname, "/etc/passwd");
}
{
	const parsed = plugin.parseTar(writeFixtureTar([
		{ name: "weird", kind: "other", flag: "Z", data: "" }
	]));
	equal("an unknown type flag becomes unknown", parsed.records[0].kind, "unknown");
}

/* ----------------------------------------------------------- paddedLength */

equal("an empty member occupies no payload blocks", plugin.paddedLength(0), 0);
equal("one byte occupies a whole block", plugin.paddedLength(1), 512);
equal("exactly one block stays one block", plugin.paddedLength(512), 512);
equal("one byte over rolls to two", plugin.paddedLength(513), 1024);

/* --------------------------------------------------------- truncation */

{
	// The bug this guards: at every cut short of the terminating zero blocks the
	// members that *were* read all checksum fine, so the loop exits quietly and
	// a caller is told the archive is intact. Half a file reading as "ok" is
	// worse than an error, because nothing prompts anyone to look.
	const whole = writeFixtureTar([
		{ name: "one.txt", data: "one\n" },
		{ name: "two.txt", data: "two\n" }
	]);
	equal("the intact archive is terminated", plugin.parseTar(whole).terminated, true);
	equal("and warns about nothing", plugin.parseTar(whole).warnings, []);

	// Cut at every block boundary up to the trailer. No cut may read as a clean,
	// complete archive. One boundary *is* legitimately terminating: the first of
	// the trailer's two zero blocks is itself a valid end marker (GNU tar
	// accepts a single zero block), so cutting there yields a correct archive of
	// the members read so far. What must never happen is a cut whose members are
	// all valid *and* whose data is incomplete — that is the silent half-file.
	let cleanButIncomplete = 0;
	let silentIncomplete = 0;
	let legitimatelyTerminated = 0;
	let cuts = 0;
	for (let cut = 512; cut < whole.length; cut += 512) {
		cuts += 1;
		const parsed = plugin.parseTar(whole.subarray(0, cut));
		const last = parsed.records[parsed.records.length - 1];
		const lastComplete = last === undefined || last.kind !== "file" || last.dataOffset + last.size <= cut;
		if (parsed.terminated) {
			legitimatelyTerminated += 1;
			// A terminated parse must have every member whole.
			if (!lastComplete) cleanButIncomplete += 1;
			continue;
		}
		if (parsed.warnings.length === 0) silentIncomplete += 1;
	}
	ok("every block boundary was checked", cuts > 0);
	equal("no terminated cut has a member whose data is incomplete", cleanButIncomplete, 0);
	equal("no unterminated cut is silent about it", silentIncomplete, 0);
	// Exactly one boundary (the first trailer block) is a valid end.
	equal("only the trailer boundary terminates successfully", legitimatelyTerminated, 1);

	// The exact boundary that used to slip through: one full header plus a
	// fraction of a block, with the first member's data intact.
	const partial = plugin.parseTar(whole.subarray(0, 1027));
	equal("a header plus a broken block warns", partial.warnings.length > 0, true);
	equal("and is not terminated", partial.terminated, false);
	ok("the warning says the archive is truncated", partial.warnings.some((w) => w.includes("truncated")));
	ok("and says how many members were read", partial.warnings.some((w) => w.includes("1 member")));
	ok("and notes the leftover is not a whole block", partial.warnings.some((w) => w.includes("512-byte block")));

	// Terminator present but a member's data cut short: a different message,
	// because the cause is different.
	const midData = plugin.parseTar(whole.subarray(0, 1024));
	equal("a cut mid-data is not terminated", midData.terminated, false);
	equal("and is flagged", midData.warnings.length > 0, true);
}

/* ------------------------------------------------------------ treeDigest */

{
	const a = [
		{ path: "a.txt", kind: "file", bytes: 1, sha256: "aa" },
		{ path: "b.txt", kind: "file", bytes: 2, sha256: "bb" }
	];
	const b = [
		{ path: "a.txt", kind: "file", bytes: 1, sha256: "aa" },
		{ path: "b.txt", kind: "file", bytes: 2, sha256: "bb" }
	];
	equal("identical manifests digest the same", plugin.treeDigest(a), plugin.treeDigest(b));
	const c = [b[1], b[0]];
	equal("order is part of the input, so a reordered manifest differs", plugin.treeDigest(a) === plugin.treeDigest(c), false);
	equal("but a *sorted* reordering matches", plugin.treeDigest(a), plugin.treeDigest([...c].sort((x, y) => (x.path < y.path ? -1 : 1))));
	equal("a content change changes the digest", plugin.treeDigest(a) === plugin.treeDigest([a[0], { ...a[1], sha256: "cc" }]), false);
	equal("a size change changes the digest", plugin.treeDigest(a) === plugin.treeDigest([a[0], { ...a[1], bytes: 3 }]), false);
	equal("a path change changes the digest", plugin.treeDigest(a) === plugin.treeDigest([a[0], { ...a[1], path: "c" }]), false);
	equal("a kind change changes the digest", plugin.treeDigest(a) === plugin.treeDigest([a[0], { ...a[1], kind: "directory" }]), false);
	equal("an empty tree has a stable digest", plugin.treeDigest([]), plugin.treeDigest([]));
	ok("the digest is a hex sha256", /^[0-9a-f]{64}$/u.test(plugin.treeDigest(a)));
	// A directory carries no content hash, so a manifest whose *only* difference
	// is a mode must not move the digest — that is what makes it comparable
	// between machines.
	equal("mode is not part of the digest", plugin.treeDigest([{ path: "d", kind: "directory", bytes: 0, sha256: "", mode: 0o755 }]), plugin.treeDigest([{ path: "d", kind: "directory", bytes: 0, sha256: "", mode: 0o700 }]));
}

/* ---------------------------------------------------------- diffManifests */

{
	const expected = [
		{ path: "a.txt", kind: "file", bytes: 1, sha256: "aa" },
		{ path: "b.txt", kind: "file", bytes: 2, sha256: "bb" }
	];
	const same = plugin.diffManifests(expected, expected);
	equal("identical manifests agree", same.ok, true);
	equal("and count every member as unchanged", same.unchanged, 2);

	const added = plugin.diffManifests(expected, [...expected, { path: "c.txt", kind: "file", bytes: 3, sha256: "cc" }]);
	equal("an extra member is reported as added", added.added.map((m) => m.path), ["c.txt"]);
	equal("an added member fails the comparison", added.ok, false);
	equal("nothing is reported as removed", added.removed.length, 0);

	const removed = plugin.diffManifests(expected, [expected[0]]);
	equal("a missing member is reported as removed", removed.removed.map((m) => m.path), ["b.txt"]);
	equal("a removed member fails the comparison", removed.ok, false);

	const changed = plugin.diffManifests(expected, [expected[0], { ...expected[1], sha256: "zz" }]);
	equal("a content change is reported", changed.changed.length, 1);
	equal("and names the path, not the index", changed.changed[0].path, "b.txt");
	equal("and names the field", changed.changed[0].field, "sha256");
	equal("and reports both hashes", [changed.changed[0].expected, changed.changed[0].actual], ["bb", "zz"]);

	const resized = plugin.diffManifests(expected, [expected[0], { ...expected[1], bytes: 9 }]);
	equal("a size change is reported on the size field", resized.changed[0].field, "bytes");
	const rekinded = plugin.diffManifests(expected, [expected[0], { ...expected[1], kind: "directory" }]);
	equal("a kind change is reported on the kind field", rekinded.changed[0].field, "kind");

	// Ordering must not matter: a directory walk and an archive walk disagree
	// about order routinely, and reporting that as a difference would make the
	// comparison useless.
	const shuffled = plugin.diffManifests(expected, [...expected].reverse());
	equal("reordering is not a difference", shuffled.ok, true);
	equal("and is still fully counted", shuffled.unchanged, 2);
}
{
	// A digest-less manifest (packing with hash:false) must not be reported as
	// changed on every member just because its hashes are empty strings.
	const expected = [{ path: "a.txt", kind: "file", bytes: 1, sha256: "" }];
	const actual = [{ path: "a.txt", kind: "file", bytes: 1, sha256: "aa" }];
	equal("an unpinned hash does not fabricate a difference", plugin.diffManifests(expected, actual).ok, true);
}

/* ------------------------------------------------------ manifestFromArchive */

{
	const buffer = writeFixtureTar([
		{ name: "a.txt", data: "hello" },
		{ name: "dir", kind: "directory" },
		{ name: "dir/b.txt", data: "world!" }
	]);
	const manifest = plugin.manifestFromArchive(buffer);
	equal("every content member appears", manifest.length, 3);
	equal("the manifest is sorted by path", manifest.map((m) => m.path), ["a.txt", "dir", "dir/b.txt"]);
	equal("a directory's trailing slash is not part of the path", manifest[1].path, "dir");
	equal("a file hash is its content hash", manifest[0].sha256, plugin.sha256(Buffer.from("hello")));
	equal("a directory has no hash", manifest[1].sha256, "");
}
{
	// A symlink is not a content member: it has no bytes, so including it in a
	// content manifest would invent a zero-byte file that is not there.
	const buffer = writeFixtureTar([{ name: "l", kind: "symlink", flag: "2", linkname: "/x" }]);
	equal("links are excluded from the content manifest", plugin.manifestFromArchive(buffer).length, 0);
}

/* ------------------------------------------------------- planExtraction */

{
	const root = resolve("C:/base/extract");
	const buffer = writeFixtureTar([
		{ name: "ok.txt", data: "fine" },
		{ name: "../escape.txt", data: "bad" },
		{ name: "/abs.txt", data: "bad" },
		{ name: "link", kind: "symlink", flag: "2", linkname: "/etc/passwd" },
		{ name: "dev", kind: "char", flag: "3" }
	]);
	const parsed = plugin.parseTar(buffer);
	const plan = plugin.planExtraction(parsed, root, { maxEntries: 100, maxTotalBytes: 1e9, maxNameBytes: 1000 });
	equal("only the safe member is writable", plan.writable.map((m) => m.name), ["ok.txt"]);
	equal("every unsafe member is refused", plan.refused.length, 4);
	equal("the traversal is named", plan.refused.some((r) => r.name === "../escape.txt" && r.kind === "traversal"), true);
	equal("the absolute member is refused as traversal-class", plan.refused.some((r) => r.name === "/abs.txt"), true);
	equal("the symlink is refused", plan.refused.some((r) => r.kind === "symlink"), true);
	equal("the device is refused", plan.refused.some((r) => r.kind === "device"), true);
	ok("the symlink refusal names its target", plan.refused.find((r) => r.kind === "symlink").reason.includes("/etc/passwd"));
	ok("the symlink refusal explains why links are not extracted", plan.refused.find((r) => r.kind === "symlink").reason.includes("follow them out of the tree"));
	equal("the device refusal names the kind", plan.refused.find((r) => r.kind === "device").reason.includes("character device"), true);
	equal("the byte total counts only accepted members", plan.totalBytes, 4);
}
{
	const root = resolve("C:/base/extract");
	const parsed = plugin.parseTar(writeFixtureTar([
		{ name: "a.txt", data: "1234567890" },
		{ name: "b.txt", data: "1234567890" }
	]));
	const plan = plugin.planExtraction(parsed, root, { maxEntries: 100, maxTotalBytes: 12, maxNameBytes: 1000 });
	equal("the first member fits under the cap", plan.writable.map((m) => m.name), ["a.txt"]);
	equal("the member that would break the cap is refused", plan.refused[0].kind, "size");
	ok("the refusal states both the projected and the allowed total", plan.refused[0].reason.includes(">"));
}
{
	const root = resolve("C:/base/extract");
	const parsed = plugin.parseTar(writeFixtureTar([{ name: "a".repeat(200) + ".txt", data: "x" }]));
	const plan = plugin.planExtraction(parsed, root, { maxEntries: 100, maxTotalBytes: 1e9, maxNameBytes: 50 });
	equal("an over-long name is refused", plan.refused[0].kind, "name");
}
{
	const root = resolve("C:/base/extract");
	const buffer = writeFixtureTar([{ name: "a.txt", data: "x" }]);
	const damaged = Buffer.from(buffer);
	damaged.write("0000000\u0000", 148, "latin1");
	const parsed = plugin.parseTar(damaged);
	const plan = plugin.planExtraction(parsed, root, { maxEntries: 100, maxTotalBytes: 1e9, maxNameBytes: 1000 });
	equal("a member with a bad checksum is refused", plan.refused.some((r) => r.kind === "checksum"), true);
}
{
	const root = resolve("C:/base/extract");
	const parsed = plugin.parseTar(writeFixtureTar([
		{ name: "weird", kind: "other", flag: "Z" }
	]));
	const plan = plugin.planExtraction(parsed, root, { maxEntries: 100, maxTotalBytes: 1e9, maxNameBytes: 1000 });
	equal("an unknown type flag is refused", plan.refused[0].kind, "unknown");
}
{
	const root = resolve("C:/base/extract");
	const parsed = plugin.parseTar(writeFixtureTar([{ name: "a.txt", data: "x" }]));
	const plan = plugin.planExtraction(parsed, root, { maxEntries: 0, maxTotalBytes: 1e9, maxNameBytes: 1000 });
	ok("exceeding maxEntries warns rather than silently truncating", plan.warnings.some((w) => w.includes("maxEntries")));
	equal("but the member is still planned", plan.writable.length, 1);
}
{
	// The refusal must happen on the *whole* configured root, not on the
	// member's immediate parent, or `a/../../b` slips through.
	const root = resolve("C:/base/extract");
	const parsed = plugin.parseTar(writeFixtureTar([{ name: "a/../../b.txt", data: "x" }]));
	const plan = plugin.planExtraction(parsed, root, { maxEntries: 100, maxTotalBytes: 1e9, maxNameBytes: 1000 });
	equal("a buried traversal is refused", plan.writable.length, 0);
	equal("and is classed as traversal", plan.refused[0].kind, "traversal");
}
{
	// Two members differing only in case are both fine on their own, and the
	// plan must accept both — the warning is about the filesystem they will land
	// on, not about the archive being wrong.
	const root = resolve("C:/base/extract");
	const parsed = plugin.parseTar(writeFixtureTar([
		{ name: "README.md", data: "U" },
		{ name: "readme.md", data: "l" },
		{ name: "other.txt", data: "o" }
	]));
	const plan = plugin.planExtraction(parsed, root, { maxEntries: 100, maxTotalBytes: 1e9, maxNameBytes: 1000 });
	equal("both spellings are accepted", plan.writable.length, 3);
	equal("nothing is refused for a case collision", plan.refused.length, 0);
	ok("but the collision is warned about", plan.warnings.some((w) => w.includes("differ only in case")));
	ok("the warning names both names", plan.warnings.some((w) => w.includes("README.md") && w.includes("readme.md")));
	ok("and says one will overwrite the other", plan.warnings.some((w) => w.includes("overwrite")));
}
{
	// Names that differ by more than case must not be flagged.
	const root = resolve("C:/base/extract");
	const parsed = plugin.parseTar(writeFixtureTar([
		{ name: "a.txt", data: "1" },
		{ name: "b.txt", data: "2" },
		{ name: "A.md", data: "3" }
	]));
	const plan = plugin.planExtraction(parsed, root, { maxEntries: 100, maxTotalBytes: 1e9, maxNameBytes: 1000 });
	equal("distinct names produce no collision warning", plan.warnings.filter((w) => w.includes("differ only in case")).length, 0);
}
{
	// Directory and file entries take part in the same comparison, since on a
	// case-insensitive filesystem `Docs` and `docs` are one directory.
	const root = resolve("C:/base/extract");
	const parsed = plugin.parseTar(writeFixtureTar([
		{ name: "Docs", kind: "directory" },
		{ name: "docs", kind: "directory" }
	]));
	const plan = plugin.planExtraction(parsed, root, { maxEntries: 100, maxTotalBytes: 1e9, maxNameBytes: 1000 });
	ok("directories collide too", plan.warnings.some((w) => w.includes("differ only in case")));
}

/* ----------------------------------------------------------- humanBytes */

equal("bytes stay bytes", plugin.humanBytes(512), "512 B");
equal("1024 becomes 1.0 KB", plugin.humanBytes(1024), "1.0 KB");
equal("1536 becomes 1.5 KB", plugin.humanBytes(1536), "1.5 KB");
equal("a megabyte reads as MB", plugin.humanBytes(1024 * 1024), "1.0 MB");
equal("a gigabyte reads as GB", plugin.humanBytes(1024 ** 3), "1.0 GB");
equal("zero reads as 0 B", plugin.humanBytes(0), "0 B");
equal("a negative is clamped rather than printed", plugin.humanBytes(-5), "0 B");
equal("a non-number is clamped", plugin.humanBytes(undefined), "0 B");
equal("a huge value stops at TB", plugin.humanBytes(1024 ** 5).endsWith("TB"), true);

/* -------------------------------------------------------- excludeSet */

{
	equal("undefined takes the fallback", [...plugin.excludeSet(undefined, ["node_modules"])], ["node_modules"]);
	equal("an empty string takes the fallback", [...plugin.excludeSet("", ["node_modules"])], ["node_modules"]);
	equal("a comma-separated string is split", [...plugin.excludeSet("a, b ,c", [])], ["a", "b", "c"]);
	equal("an array is accepted", [...plugin.excludeSet(["a", "b"], [])], ["a", "b"]);
	equal("blank items are dropped", [...plugin.excludeSet("a,,b", [])], ["a", "b"]);
	equal("an explicit list replaces the fallback entirely", plugin.excludeSet("x", ["node_modules"]).has("node_modules"), false);
}

/* -------------------------------------------------------- archivePath */

{
	const dir = resolve("C:/base/arch");
	ok("an empty request gets a timestamped tar", plugin.archivePath(dir, "").endsWith(".tar"));
	equal("a name gets the extension added", plugin.archivePath(dir, "pack"), resolve(dir, "pack.tar"));
	equal("an existing .tar extension is kept", plugin.archivePath(dir, "pack.tar"), resolve(dir, "pack.tar"));
	equal("a .tgz name is kept as given", plugin.archivePath(dir, "pack.tgz"), resolve(dir, "pack.tgz"));
	equal("an absolute name is stripped to its tail", plugin.archivePath(dir, "C:/Windows/x.tar"), resolve(dir, "x.tar"));
	equal("a traversal is stripped to its tail", plugin.archivePath(dir, "../x"), resolve(dir, "x.tar"));
}

/* -------------------------------------------------------- resolveSource */

{
	const dir = resolve("C:/base");
	equal("an empty source is the work directory", plugin.resolveSource(dir, ""), dir);
	equal("a relative source resolves against it", plugin.resolveSource(dir, "sub"), resolve(dir, "sub"));
	equal("an absolute source is honoured, because reading is not writing", plugin.resolveSource(dir, "D:/data"), resolve("D:/data"));
}

/* --------------------------------------------------------- constants */

equal("the block size is 512", plugin.BLOCK, 512);
equal("the checksum field starts at 148", plugin.CHECKSUM_OFFSET, 148);
equal("the checksum field is 8 bytes", plugin.CHECKSUM_LENGTH, 8);
equal("the name field is 100 bytes", plugin.USTAR_NAME_MAX, 100);
equal("the prefix field is 155 bytes", plugin.USTAR_PREFIX_MAX, 155);
equal("the magic is ustar plus a NUL", plugin.USTAR_MAGIC, "ustar\u0000");
equal("the version is 00", plugin.USTAR_VERSION, "00");
equal("a file mode is pinned to 644", plugin.PACK_MODE_FILE, 0o644);
equal("a directory mode is pinned to 755", plugin.PACK_MODE_DIR, 0o755);
equal("the default excludes cover node_modules and .git", ["node_modules", ".git"].every((n) => plugin.DEFAULT_EXCLUDES.includes(n)), true);
ok("symlinks are a known type", plugin.TYPE_FLAGS["2"] === "symlink");
ok("hardlinks are a known type", plugin.TYPE_FLAGS["1"] === "hardlink");
ok("the dangerous list covers devices and FIFOs", ["3", "4", "6"].every((f) => plugin.DANGEROUS_TYPES[f] !== undefined));
ok("a FIFO is listed by name", plugin.DANGEROUS_TYPES["6"].includes("FIFO"));

/* ---------------------------------------------------------- sha256 */

equal("sha256 of empty matches the known digest", plugin.sha256(Buffer.alloc(0)), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
equal("sha256 of 'abc' matches the known digest", plugin.sha256(Buffer.from("abc")), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

/* -------------------------------------------------------------- report */

console.log(`archive logic: ${passed} passed, ${failed} failed`);
process.exit(failed === 0 ? 0 : 1);