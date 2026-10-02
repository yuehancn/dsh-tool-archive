// Published-artifact regression.
//
// The other three suites all run the plugin through `new Function`, i.e. the
// entry point is exercised from a string with its imports stripped and rebound.
// That is the right shape for reaching internals, but it means none of them
// ever load the plugin the way a user does: `import` the installed package and
// let the real `@deepseek-ai/dsh-tools` compiler turn the schema objects into
// whatever the framework actually wants, from the file as shipped.
//
// So this file does exactly that, from the installed tree, with no harness and
// no string surgery. It is deliberately small — a smoke test, not a suite:
//
//   1. `import()` resolves the real `lib/index.js` from disk.
//   2. `Config` is a real schemastery constructor that resolves defaults.
//   3. `apply()` registers four tools against a live tool registry.
//   4. Every emitted schema survives the real JSON-schema compiler — the thing
//      that threw `JsonSchemaError` when `required` was authored as an array.
//   5. Tools actually execute end to end through the registry.
//
// If a future edit reintroduces a malformed schema, this is the file that fails
// first, and it fails for the reason a user would hit.
import { strict as assert } from "node:assert";
import { mkdtemp, mkdir, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

let passed = 0;
let failed = 0;

function check(name, fn) {
	try {
		fn();
		passed += 1;
	} catch (error) {
		failed += 1;
		console.log(`  FAIL  ${name}\n        ${error.message}`);
	}
}

async function checkAsync(name, fn) {
	try {
		await fn();
		passed += 1;
	} catch (error) {
		failed += 1;
		console.log(`  FAIL  ${name}\n        ${error.message}`);
	}
}

console.log("archive: published-artifact regression");

// ── 1. The package metadata, read from disk ────────────────────────────────
const pkg = JSON.parse(
	await import("node:fs/promises").then((fs) =>
		fs.readFile(new URL("../package.json", import.meta.url), "utf8")
	)
);

check("package declares dsh.bundle.patch", () => {
	assert.equal(pkg.dsh?.bundle?.patch, "./cordis.patch.yml");
});

check("package main resolves to lib/index.js", () => {
	assert.equal(pkg.main, "lib/index.js");
	assert.equal(pkg.exports?.["."], "./lib/index.js");
});

check("package ships only the runtime files", () => {
	assert.deepEqual(pkg.files, [
		"lib/**/*.js",
		"cordis.patch.yml",
		"README.md",
		"LICENSE"
	]);
});

// ── 2. Import the shipped entry point and the real compiler ────────────────
const plugin = await import("../lib/index.js");

check("plugin exports a name", () => {
	assert.equal(typeof plugin.name, "string");
	assert.ok(plugin.name.length > 0);
});

check("plugin exports a Config constructor", () => {
	assert.equal(typeof plugin.Config, "function");
});

check("plugin exports an apply function", () => {
	assert.equal(typeof plugin.apply, "function");
});

check("plugin exports an inject list", () => {
	assert.ok(Array.isArray(plugin.inject), "inject must be an array");
});

const tools = await import("@deepseek-ai/dsh-tools");

check("dsh-tools exports defineTool", () => {
	assert.equal(typeof tools.defineTool, "function");
});

// ── 3. Config resolves defaults through schemastery ────────────────────────
const resolved = new plugin.Config({ workDir: process.cwd() });

check("Config resolves maxEntries default", () => {
	assert.equal(resolved.maxEntries, 20000);
});

check("Config resolves hash default", () => {
	assert.equal(resolved.hash, true);
});

check("Config resolves noOverwrite default", () => {
	assert.equal(resolved.noOverwrite, false);
});

check("Config resolves timeoutMs default", () => {
	assert.equal(resolved.timeoutMs, 300000);
});

// ── 4. Register against the real compiler ─────────────────────────────────
//
// `apply` reads `ctx.tools.register` and calls `defineTool` itself, so the
// schema is compiled by the real package. Nothing is stubbed.
const registered = new Map();
const ctx = {
	tools: {
		register(spec) {
			registered.set(spec.name, spec);
			return spec;
		}
	},
	transport: {}
};

await checkAsync("apply registers four tools without throwing", async () => {
	await plugin.apply(ctx, resolved);
});

check("the four expected tool names are registered", () => {
	assert.deepEqual([...registered.keys()].sort(), [
		"archive_pack",
		"archive_status",
		"archive_unpack",
		"archive_verify"
	]);
});

// ── 5. Every emitted schema is well-formed ────────────────────────────────
//
// The load-time throw came from `required` being authored as an array on the
// tool root. Assert the compiled shape instead: an array only where the
// framework hoisted flags, never a leaking per-property boolean.
for (const [name, spec] of registered) {
	check(`${name}: parameters is an object schema`, () => {
		assert.equal(typeof spec.parameters, "object");
		assert.equal(spec.parameters.type, "object");
	});

	check(`${name}: no property leaks a bare required flag`, () => {
		for (const [key, value] of Object.entries(spec.parameters.properties ?? {})) {
			if (value !== null && typeof value === "object" && !Array.isArray(value)) {
				assert.ok(
					value.required === undefined,
					`property "${key}" still carries a required flag after compilation`
				);
			}
		}
	});

	check(`${name}: output schema is object-typed`, () => {
		const schema = spec.output?.schema ?? spec.output;
		assert.equal(schema?.type, "object");
	});

	check(`${name}: every nested object declares additionalProperties`, () => {
		// The argument schema (`parameters`) has no `additionalProperties` of its
		// own — the framework synthesises that flag only for output schemas and
		// for objects the author declares inside them. So the walk starts at the
		// output schema and only descends into *nested* objects of `parameters`,
		// never asserting on the parameters root itself.
		const walk = (node, path, isRoot) => {
			if (node === null || typeof node !== "object") return;
			if (Array.isArray(node)) {
				node.forEach((item, index) => walk(item, `${path}[${index}]`, false));
				return;
			}
			if (node.type === "object" && !isRoot) {
				assert.ok(
					node.additionalProperties === true || node.additionalProperties === false,
					`object at ${path} must declare additionalProperties explicitly`
				);
			}
			for (const [key, value] of Object.entries(node)) {
				if (key === "properties") {
					for (const [prop, child] of Object.entries(value ?? {})) {
						walk(child, `${path}.properties.${prop}`, false);
					}
					continue;
				}
				walk(value, `${path}.${key}`, false);
			}
		};
		// `parameters` root is exempt; every object beneath it is not.
		for (const [prop, child] of Object.entries(spec.parameters.properties ?? {})) {
			walk(child, `parameters.properties.${prop}`, false);
		}
		if (spec.output !== undefined) {
			walk(spec.output.schema ?? spec.output, "output", true);
		}
	});

	check(`${name}: declares a timeout and a concurrency verdict`, () => {
		assert.equal(typeof spec.timeoutMs, "number");
		// `isConcurrencySafe` is wrapped with the argument validator, so the
		// wrapper needs a schema-valid call before the predicate is reached.
		assert.equal(typeof spec.isConcurrencySafe, "function");
	});
}

// ── 6. Tools actually run through the registry ────────────────────────────
//
// `call` mirrors how the framework invokes a tool: `execute(args, { signal })`.
// The order that matters here is (args, context) — passing the context first
// is the mistake to avoid, and it fails loudly rather than silently.
function call(spec, args, context) {
	return spec.execute(args, { signal: undefined, context });
}

const sandbox = await mkdtemp(join(tmpdir(), "archive-published-"));
const workDir = join(sandbox, "work");
await mkdir(workDir, { recursive: true });
await writeFile(join(workDir, "readme.txt"), "published artifact regression\n");
await writeFile(join(workDir, "notes.md"), "# notes\n");

// Rebuild the context with all directories pointing inside the sandbox.
const runtimeConfig = new plugin.Config({
	workDir,
	archiveDir: join(sandbox, "archives"),
	extractDir: join(sandbox, "extract")
});
const runtimeCtx = { tools: ctx.tools, transport: {} };
await plugin.apply(runtimeCtx, runtimeConfig);
const live = (name) => registered.get(name);

await checkAsync("archive_status runs through the registry", async () => {
	const result = await call(live("archive_status"), {}, runtimeConfig);
	assert.ok(result !== null && typeof result === "object");
	assert.equal(typeof result.format, "string");
	// `operations` names the *other* tools this plugin registers, so three.
	assert.ok(Array.isArray(result.operations));
	assert.equal(result.operations.length, 3);
	assert.ok(result.directories.workDir.length > 0);
});

await checkAsync("archive_pack produces an archive that archive_verify accepts", async () => {
	const packed = await call(live("archive_pack"), { source: workDir }, runtimeConfig);
	assert.ok(packed?.file, "pack must report the archive path");
	assert.ok(Array.isArray(packed.manifest) && packed.manifest.length >= 2);

	const verified = await call(live("archive_verify"), { file: packed.file }, runtimeConfig);
	assert.equal(verified?.ok, true, "verify must accept a freshly packed archive");
});

await checkAsync("archive_unpack lists without writing anything", async () => {
	const packed = await call(live("archive_pack"), { source: workDir }, runtimeConfig);
	const listed = await call(
		live("archive_unpack"),
		{ file: packed.file, listOnly: true },
		runtimeConfig
	);
	// The member list is `manifest`; `entries` is the raw header count.
	assert.ok(Array.isArray(listed.manifest));
	assert.ok(listed.manifest.length >= 2);
	assert.equal(listed.listOnly, true);
	assert.equal(listed.written, 0);
});

await checkAsync("archive_pack refuses a non-string source before touching disk", async () => {
	// The compiled validator runs first; a wrong *type* must be refused.
	let threw = false;
	try {
		await live("archive_pack").execute({ source: 42 }, { signal: undefined });
	} catch {
		threw = true;
	}
	assert.equal(threw, true, "a numeric source must be rejected by the validator");
});

await rm(sandbox, { recursive: true, force: true });

console.log("");
console.log(`archive published-artifact regression: ${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);