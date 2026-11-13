/**
 * Vendor tests: what the installed oh-my-pi (omp) actually does, for the
 * assumptions the omp hook (`omp/aca-safety-net.ts`) and `src/omp.rs` make.
 * Each test backs one claim in `vendor-claims.toml`.
 *
 * They load omp's own modules from its install directory, found through the
 * `omp` on PATH (or OMP_PACKAGE_DIR). Run with `just vendor-test`.
 */
import { afterAll, describe, expect, test } from "bun:test";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

const PACKAGE_NAME = "@oh-my-pi/pi-coding-agent";

const findPackageDir = (): string | undefined => {
	if (process.env.OMP_PACKAGE_DIR) return process.env.OMP_PACKAGE_DIR;
	const bin = Bun.which("omp");
	if (!bin) return undefined;
	let dir = path.dirname(fs.realpathSync(bin));
	while (dir !== path.dirname(dir)) {
		const manifest = path.join(dir, "package.json");
		if (fs.existsSync(manifest) && JSON.parse(fs.readFileSync(manifest, "utf8")).name === PACKAGE_NAME) return dir;
		dir = path.dirname(dir);
	}
	return undefined;
};

const PKG = findPackageDir();
const SRC = PKG ? path.join(PKG, "src") : "";
const vendor = describe.skipIf(!PKG);
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "aca-omp-vendor-"));
afterAll(() => fs.rmSync(tmp, { recursive: true, force: true }));

const writeProbeHook = (name: string, body: string): string => {
	const file = path.join(tmp, `${name}.ts`);
	fs.writeFileSync(file, `export default function (pi) {\n${body}\n}\n`);
	return file;
};

/** A tool named `name` that records whether it ran, wrapped in omp's hook wrapper with `hookFile` loaded. */
const wrappedTool = async (name: string, hookFile: string, runnerCwd: string) => {
	const { loadHooks, HookRunner, HookToolWrapper } = await import(`${SRC}/extensibility/hooks/index.ts`);
	const { hooks, errors } = await loadHooks([hookFile], runnerCwd);
	expect(errors).toEqual([]);
	const runner = new HookRunner(hooks, runnerCwd, {}, {});
	const ran = { value: false };
	const tool = {
		name,
		label: name,
		description: "probe",
		parameters: {},
		execute: async () => {
			ran.value = true;
			return { content: [{ type: "text", text: "ok" }] };
		},
	};
	return { wrapper: new HookToolWrapper(tool, runner), ran };
};

vendor("omp hooks", () => {
	// Claim:    a tool_call hook event carries the tool name as toolName and its arguments as input, and the hook context carries the session cwd
	// Fails if: omp renamed toolName/input or dropped ctx.cwd: the recorded fields would be undefined
	test("omp must pass the tool name, input and session cwd to tool_call hooks", async () => {
		const seen = path.join(tmp, "seen.json");
		const hook = writeProbeHook(
			"record",
			`pi.on("tool_call", async (event, ctx) => {
				await Bun.write(${JSON.stringify(seen)}, JSON.stringify({ toolName: event.toolName, input: event.input, cwd: ctx.cwd }));
			});`,
		);
		const { wrapper } = await wrappedTool("bash", hook, "/session/dir");
		await wrapper.execute("call-1", { command: "ls", cwd: "sub" });
		const recorded = JSON.parse(fs.readFileSync(seen, "utf8"));
		expect(recorded.toolName).toBe("bash");
		expect(recorded.input).toEqual({ command: "ls", cwd: "sub" });
		expect(recorded.cwd).toBe("/session/dir");
	});

	// Claim:    a hook that throws or returns { block: true, reason } stops the tool call and shows the reason to the model
	// Fails if: omp ran the tool anyway, or swallowed the reason: ran would be true or the error text would differ
	// Control:  a hook that returns nothing lets the tool run
	test("omp must stop a tool call when a hook blocks it or throws", async () => {
		const allow = await wrappedTool("read", writeProbeHook("allow", `pi.on("tool_call", async () => undefined);`), tmp);
		await allow.wrapper.execute("call-2", { path: "a" });
		expect(allow.ran.value).toBe(true);

		const block = await wrappedTool(
			"read",
			writeProbeHook("block", `pi.on("tool_call", async () => ({ block: true, reason: "probe-block-reason" }));`),
			tmp,
		);
		await expect(block.wrapper.execute("call-3", { path: "a" })).rejects.toThrow("probe-block-reason");
		expect(block.ran.value).toBe(false);

		const thrown = await wrappedTool(
			"read",
			writeProbeHook("throw", `pi.on("tool_call", async () => { throw new Error("probe-hook-crash"); });`),
			tmp,
		);
		await expect(thrown.wrapper.execute("call-4", { path: "a" })).rejects.toThrow("probe-hook-crash");
		expect(thrown.ran.value).toBe(false);
	});

	// Claim:    hook files in ~/.omp/agent/hooks/pre/ load in every session unless extensions are disabled
	// Fails if: omp stopped looking in that directory: the probe file would be missing from the discovered paths
	test("omp must discover hook files in ~/.omp/agent/hooks/pre", async () => {
		const home = path.join(tmp, "home");
		const preDir = path.join(home, ".omp", "agent", "hooks", "pre");
		fs.mkdirSync(preDir, { recursive: true });
		fs.writeFileSync(path.join(preDir, "probe.ts"), "export default function () {}\n");
		const project = path.join(tmp, "project");
		fs.mkdirSync(project, { recursive: true });
		const script = path.join(tmp, "discover.ts");
		fs.writeFileSync(
			script,
			`import { loadCapability } from ${JSON.stringify(`${SRC}/capability/index.ts`)};
			import { hookCapability } from ${JSON.stringify(`${SRC}/capability/hook.ts`)};
			await import(${JSON.stringify(`${SRC}/discovery/index.ts`)});
			const found = await loadCapability(hookCapability.id, { cwd: ${JSON.stringify(project)} });
			console.log(JSON.stringify(found.items.map(h => h.path)));
			process.exit(0);`,
		);
		const proc = Bun.spawnSync(["bun", script], { env: { ...process.env, HOME: home }, cwd: project });
		const discovered: string[] = JSON.parse(proc.stdout.toString().trim().split("\n").pop() ?? "[]");
		expect(discovered).toContain(path.join(preDir, "probe.ts"));
	});
});

vendor("omp tool inputs", () => {
	const instantiate = async (file: string, cls: string) => {
		const { Settings } = await import(`${SRC}/config/settings.ts`);
		const settings = Settings.isolated();
		const mod = await import(`${SRC}/tools/${file}.ts`);
		return new mod[cls]({ cwd: tmp, settings, getSessionId: () => "vendor-test" });
	};
	/** The schema's result: the input when accepted, else its error text naming the offending field. */
	const validate = (schema: (v: unknown) => unknown, value: unknown): { ok: boolean; error: string } => {
		const result = schema(value) as { constructor?: { name?: string } };
		const rejected = result?.constructor?.name?.endsWith("Errors") === true;
		return { ok: !rejected, error: rejected ? String(result) : "" };
	};

	// Claim:    bash takes command and an optional cwd; read takes path; write takes path and optional content; grep takes pattern and optional path; glob takes optional path
	// Fails if: omp renamed a field (say path to file_path): the schema would reject the sample, or accept the Claude Code name instead
	test("omp tools must name their inputs command, cwd, path, content and pattern", async () => {
		// [module, class, tool name, input the hook expects, the field a wrong input lacks or mistypes, that input]
		const cases: Array<[string, string, string, Record<string, unknown>, string, Record<string, unknown>]> = [
			["bash", "BashTool", "bash", { command: "ls", cwd: "sub" }, "command", { cmd: "ls" }],
			["bash", "BashTool", "bash", { command: "ls", cwd: "sub" }, "cwd", { command: "ls", cwd: 1 }],
			["read", "ReadTool", "read", { path: "a.txt" }, "path", { file_path: "a.txt" }],
			["write", "WriteTool", "write", { path: "a.txt", content: "x" }, "path", { file_path: "a.txt", content: "x" }],
			["write", "WriteTool", "write", { path: "a.txt", content: "x" }, "content", { path: "a.txt", content: 1 }],
			["grep", "GrepTool", "grep", { pattern: "x", path: "src" }, "pattern", { regex: "x" }],
			["grep", "GrepTool", "grep", { pattern: "x", path: "src" }, "path", { pattern: "x", path: 1 }],
			["glob", "GlobTool", "glob", { path: "**/*.rs" }, "path", { path: 1 }],
		];
		for (const [file, cls, name, good, field, wrong] of cases) {
			const tool = await instantiate(file, cls);
			expect(tool.name).toBe(name);
			expect(validate(tool.parameters, good)).toStrictEqual({ ok: true, error: "" });
			const rejected = validate(tool.parameters, wrong);
			expect(rejected.ok).toBe(false);
			expect(rejected.error).toContain(field);
		}
	});

	// Claim:    eval takes language py or js and code
	// Fails if: omp renamed code or language, or added a runtime: the sample would be rejected or the other language accepted
	test("omp eval must take language py or js and code", async () => {
		const { evalSchema } = await import(`${SRC}/tools/eval.ts`);
		expect(validate(evalSchema, { language: "py", code: "1" }).ok).toBe(true);
		expect(validate(evalSchema, { language: "js", code: "1" }).ok).toBe(true);
		expect(validate(evalSchema, { language: "rb", code: "1" }).error).toContain("language");
		expect(validate(evalSchema, { language: "py", source: "1" }).error).toContain("code");
	});

	// Claim:    edit events carry the target as path, or the hashline patch targets as paths
	// Fails if: omp stopped extracting patch targets: paths would be missing and the hook would check no file
	test("omp edit events must carry patch targets as paths", async () => {
		const { normalizeToolEventInput } = await import(`${SRC}/extensibility/tool-event-input.ts`);
		const { HL_FILE_PREFIX, HL_FILE_SUFFIX } = await import(
			`${PKG}/node_modules/@oh-my-pi/pi-tui/src/tools/hashline-format.ts`
		);
		const patch = [`${HL_FILE_PREFIX}a.txt${HL_FILE_SUFFIX}`, "x", `${HL_FILE_PREFIX}b.txt${HL_FILE_SUFFIX}`, "y"].join("\n");
		expect(normalizeToolEventInput("edit", { input: patch }).paths).toEqual(["a.txt", "b.txt"]);
		expect(normalizeToolEventInput("edit", { input: `${HL_FILE_PREFIX}a.txt${HL_FILE_SUFFIX}\nx` }).path).toBe("a.txt");
		expect(normalizeToolEventInput("edit", { _path: "c.txt" }).path).toBe("c.txt");
	});
});

vendor("omp python eval", () => {
	/**
	 * Runs Python with omp's runner.py imported as `runner` and returns what
	 * `body` assigns to `result`. Loading runner.py repoints stdout at its kernel
	 * channel, so the result goes through a file.
	 */
	const withRunner = (body: string): unknown => {
		const script = path.join(tmp, "runner_probe.py");
		const out = path.join(tmp, "runner_probe.json");
		fs.rmSync(out, { force: true });
		fs.writeFileSync(
			script,
			[
				"import importlib.util, json, os",
				`spec = importlib.util.spec_from_file_location("omp_runner", ${JSON.stringify(`${SRC}/eval/py/runner.py`)})`,
				"runner = importlib.util.module_from_spec(spec)",
				"spec.loader.exec_module(runner)",
				body,
				`open(${JSON.stringify(out)}, "w").write(json.dumps(result))`,
			].join("\n"),
		);
		const proc = Bun.spawnSync(["python", "-I", script]);
		expect(proc.exitCode).toBe(0);
		return JSON.parse(fs.readFileSync(out, "utf8"));
	};

	// Claim:    a Python cell runs !cmd and var = !cmd lines as shell, %magic lines through omp's magic of that name, and a %%magic cell through the cell magic of that name
	// Fails if: omp passed these lines to Python unchanged, or ran magics as shell: the translated text would differ
	test("omp python cells must run !cmd as shell and %name as the omp magic", () => {
		const cells = ["!ls -la", "x = !whoami", "%env HOME", "%%bash\necho hi"];
		const out = withRunner(`result = [runner.transform_cell(c) for c in ${JSON.stringify(cells)}]`) as string[];
		expect(out).toHaveLength(4);
		expect(out[0]).toContain("__omp_shell(");
		expect(out[0]).toContain("ls -la");
		expect(out[1]).toMatch(/^x = __omp_shell\(.*whoami/);
		expect(out[2]).toMatch(/__omp_magic\(['"]env['"], ['"]HOME['"]\)/);
		expect(out[3]).toMatch(/__omp_magic_cell\(['"]bash['"]/);
	});

	// Claim:    omp's magics are exactly the set src/omp.rs handles: line env, set_env, load, run, cd, pwd, ls, pip, time, timeit, who, whos, reset; cell bash, capture, timeit, writefile
	// Fails if: omp added a magic (say %cat) that the hook would only check by name: the set would differ
	test("omp must define exactly the magics the hook translates", () => {
		const out = withRunner("result = {'line': sorted(runner._LINE_MAGICS), 'cell': sorted(runner._CELL_MAGICS)}");
		expect(out).toStrictEqual({
			line: ["cd", "env", "load", "ls", "pip", "pwd", "reset", "run", "set_env", "time", "timeit", "who", "whos"],
			cell: ["bash", "capture", "timeit", "writefile"],
		});
	});

	// Claim:    %env with no arguments returns every environment variable, and %env NAME returns that variable
	// Fails if: %env only set variables: the probe variable would be missing from both results
	test("omp %env must return environment variables", () => {
		// Only booleans leave the probe, never variable values.
		const out = withRunner(
			[
				"os.environ['ACA_VENDOR_PROBE'] = 'probe-value'",
				"everything = runner._magic_env('')",
				"result = [runner._magic_env('ACA_VENDOR_PROBE') == 'probe-value', isinstance(everything, dict) and everything.get('ACA_VENDOR_PROBE') == 'probe-value']",
			].join("\n"),
		);
		expect(out).toStrictEqual([true, true]);
	});
});

vendor("omp version", () => {
	// Claim:    the package.json in omp's install directory holds the version omp reports
	// Fails if: omp's reported version came from elsewhere: the two would differ after an update
	test("omp must report the version in its package.json", () => {
		const manifest = JSON.parse(fs.readFileSync(path.join(PKG ?? "", "package.json"), "utf8"));
		const proc = Bun.spawnSync(["omp", "--version"]);
		expect(proc.stdout.toString()).toContain(manifest.version);
	});
});
