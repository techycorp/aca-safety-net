/**
 * aca-safety-net hook for oh-my-pi (omp).
 *
 * Sends each tool call to `aca-safety-net --agent omp`. Exit 2 blocks the
 * call; an ask decision opens a confirm dialog (blocked without a UI); any
 * other failure (binary missing, crash, timeout, other exit code) blocks.
 *
 * Every call is also blocked while the running omp differs from the version
 * the vendor tests last passed on, recorded by `just install`: the
 * translation of omp's tool calls is only known to hold for that version.
 *
 * Installed to ~/.omp/agent/hooks/pre/ by `just install`. Standalone: omp
 * loads it directly, so it has no dependencies beyond omp's types and Bun.
 */
import type { HookAPI } from "@oh-my-pi/pi-coding-agent/extensibility/hooks";
import * as fs from "node:fs";
import * as path from "node:path";

const BINARY = `${process.env.HOME}/.local/bin/aca-safety-net`;
const VERIFIED_FILE = `${process.env.HOME}/.config/aca-safety-net/omp-verified.json`;
const OMP_PACKAGE = "@oh-my-pi/pi-coding-agent";
const TIMEOUT_MS = 10_000;
const TAG = "[aca-safety-net]";

type Verified = { readonly version: string; readonly repo: string };

const readJson = (file: string): Record<string, unknown> | undefined => {
	try {
		return JSON.parse(fs.readFileSync(file, "utf8"));
	} catch {
		return undefined;
	}
};

/** The version in the package.json of the omp install running this hook. */
const runningOmpVersion = (): string | undefined => {
	let dir = path.dirname(fs.realpathSync(Bun.main));
	while (dir !== path.dirname(dir)) {
		const manifest = readJson(path.join(dir, "package.json"));
		if (manifest?.name === OMP_PACKAGE) return String(manifest.version);
		dir = path.dirname(dir);
	}
	return undefined;
};

const readVerified = (): Verified | undefined => {
	const v = readJson(VERIFIED_FILE);
	return typeof v?.version === "string" ? { version: v.version, repo: String(v.repo ?? "aca-safety-net") } : undefined;
};

/** Why every call is blocked, or undefined when the running omp is the verified one. */
const versionBlock = (running: string | undefined, verified: Verified | undefined): string | undefined => {
	if (running !== undefined && running === verified?.version) return undefined;
	const repo = verified?.repo ?? "the aca-safety-net repo";
	return (
		`${TAG} omp is ${running ?? "an unknown version"}, but aca-safety-net's checks last passed on ` +
		`${verified?.version ?? "no version"}. Ask the user to run \`just install\` in ${repo}, ` +
		"which re-runs the checks against this omp. Until then every tool call is blocked."
	);
};

type Run = { readonly code: number | null; readonly stdout: string; readonly stderr: string };

type Verdict =
	| { readonly kind: "allow" }
	| { readonly kind: "block"; readonly reason: string }
	| { readonly kind: "ask"; readonly reason: string };

const runBinary = async (event: unknown): Promise<Run> => {
	const proc = Bun.spawn([BINARY, "--agent", "omp"], {
		stdin: new TextEncoder().encode(JSON.stringify(event)),
		stdout: "pipe",
		stderr: "pipe",
	});
	const timer = setTimeout(() => proc.kill(), TIMEOUT_MS);
	try {
		const [stdout, stderr, code] = await Promise.all([
			new Response(proc.stdout).text(),
			new Response(proc.stderr).text(),
			proc.exited,
		]);
		return { code: proc.signalCode ? null : code, stdout, stderr };
	} finally {
		clearTimeout(timer);
	}
};

const askReason = (stdout: string): string | undefined => {
	try {
		const out = JSON.parse(stdout.trim())?.hookSpecificOutput;
		return out?.permissionDecision === "ask" ? String(out.permissionDecisionReason ?? "") : undefined;
	} catch {
		return undefined;
	}
};

const verdictOf = (run: Run): Verdict => {
	if (run.code === 2) return { kind: "block", reason: `${TAG}: ${run.stderr.trim()}` };
	if (run.code !== 0) {
		return { kind: "block", reason: `${TAG} check failed (exit ${run.code ?? "timeout"}): ${run.stderr.trim()}` };
	}
	const ask = run.stdout.trim() ? askReason(run.stdout) : undefined;
	return ask === undefined ? { kind: "allow" } : { kind: "ask", reason: ask };
};

const check = (event: unknown): Promise<Verdict> =>
	runBinary(event).then(verdictOf, (e) => ({ kind: "block", reason: `${TAG} could not run ${BINARY}: ${String(e)}` }));

export default function (pi: HookAPI) {
	pi.on("tool_call", async (event, ctx) => {
		const outdated = versionBlock(runningOmpVersion(), readVerified());
		if (outdated) return { block: true, reason: outdated };
		const verdict = await check({ tool_name: event.toolName, tool_input: event.input, cwd: ctx.cwd });
		switch (verdict.kind) {
			case "allow":
				return undefined;
			case "block":
				return { block: true, reason: verdict.reason };
			case "ask": {
				if (!ctx.hasUI) return { block: true, reason: `${TAG} needs approval: ${verdict.reason}` };
				const ok = await ctx.ui.confirm("aca-safety-net", verdict.reason);
				return ok ? undefined : { block: true, reason: `${TAG} declined: ${verdict.reason}` };
			}
			default: {
				const _exhaustive: never = verdict;
				return _exhaustive;
			}
		}
	});
}
