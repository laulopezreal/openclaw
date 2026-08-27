import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { PassThrough } from "node:stream";
import { fileURLToPath, pathToFileURL } from "node:url";

const MAX_DENY_MS = 5_000;
const WAIT_INTERVAL_MS = 200;
const WAIT_TIMEOUT_MS = 30_000;

type AcpPermissionProof = {
  elapsedMs: number;
  optionId: string | null;
  outcome: string;
};

type TargetRuntime = {
  decodeWindowsLauncherScript: (params: { buffer: Buffer }) => string;
  execSchtasks: (argv: string[]) => Promise<{ code: number }>;
  resolveGatewayService: () => {
    install(params: {
      description: string;
      env: NodeJS.ProcessEnv;
      environment: Record<string, string>;
      programArguments: string[];
      stdout: NodeJS.WritableStream;
      workingDirectory: string;
    }): Promise<void>;
    uninstall(params: { env: NodeJS.ProcessEnv; stdout: NodeJS.WritableStream }): Promise<void>;
  };
  resolveGatewayWindowsTaskName: (profile: string) => string;
  resolveTaskScriptPath: (env: NodeJS.ProcessEnv) => string;
};

function sleep(): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, WAIT_INTERVAL_MS));
}

export function assertAcpPermissionProof(value: unknown): asserts value is AcpPermissionProof {
  if (typeof value !== "object" || value === null) {
    throw new Error("ACP permission proof must be an object");
  }
  const proof = value as Partial<AcpPermissionProof>;
  if (
    typeof proof.elapsedMs !== "number" ||
    !Number.isFinite(proof.elapsedMs) ||
    proof.elapsedMs < 0 ||
    proof.elapsedMs > MAX_DENY_MS ||
    proof.outcome !== "selected" ||
    proof.optionId !== "deny"
  ) {
    throw new Error("ACP permission request did not take the prompt non-interactive deny path");
  }
}

async function waitForProof(resultPath: string): Promise<AcpPermissionProof> {
  const deadline = Date.now() + WAIT_TIMEOUT_MS;
  let lastError: unknown;
  while (Date.now() < deadline) {
    try {
      const proof = JSON.parse(await fs.readFile(resultPath, "utf8")) as unknown;
      assertAcpPermissionProof(proof);
      return proof;
    } catch (error) {
      lastError = error;
      await sleep();
    }
  }
  throw new Error(
    `Timed out waiting for ACP Scheduled Task denial: ${
      lastError instanceof Error ? lastError.message : String(lastError)
    }`,
  );
}

async function loadTargetRuntime(targetRoot: string): Promise<TargetRuntime> {
  const load = async (relativePath: string) =>
    await import(pathToFileURL(path.join(targetRoot, relativePath)).href);
  const [launcher, constants, schtasksExec, schtasks, service] = await Promise.all([
    load("src/infra/windows-launcher-encoding.js"),
    load("src/daemon/constants.js"),
    load("src/daemon/schtasks-exec.js"),
    load("src/daemon/schtasks.js"),
    load("src/daemon/service.js"),
  ]);
  return {
    decodeWindowsLauncherScript: launcher.decodeWindowsLauncherScript,
    execSchtasks: schtasksExec.execSchtasks,
    resolveGatewayService: service.resolveGatewayService,
    resolveGatewayWindowsTaskName: constants.resolveGatewayWindowsTaskName,
    resolveTaskScriptPath: schtasks.resolveTaskScriptPath,
  };
}

async function main(): Promise<void> {
  if (process.platform !== "win32") {
    throw new Error("Native Scheduled Task ACP proof must run on Windows");
  }
  const targetRoot = path.resolve(
    process.env.CI_WINDOWS_SCHTASKS_TARGET_ROOT?.trim() || process.cwd(),
  );
  const expectedHead = process.env.EXPECTED_HEAD?.trim().toLowerCase();
  if (!expectedHead || !/^[0-9a-f]{40}$/u.test(expectedHead)) {
    throw new Error("EXPECTED_HEAD must identify the exact 40-character target SHA");
  }
  const actualHead = execFileSync("git", ["rev-parse", "HEAD"], {
    cwd: targetRoot,
    encoding: "utf8",
  }).trim();
  if (actualHead !== expectedHead) {
    throw new Error(`Target checkout is ${actualHead}, expected ${expectedHead}`);
  }
  const proofPath = process.env.CI_WINDOWS_SCHTASKS_ACP_PROOF_PATH?.trim();
  if (!proofPath) {
    throw new Error("CI_WINDOWS_SCHTASKS_ACP_PROOF_PATH is required");
  }

  const runtime = await loadTargetRuntime(targetRoot);
  const id = randomUUID().slice(0, 8);
  const rootDir = await fs.mkdtemp(path.join(os.tmpdir(), `openclaw-schtasks-acp-${id}-`));
  const stateDir = path.join(os.userInfo().homedir, `.openclaw-schtasks-acp-${id}`);
  const profile = `schtasks-acp-${id}`;
  const taskName = runtime.resolveGatewayWindowsTaskName(profile);
  const workingDirectory = path.join(rootDir, "acpx-permission-proof");
  const resultPath = path.join(workingDirectory, "result.json");
  const acpxCliPath = path.join(targetRoot, "node_modules", "acpx", "dist", "cli.js");
  const agentPath = path.resolve(process.env.CI_WINDOWS_SCHTASKS_ACP_AGENT_PATH?.trim() || "");
  if (!agentPath || agentPath === path.resolve(".")) {
    throw new Error("CI_WINDOWS_SCHTASKS_ACP_AGENT_PATH is required");
  }
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    APPDATA: path.join(rootDir, "appdata"),
    HOME: os.userInfo().homedir,
    OPENCLAW_CONFIG_PATH: path.join(stateDir, "openclaw.json"),
    OPENCLAW_HOME: undefined,
    OPENCLAW_PROFILE: profile,
    OPENCLAW_STATE_DIR: stateDir,
    OPENCLAW_TASK_SCRIPT: undefined,
    OPENCLAW_TASK_SCRIPT_NAME: undefined,
    OPENCLAW_WINDOWS_TASK_HIDDEN_LAUNCHER: "1",
    OPENCLAW_WINDOWS_TASK_NAME: undefined,
    USERPROFILE: os.userInfo().homedir,
  };
  const stdout = new PassThrough();
  let installed = false;
  try {
    await fs.mkdir(workingDirectory);
    await fs.writeFile(
      path.join(workingDirectory, ".acpxrc.json"),
      `${JSON.stringify(
        {
          agents: { "scheduled-task-proof": { argv: [process.execPath, agentPath] } },
          defaultAgent: "scheduled-task-proof",
          defaultPermissions: "approve-reads",
          nonInteractivePermissions: "deny",
        },
        null,
        2,
      )}\n`,
      "utf8",
    );
    await Promise.all([fs.access(acpxCliPath), fs.access(agentPath)]);
    const scriptPath = runtime.resolveTaskScriptPath(env);
    const service = runtime.resolveGatewayService();
    await service.install({
      description: "OpenClaw CI Scheduled Task ACP permission proof",
      env,
      environment: { ACPX_SCHTASKS_PROOF_RESULT_PATH: resultPath },
      programArguments: [
        process.execPath,
        acpxCliPath,
        "exec",
        "trigger configured non-interactive permission denial",
      ],
      stdout,
      workingDirectory,
    });
    installed = true;
    if ((await runtime.execSchtasks(["/Query", "/TN", taskName])).code !== 0) {
      throw new Error(`Scheduled Task ${taskName} was not installed`);
    }
    const launcher = runtime.decodeWindowsLauncherScript({ buffer: await fs.readFile(scriptPath) });
    if (!launcher.includes("< NUL")) {
      throw new Error("Scheduled Task launcher did not redirect stdin from NUL");
    }
    const proof = await waitForProof(resultPath);
    await fs.mkdir(path.dirname(proofPath), { recursive: true });
    await fs.writeFile(
      proofPath,
      `${JSON.stringify(
        {
          elapsedMs: proof.elapsedMs,
          head: actualHead,
          outcome: proof.outcome,
          policy: "deny",
          result: proof.optionId,
          resultStatus: "pass",
        },
        null,
        2,
      )}\n`,
      "utf8",
    );
  } finally {
    try {
      if (installed) {
        await runtime.resolveGatewayService().uninstall({ env, stdout });
      }
    } finally {
      await fs.rm(stateDir, { force: true, recursive: true });
      await fs.rm(rootDir, { force: true, recursive: true });
    }
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await main();
}
