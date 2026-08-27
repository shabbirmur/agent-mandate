import { spawn } from "node:child_process";
import type { CommandInvocation, CommandResult, CommandRunner } from "./types.js";

const MAX_CAPTURE_BYTES = 65_536;
const GITHUB_CREDENTIAL_ENV = /^(?:GH|GITHUB)(?:_[A-Z0-9]+)*_(?:TOKEN|SECRET|PASSWORD|PRIVATE_KEY)(?:_FILE)?$/u;

export class SpawnCommandRunner implements CommandRunner {
  readonly #environment: NodeJS.ProcessEnv;
  readonly #cwd: string;

  constructor(environment: NodeJS.ProcessEnv, cwd: string) {
    this.#environment = { ...environment };
    // Provider credentials must never be inherited by installer or diagnostic
    // subprocesses. Doctor reports only that these names were present.
    for (const name of Object.keys(this.#environment)) {
      if (GITHUB_CREDENTIAL_ENV.test(name)) delete this.#environment[name];
    }
    this.#cwd = cwd;
  }

  async run(invocation: CommandInvocation): Promise<CommandResult> {
    return await new Promise((resolve, reject) => {
      const child = spawn(invocation.file, [...invocation.args], {
        cwd: this.#cwd,
        env: this.#environment,
        shell: false,
        stdio: ["ignore", "pipe", "pipe"],
      });
      const stdout: Buffer[] = [];
      const stderr: Buffer[] = [];
      let stdoutBytes = 0;
      let stderrBytes = 0;
      let settled = false;
      let timedOut = false;

      const timeout = setTimeout(() => {
        timedOut = true;
        child.kill("SIGTERM");
        setTimeout(() => child.kill("SIGKILL"), 1_000).unref();
      }, invocation.timeoutMs ?? 10_000);
      timeout.unref();

      child.stdout?.on("data", (chunk: Buffer) => {
        if (stdoutBytes >= MAX_CAPTURE_BYTES) return;
        const remaining = MAX_CAPTURE_BYTES - stdoutBytes;
        const accepted = chunk.subarray(0, remaining);
        stdout.push(accepted);
        stdoutBytes += accepted.length;
      });
      child.stderr?.on("data", (chunk: Buffer) => {
        if (stderrBytes >= MAX_CAPTURE_BYTES) return;
        const remaining = MAX_CAPTURE_BYTES - stderrBytes;
        const accepted = chunk.subarray(0, remaining);
        stderr.push(accepted);
        stderrBytes += accepted.length;
      });
      child.once("error", (error) => {
        if (settled) return;
        settled = true;
        clearTimeout(timeout);
        if (isNodeError(error) && error.code === "ENOENT") {
          resolve({ exitCode: 127, stdout: "", stderr: "" });
          return;
        }
        reject(error);
      });
      child.once("close", (code) => {
        if (settled) return;
        settled = true;
        clearTimeout(timeout);
        resolve({
          exitCode: timedOut ? 124 : (code ?? 1),
          stdout: Buffer.concat(stdout).toString("utf8"),
          stderr: Buffer.concat(stderr).toString("utf8"),
        });
      });
    });
  }
}

function isNodeError(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error && "code" in error;
}
