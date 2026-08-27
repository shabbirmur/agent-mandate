import assert from "node:assert/strict";
import { chmod, mkdir, mkdtemp, readFile, readdir, stat, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  parseCliOptions,
  runCli,
  SpawnCommandRunner,
  type CliDependencies,
  type CommandInvocation,
  type CommandResult,
  type CommandRunner,
} from "../src/cli/index.js";

const FIXED_NOW = new Date("2026-08-26T00:00:00.000Z");

class RecordingRunner implements CommandRunner {
  readonly invocations: CommandInvocation[] = [];
  readonly #respond: (invocation: CommandInvocation) => CommandResult | Promise<CommandResult>;

  constructor(respond: (invocation: CommandInvocation) => CommandResult | Promise<CommandResult> = () => result(127)) {
    this.#respond = respond;
  }

  async run(invocation: CommandInvocation): Promise<CommandResult> {
    const copy = { ...invocation, args: [...invocation.args] };
    this.invocations.push(copy);
    return await this.#respond(copy);
  }
}

test("CLI parser accepts the complete product option surface", () => {
  const parsed = parseCliOptions([
    "protect", "github", "--clients", "codex,claude,cursor,vscode,gemini", "--scope", "project",
    "--endpoint", "https://mcp.example.test/mcp", "--dry-run", "--replace", "--json",
  ]);
  assert.equal(parsed.command, "protect");
  assert.equal(parsed.provider, "github");
  assert.deepEqual(parsed.clients, ["codex", "claude", "cursor", "vscode", "gemini"]);
  assert.equal(parsed.scope, "project");
  assert.equal(parsed.endpoint, "https://mcp.example.test/mcp");
  assert.equal(parsed.selfHosted, false);
  assert.equal(parsed.dryRun, true);
  assert.equal(parsed.replace, true);
  assert.equal(parsed.json, true);
  assert.equal(parseCliOptions(["install", "--self-hosted"]).selfHosted, true);
  assert.throws(
    () => parseCliOptions(["install", "--self-hosted", "--endpoint", "https://mcp.example.test/mcp"]),
    /either --self-hosted or --endpoint/,
  );
});

test("CLI parser refuses insecure endpoints, embedded credentials, query secrets, and secret options", () => {
  assert.throws(() => parseCliOptions(["install"]), /No managed service endpoint is published/);
  assert.throws(() => parseCliOptions(["install", "--endpoint", "http://example.test/mcp"]), /HTTPS/);
  assert.throws(() => parseCliOptions(["install", "--endpoint", "https://user:pass@example.test/mcp"]), /credentials/);
  assert.throws(() => parseCliOptions(["install", "--endpoint", "https://example.test/mcp?token=hidden"]), /query strings/);
  assert.throws(() => parseCliOptions(["install", "--token", "hidden"]), /Refusing secret-bearing option/);
  assert.equal(parseCliOptions(["install", "--endpoint", "http://localhost:8787/mcp"]).endpoint, "http://localhost:8787/mcp");
  assert.equal(parseCliOptions(["install", "--endpoint", "http://127.9.8.7:8787/mcp"]).endpoint, "http://127.9.8.7:8787/mcp");
});

test("native client install passes injection-like endpoint text as one literal argv element and writes a private manifest", async () => {
  const fixture = await createFixture();
  const runner = new RecordingRunner((invocation) => {
    if (invocation.args.join(" ") === "mcp get agent-mandate --json") return result(1);
    return result(0);
  });
  const endpoint = "https://mcp.example.test/mcp;$(touch-pwned)";
  const execution = await invoke(["install", "--clients", "codex", "--endpoint", endpoint, "--json"], fixture, runner);
  assert.equal(execution.result.exitCode, 0, execution.stderr.join(""));
  const mutation = runner.invocations.find((invocation) => invocation.mutates);
  assert.ok(mutation);
  assert.equal(mutation.file, "codex");
  assert.deepEqual(mutation.args.slice(0, 4), ["mcp", "add", "agent-mandate", "--url"]);
  assert.equal(mutation.args[4], parseCliOptions(["install", "--endpoint", endpoint]).endpoint);
  assert.equal(runner.invocations.some((invocation) => invocation.file === "sh" || invocation.file === "zsh"), false);

  const manifestStat = await stat(fixture.manifestPath);
  assert.equal(manifestStat.mode & 0o777, 0o600);
  const manifest = JSON.parse(await readFile(fixture.manifestPath, "utf8")) as { installations: Array<Record<string, unknown>> };
  assert.equal(manifest.installations.length, 1);
  assert.equal(manifest.installations[0]?.client, "codex");
});

test("spawn runner never inherits direct GitHub credential environment variables", async () => {
  const fixture = await createFixture();
  const secret = "never-inherit-me";
  const runner = new SpawnCommandRunner({
    ...process.env,
    GH_TOKEN: secret,
    GITHUB_TOKEN: secret,
    GH_ENTERPRISE_TOKEN: secret,
    GITHUB_APP_PRIVATE_KEY: secret,
    AM_SAFE_MARKER: "present",
  }, fixture.cwd);
  const invocation: CommandInvocation = {
    file: process.execPath,
    args: ["-e", "process.stdout.write(JSON.stringify({gh:Boolean(process.env.GH_TOKEN),github:Boolean(process.env.GITHUB_TOKEN),enterprise:Boolean(process.env.GH_ENTERPRISE_TOKEN),appKey:Boolean(process.env.GITHUB_APP_PRIVATE_KEY),safe:process.env.AM_SAFE_MARKER}))"],
    mutates: false,
  };
  const executed = await runner.run(invocation);
  assert.equal(executed.exitCode, 0);
  assert.deepEqual(JSON.parse(executed.stdout), { gh: false, github: false, enterprise: false, appKey: false, safe: "present" });
  assert.equal(executed.stdout.includes(secret), false);
});

test("dry-run performs zero file writes and invokes no mutating client command", async () => {
  const fixture = await createFixture();
  const cursorDir = join(fixture.homeDir, ".cursor");
  const cursorPath = join(cursorDir, "mcp.json");
  await mkdir(cursorDir, { recursive: true, mode: 0o700 });
  const original = `${JSON.stringify({ mcpServers: { other: { url: "https://other.example/mcp" } }, retained: true }, null, 2)}\n`;
  await writeFile(cursorPath, original, { mode: 0o600 });
  const runner = new RecordingRunner();

  const execution = await invoke(["install", "--clients", "cursor", "--self-hosted", "--dry-run"], fixture, runner);
  assert.equal(execution.result.exitCode, 0, execution.stderr.join(""));
  assert.equal(await readFile(cursorPath, "utf8"), original);
  assert.equal(await exists(fixture.manifestPath), false);
  assert.deepEqual((await readdir(cursorDir)).sort(), ["mcp.json"]);
  assert.equal(runner.invocations.some((invocation) => invocation.mutates), false);
});

test("Cursor install preserves unrelated configuration, creates a private backup, and is idempotent", async () => {
  const fixture = await createFixture();
  const cursorDir = join(fixture.homeDir, ".cursor");
  const cursorPath = join(cursorDir, "mcp.json");
  await mkdir(cursorDir, { recursive: true, mode: 0o700 });
  await writeFile(cursorPath, JSON.stringify({ mcpServers: { other: { url: "https://other.example/mcp" } }, retained: { yes: true } }), { mode: 0o644 });

  const first = await invoke(["install", "--clients", "cursor", "--self-hosted"], fixture, new RecordingRunner());
  assert.equal(first.result.exitCode, 0, first.stderr.join(""));
  const installed = JSON.parse(await readFile(cursorPath, "utf8")) as Record<string, unknown>;
  assert.deepEqual(installed.retained, { yes: true });
  assert.deepEqual((installed.mcpServers as Record<string, unknown>).other, { url: "https://other.example/mcp" });
  assert.deepEqual((installed.mcpServers as Record<string, unknown>)["agent-mandate"], { url: "http://127.0.0.1:8787/mcp" });
  const firstEntries = await readdir(cursorDir);
  const backup = firstEntries.find((name) => name.includes(".am-backup-"));
  assert.ok(backup);
  assert.equal((await stat(join(cursorDir, backup))).mode & 0o777, 0o600);
  const bytes = await readFile(cursorPath, "utf8");

  const second = await invoke(["install", "--clients", "cursor", "--self-hosted"], fixture, new RecordingRunner());
  assert.equal(second.result.exitCode, 0, second.stderr.join(""));
  assert.equal(await readFile(cursorPath, "utf8"), bytes);
  assert.equal((await readdir(cursorDir)).filter((name) => name.includes(".am-backup-")).length, 1);
});

test("Cursor malformed configuration is refused without backup or manifest writes", async () => {
  const fixture = await createFixture();
  const cursorDir = join(fixture.homeDir, ".cursor");
  const cursorPath = join(cursorDir, "mcp.json");
  await mkdir(cursorDir, { recursive: true, mode: 0o700 });
  await writeFile(cursorPath, "{ malformed", { mode: 0o600 });

  const execution = await invoke(["install", "--clients", "cursor", "--self-hosted"], fixture, new RecordingRunner());
  assert.equal(execution.result.exitCode, 1);
  assert.match(execution.stderr.join(""), /malformed_config/);
  assert.equal(await readFile(cursorPath, "utf8"), "{ malformed");
  assert.deepEqual(await readdir(cursorDir), ["mcp.json"]);
  assert.equal(await exists(fixture.manifestPath), false);
});

test("Cursor conflicting entry requires replace and replacement preserves unrelated servers", async () => {
  const fixture = await createFixture();
  const cursorDir = join(fixture.homeDir, ".cursor");
  const cursorPath = join(cursorDir, "mcp.json");
  await mkdir(cursorDir, { recursive: true, mode: 0o700 });
  const original = JSON.stringify({ mcpServers: { "agent-mandate": { url: "https://old.example/mcp" }, other: { command: "safe" } } });
  await writeFile(cursorPath, original, { mode: 0o600 });

  const refused = await invoke(["install", "--clients", "cursor", "--self-hosted"], fixture, new RecordingRunner());
  assert.equal(refused.result.exitCode, 1);
  assert.equal(await readFile(cursorPath, "utf8"), original);

  const replaced = await invoke(["install", "--clients", "cursor", "--self-hosted", "--replace"], fixture, new RecordingRunner());
  assert.equal(replaced.result.exitCode, 0, replaced.stderr.join(""));
  const document = JSON.parse(await readFile(cursorPath, "utf8")) as { mcpServers: Record<string, unknown> };
  assert.deepEqual(document.mcpServers.other, { command: "safe" });
  assert.deepEqual(document.mcpServers["agent-mandate"], { url: "http://127.0.0.1:8787/mcp" });
});

test("secret-bearing Agent Mandate config is refused even with replace", async () => {
  const fixture = await createFixture();
  const cursorDir = join(fixture.homeDir, ".cursor");
  const cursorPath = join(cursorDir, "mcp.json");
  await mkdir(cursorDir, { recursive: true, mode: 0o700 });
  const secret = "never-print-this-secret";
  const original = JSON.stringify({ mcpServers: { "agent-mandate": { url: "https://old.example/mcp", headers: { Authorization: secret } } } });
  await writeFile(cursorPath, original, { mode: 0o600 });

  const execution = await invoke(["install", "--clients", "cursor", "--self-hosted", "--replace", "--json"], fixture, new RecordingRunner());
  assert.equal(execution.result.exitCode, 1);
  assert.match(execution.stderr.join(""), /secret_config_refused/);
  assert.equal(execution.stderr.join("").includes(secret), false);
  assert.equal(await readFile(cursorPath, "utf8"), original);
});

test("symlinked Cursor configuration and unsafe manifest permissions are refused", async () => {
  const fixture = await createFixture();
  const cursorDir = join(fixture.homeDir, ".cursor");
  await mkdir(cursorDir, { recursive: true, mode: 0o700 });
  const target = join(fixture.root, "outside.json");
  await writeFile(target, "{}", { mode: 0o600 });
  await symlink(target, join(cursorDir, "mcp.json"));
  const symlinked = await invoke(["install", "--clients", "cursor", "--self-hosted"], fixture, new RecordingRunner());
  assert.equal(symlinked.result.exitCode, 1);
  assert.match(symlinked.stderr.join(""), /unsafe_config_file/);

  const other = await createFixture();
  await mkdir(join(other.homeDir, "state"), { recursive: true, mode: 0o700 });
  await writeFile(other.manifestPath, JSON.stringify({ version: 1, installations: [] }), { mode: 0o644 });
  await chmod(other.manifestPath, 0o644);
  const unsafeManifest = await invoke(["status", "--clients", "cursor"], other, new RecordingRunner());
  assert.equal(unsafeManifest.result.exitCode, 1);
  assert.match(unsafeManifest.stderr.join(""), /unsafe_manifest_permissions/);
});

test("manifest writes refuse an intermediate directory symlink that escapes the home anchor", async () => {
  const fixture = await createFixture();
  const outside = join(fixture.root, "outside-config");
  await mkdir(outside, { mode: 0o700 });
  await symlink(outside, join(fixture.homeDir, "state"));
  fixture.manifestPath = join(fixture.homeDir, "state", "agent-mandate", "installations.json");
  const runner = new RecordingRunner((invocation) => invocation.args.join(" ") === "mcp get agent-mandate --json" ? result(1) : result(0));

  const execution = await invoke(["install", "--clients", "codex", "--self-hosted"], fixture, runner);
  assert.equal(execution.result.exitCode, 1);
  assert.match(execution.stderr.join(""), /unsafe_config_path/);
  assert.equal(await exists(join(outside, "agent-mandate", "installations.json")), false);
  assert.deepEqual(await readdir(outside), []);
  assert.equal(runner.invocations.some((invocation) => invocation.mutates), false);
});

test("uninstall is ownership- and scope-limited", async () => {
  const fixture = await createFixture();
  assert.equal((await invoke(["install", "--clients", "cursor", "--scope", "user", "--self-hosted"], fixture, new RecordingRunner())).result.exitCode, 0);
  assert.equal((await invoke(["install", "--clients", "cursor", "--scope", "project", "--self-hosted"], fixture, new RecordingRunner())).result.exitCode, 0);

  const uninstalled = await invoke(["uninstall", "--clients", "cursor", "--scope", "user"], fixture, new RecordingRunner());
  assert.equal(uninstalled.result.exitCode, 0, uninstalled.stderr.join(""));
  const userConfig = JSON.parse(await readFile(join(fixture.homeDir, ".cursor", "mcp.json"), "utf8")) as { mcpServers: Record<string, unknown> };
  const projectConfig = JSON.parse(await readFile(join(fixture.cwd, ".cursor", "mcp.json"), "utf8")) as { mcpServers: Record<string, unknown> };
  assert.equal(userConfig.mcpServers["agent-mandate"], undefined);
  assert.ok(projectConfig.mcpServers["agent-mandate"]);
  const manifest = JSON.parse(await readFile(fixture.manifestPath, "utf8")) as { installations: Array<{ scope: string }> };
  assert.deepEqual(manifest.installations.map((record) => record.scope), ["project"]);
});

test("uninstall never removes an unowned matching configuration", async () => {
  const fixture = await createFixture();
  const cursorDir = join(fixture.homeDir, ".cursor");
  const cursorPath = join(cursorDir, "mcp.json");
  await mkdir(cursorDir, { recursive: true, mode: 0o700 });
  const original = JSON.stringify({ mcpServers: { "agent-mandate": { url: "http://127.0.0.1:8787/mcp" } } });
  await writeFile(cursorPath, original, { mode: 0o600 });
  const execution = await invoke(["uninstall", "--clients", "cursor"], fixture, new RecordingRunner());
  assert.equal(execution.result.exitCode, 0);
  assert.equal(await readFile(cursorPath, "utf8"), original);
});

test("project scope is rejected before native Codex mutation", async () => {
  const fixture = await createFixture();
  const runner = new RecordingRunner(() => result(0));
  const execution = await invoke(["install", "--clients", "codex", "--scope", "project", "--self-hosted"], fixture, runner);
  assert.equal(execution.result.exitCode, 1);
  assert.match(execution.stderr.join(""), /unsupported_scope/);
  assert.equal(runner.invocations.some((invocation) => invocation.mutates), false);
});

test("native status and uninstall require the exact installer-owned endpoint", async () => {
  const fixture = await createFixture();
  let configuredEndpoint: string | undefined;
  let enabled = true;
  const runner = new RecordingRunner((invocation) => {
    const command = invocation.args.join(" ");
    if (command === "mcp get agent-mandate --json") {
      return configuredEndpoint === undefined ? result(1) : result(0, codexConfiguration(configuredEndpoint, enabled));
    }
    if (command === "mcp remove agent-mandate") {
      configuredEndpoint = undefined;
      return result(0);
    }
    if (invocation.args[0] === "mcp" && invocation.args[1] === "add") {
      configuredEndpoint = invocation.args[4];
      return result(0);
    }
    return result(0);
  });
  assert.equal((await invoke(["install", "--clients", "codex", "--self-hosted"], fixture, runner)).result.exitCode, 0);
  enabled = false;
  const disabled = await invoke(["status", "--clients", "codex", "--json"], fixture, runner);
  assert.equal((JSON.parse(disabled.stdout.join("")) as { clients: Array<{ state: string }> }).clients[0]?.state, "unknown");
  enabled = true;
  configuredEndpoint = "https://drift.example.test/mcp";

  const statusResult = await invoke(["status", "--clients", "codex", "--json"], fixture, runner);
  assert.equal(statusResult.result.exitCode, 0);
  assert.equal((JSON.parse(statusResult.stdout.join("")) as { clients: Array<{ state: string }> }).clients[0]?.state, "conflict");
  const refused = await invoke(["uninstall", "--clients", "codex"], fixture, runner);
  assert.equal(refused.result.exitCode, 1);
  assert.equal(configuredEndpoint, "https://drift.example.test/mcp");

  const explicit = await invoke(["uninstall", "--clients", "codex", "--replace"], fixture, runner);
  assert.equal(explicit.result.exitCode, 0, explicit.stderr.join(""));
  assert.equal(configuredEndpoint, undefined);
});

test("native replacement is refused before mutation when full client state cannot be restored", async () => {
  const fixture = await createFixture();
  const oldEndpoint = "https://old.example.test/mcp";
  const nextEndpoint = "https://new.example.test/mcp";
  const configuredEndpoint: string | undefined = oldEndpoint;
  const runner = new RecordingRunner((invocation) => {
    const command = invocation.args.join(" ");
    if (command === "mcp get agent-mandate --json") {
      return configuredEndpoint === undefined ? result(1) : result(0, codexConfiguration(configuredEndpoint));
    }
    return result(0);
  });

  const execution = await invoke([
    "install", "--clients", "codex", "--endpoint", nextEndpoint, "--replace", "--json",
  ], fixture, runner);
  assert.equal(execution.result.exitCode, 1);
  assert.match(execution.stderr.join(""), /replace_unsupported/);
  assert.equal(configuredEndpoint, oldEndpoint);
  assert.equal(runner.invocations.some((invocation) => invocation.mutates), false);
  assert.equal(await exists(fixture.manifestPath), false);
});

test("a later client failure restores an earlier Cursor replacement", async () => {
  const fixture = await createFixture();
  const oldEndpoint = "https://old.example.test/mcp";
  const nextEndpoint = "https://new.example.test/mcp";
  assert.equal((await invoke([
    "install", "--clients", "cursor", "--endpoint", oldEndpoint,
  ], fixture, new RecordingRunner())).result.exitCode, 0);

  const runner = new RecordingRunner((invocation) => {
    if (invocation.args.join(" ") === "mcp get agent-mandate --json") return result(1);
    if (invocation.file === "codex" && invocation.mutates) return result(1);
    return result(0);
  });
  const execution = await invoke([
    "install", "--clients", "cursor,codex", "--endpoint", nextEndpoint, "--replace", "--json",
  ], fixture, runner);
  assert.equal(execution.result.exitCode, 1);
  assert.match(execution.stderr.join(""), /client_install_failed/);
  const document = JSON.parse(await readFile(join(fixture.homeDir, ".cursor", "mcp.json"), "utf8")) as { mcpServers: Record<string, { url: string }> };
  assert.equal(document.mcpServers["agent-mandate"]?.url, oldEndpoint);
  const manifest = JSON.parse(await readFile(fixture.manifestPath, "utf8")) as { installations: Array<{ endpoint: string }> };
  assert.equal(manifest.installations[0]?.endpoint, oldEndpoint);
});

test("protect github configures and starts Codex OAuth without a shell", async () => {
  const fixture = await createFixture();
  const runner = new RecordingRunner((invocation) => invocation.args.join(" ") === "mcp get agent-mandate --json" ? result(1) : result(0));
  const execution = await invoke(["protect", "github", "--clients", "codex", "--self-hosted"], fixture, runner);
  assert.equal(execution.result.exitCode, 0, execution.stderr.join(""));
  assert.deepEqual(runner.invocations.filter((invocation) => invocation.mutates).map((invocation) => invocation.args), [
    ["mcp", "add", "agent-mandate", "--url", "http://127.0.0.1:8787/mcp"],
    ["mcp", "login", "agent-mandate", "--scopes", "agent-mandate:use"],
  ]);
  assert.equal(runner.invocations.some((invocation) => invocation.file.includes("sh")), false);
});

test("Cursor OAuth prefers the current agent CLI and falls back to cursor-agent", async () => {
  const current = await createFixture();
  const currentRunner = new RecordingRunner((invocation) => {
    if (invocation.file === "agent" && invocation.args.join(" ") === "mcp --help") return result(0);
    return result(0);
  });
  const currentExecution = await invoke(["protect", "github", "--clients", "cursor", "--self-hosted"], current, currentRunner);
  assert.equal(currentExecution.result.exitCode, 0, currentExecution.stderr.join(""));
  assert.equal(currentRunner.invocations.find((invocation) => invocation.mutates)?.file, "agent");

  const legacy = await createFixture();
  const legacyRunner = new RecordingRunner((invocation) => {
    if (invocation.args.join(" ") === "mcp --help") return result(invocation.file === "cursor-agent" ? 0 : 127);
    return result(0);
  });
  const legacyExecution = await invoke(["protect", "github", "--clients", "cursor", "--self-hosted"], legacy, legacyRunner);
  assert.equal(legacyExecution.result.exitCode, 0, legacyExecution.stderr.join(""));
  assert.equal(legacyRunner.invocations.find((invocation) => invocation.mutates)?.file, "cursor-agent");
});

test("doctor separates mediation from enforcement, reports common bypasses, and never prints secret values", async () => {
  const fixture = await createFixture();
  await invoke(["install", "--clients", "cursor", "--self-hosted"], fixture, new RecordingRunner());
  await mkdir(join(fixture.homeDir, ".ssh"), { recursive: true, mode: 0o700 });
  await writeFile(join(fixture.homeDir, ".ssh", "id_ed25519"), "private-material", { mode: 0o600 });
  await writeFile(join(fixture.cwd, ".mcp.json"), JSON.stringify({ mcpServers: { github: { url: "https://api.github.com/mcp" } } }), { mode: 0o600 });
  const secret = "ghp_never_print_this";
  const runner = new RecordingRunner((invocation) => {
    if (invocation.file === "gh") return result(0, "authenticated with hidden account");
    if (invocation.file === "git") return result(0, "osxkeychain");
    return result(127);
  });
  const execution = await invoke(["doctor", "--json"], fixture, runner, { GH_TOKEN: secret, GITHUB_APP_PRIVATE_KEY: secret });
  assert.equal(execution.result.exitCode, 0, execution.stderr.join(""));
  const printed = execution.stdout.join("");
  assert.equal(printed.includes(secret), false);
  assert.equal(printed.includes("private-material"), false);
  const report = JSON.parse(printed) as {
    mediated: { configured: boolean };
    enforced: { status: string; verified: boolean };
    bypassIndicators: Array<{ code: string }>;
  };
  assert.equal(report.mediated.configured, true);
  assert.equal(report.enforced.status, "bypass_detected");
  assert.equal(report.enforced.verified, false);
  assert.deepEqual(new Set(report.bypassIndicators.map((indicator) => indicator.code)), new Set([
    "environment_token", "gh_authenticated", "credential_helper", "ssh_private_key", "direct_github_mcp",
  ]));
});

test("doctor never upgrades a clean common-indicator scan into a complete enforcement claim", async () => {
  const fixture = await createFixture();
  const execution = await invoke(["doctor", "--json"], fixture, new RecordingRunner(() => result(1)));
  assert.equal(execution.result.exitCode, 0);
  const report = JSON.parse(execution.stdout.join("")) as { enforced: { status: string; verified: boolean }; completeness: string };
  assert.equal(report.enforced.status, "not_verified");
  assert.equal(report.enforced.verified, false);
  assert.equal(report.completeness, "common-indicators-only");
});

test("doctor does not claim mediation from a stale ownership manifest", async () => {
  const fixture = await createFixture();
  assert.equal((await invoke(["install", "--clients", "cursor", "--self-hosted"], fixture, new RecordingRunner())).result.exitCode, 0);
  await writeFile(
    join(fixture.homeDir, ".cursor", "mcp.json"),
    JSON.stringify({ mcpServers: { "agent-mandate": { url: "https://drift.example.test/mcp" } } }),
    { mode: 0o600 },
  );
  const execution = await invoke(["doctor", "--json"], fixture, new RecordingRunner(() => result(1)));
  assert.equal(execution.result.exitCode, 0);
  const report = JSON.parse(execution.stdout.join("")) as { mediated: { configured: boolean; clients: string[] } };
  assert.equal(report.mediated.configured, false);
  assert.deepEqual(report.mediated.clients, []);
});

interface Fixture {
  root: string;
  homeDir: string;
  cwd: string;
  manifestPath: string;
}

async function createFixture(): Promise<Fixture> {
  const root = await mkdtemp(join(tmpdir(), "agent-mandate-cli-"));
  const homeDir = join(root, "home");
  const cwd = join(root, "workspace");
  await mkdir(homeDir, { mode: 0o700 });
  await mkdir(cwd, { mode: 0o700 });
  return { root, homeDir, cwd, manifestPath: join(homeDir, "state", "installations.json") };
}

async function invoke(
  argv: string[],
  fixture: Fixture,
  runner: CommandRunner,
  environment: NodeJS.ProcessEnv = {},
): Promise<{ result: Awaited<ReturnType<typeof runCli>>; stdout: string[]; stderr: string[] }> {
  const stdout: string[] = [];
  const stderr: string[] = [];
  const dependencies: CliDependencies = {
    cwd: fixture.cwd,
    homeDir: fixture.homeDir,
    manifestPath: fixture.manifestPath,
    env: environment,
    runner,
    now: () => new Date(FIXED_NOW),
    stdout: (text) => stdout.push(text),
    stderr: (text) => stderr.push(text),
  };
  return { result: await runCli(argv, dependencies), stdout, stderr };
}

function result(exitCode: number, stdout = "", stderr = ""): CommandResult {
  return { exitCode, stdout, stderr };
}

function codexConfiguration(endpoint: string, enabled = true): string {
  return JSON.stringify({
    name: "agent-mandate",
    enabled,
    disabled_reason: null,
    transport: {
      type: "streamable_http",
      url: endpoint,
      bearer_token_env_var: null,
      http_headers: null,
      env_http_headers: null,
      http_headers_helper: null,
    },
    enabled_tools: null,
    disabled_tools: null,
    startup_timeout_sec: null,
    tool_timeout_sec: null,
  });
}

async function exists(path: string): Promise<boolean> {
  try {
    await stat(path);
    return true;
  } catch {
    return false;
  }
}
