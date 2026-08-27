import { join } from "node:path";
import {
  atomicWriteJson,
  containsSecretMaterial,
  isPlainRecord,
  readSafeJson,
} from "./files.js";
import { validateEndpoint } from "./options.js";
import {
  CliError,
  type AdapterActionResult,
  type AdapterContext,
  type ClientAdapter,
  type ClientId,
  type ClientStatus,
  type InstallCliOptions,
  type CommandInvocation,
  type InstallationRecord,
  type InstallScope,
} from "./types.js";

const SERVER_NAME = "agent-mandate";

interface NativeAdapterDefinition {
  id: Exclude<ClientId, "cursor">;
  executable: string;
  projectScope: boolean;
  install(scope: InstallScope, endpoint: string): string[];
  remove?(scope: InstallScope): string[];
  status?(scope: InstallScope): string[];
  statusEndpoint?(stdout: string, scope: InstallScope): string | undefined;
  /** False when a list command cannot prove which configuration scope supplied an entry. */
  statusScopeVerifiable?: boolean;
  connect?(): string[];
  manualConnect: string;
}

class NativeClientAdapter implements ClientAdapter {
  readonly id: NativeAdapterDefinition["id"];
  readonly #definition: NativeAdapterDefinition;

  constructor(definition: NativeAdapterDefinition) {
    this.id = definition.id;
    this.#definition = definition;
  }

  supportsScope(scope: InstallScope): boolean {
    return scope === "user" || this.#definition.projectScope;
  }

  async detect(context: AdapterContext): Promise<boolean> {
    const result = await context.runner.run(readOnly(this.#definition.executable, ["--version"]));
    return result.exitCode === 0;
  }

  async status(context: AdapterContext, scope: InstallScope, tracked?: InstallationRecord): Promise<ClientStatus> {
    if (!this.supportsScope(scope)) return status(this.id, scope, tracked !== undefined, "conflict", "This client has no safe native command for the requested scope.");
    const args = this.#definition.status?.(scope);
    if (!args) {
      return status(this.id, scope, tracked !== undefined, tracked ? "unknown" : "missing", tracked
        ? "Installation is owned, but this client has no non-mutating get command."
        : "No owned installation is recorded.");
    }
    const result = await context.runner.run(readOnly(this.#definition.executable, args));
    if (result.exitCode !== 0) {
      return status(this.id, scope, tracked !== undefined, "missing", "Agent Mandate is not present in the client configuration.");
    }
    const endpoint = this.#definition.statusEndpoint?.(result.stdout, scope);
    if (endpoint === undefined) {
      return status(this.id, scope, tracked !== undefined, "unknown", "The client entry exists, but its exact secret-free endpoint could not be verified.");
    }
    if (tracked && this.#definition.statusScopeVerifiable === false) {
      return status(this.id, scope, true, "unknown", "The client reports the expected endpoint, but does not identify its configuration scope.", endpoint);
    }
    if (tracked && endpoint !== tracked.endpoint) {
      return status(this.id, scope, true, "conflict", "The client endpoint differs from the installer-owned endpoint.", endpoint);
    }
    return status(this.id, scope, tracked !== undefined, "configured", tracked
      ? "The exact installer-owned endpoint is present in the client configuration."
      : "An unowned Agent Mandate endpoint is present in the client configuration.", endpoint);
  }

  async install(context: AdapterContext, options: InstallCliOptions, tracked?: InstallationRecord): Promise<AdapterActionResult> {
    if (!this.supportsScope(options.scope)) throw new CliError("unsupported_scope", `${this.id} does not expose a safe native command for project-scoped MCP installation.`);
    const current = await this.status(context, options.scope, tracked);
    if (current.state === "unknown") {
      throw new CliError("ownership_unverifiable", `${this.id} does not expose enough information to replace this entry safely.`);
    }
    const present = current.state === "configured" || current.state === "conflict";
    if (present && !tracked && !options.replace) {
      throw new CliError("config_conflict", `${this.id} already has an unowned Agent Mandate entry; use --replace to take ownership explicitly.`);
    }
    if (current.state === "configured" && tracked?.endpoint === options.endpoint) {
      return { changed: false, detail: "Already configured with the owned endpoint." };
    }
    if (present && !options.replace) {
      throw new CliError("config_conflict", `${this.id} has a conflicting Agent Mandate entry; use --replace explicitly.`);
    }
    if (present) {
      throw new CliError(
        "replace_unsupported",
        `${this.id} cannot preserve all native client and OAuth state during replacement; remove it explicitly before installing the new endpoint.`,
      );
    }

    if (context.dryRun) return { changed: true, detail: "Would configure the client through its native CLI." };
    await requireSuccess(context, mutate(this.#definition.executable, this.#definition.install(options.scope, options.endpoint)), "client_install_failed");
    return { changed: true, detail: "Configured through the client's native MCP command." };
  }

  async connect(context: AdapterContext, _record: InstallationRecord): Promise<AdapterActionResult> {
    const args = this.#definition.connect?.();
    if (!args) return { changed: false, detail: "Authentication must be completed in the client.", manualAction: this.#definition.manualConnect };
    if (context.dryRun) return { changed: true, detail: "Would start the client's MCP OAuth flow." };
    await requireSuccess(context, mutate(this.#definition.executable, args), "client_connect_failed");
    return { changed: true, detail: "Started the client's MCP OAuth flow." };
  }

  async uninstall(context: AdapterContext, record: InstallationRecord): Promise<AdapterActionResult> {
    const args = this.#definition.remove?.(record.scope);
    if (!args) {
      return {
        changed: false,
        detail: "This client has no safe native MCP removal command; ownership was retained.",
        manualAction: `Remove ${SERVER_NAME} from ${this.id}, then run am uninstall again.`,
      };
    }
    const current = await this.status(context, record.scope, record);
    if (current.state === "missing") return { changed: false, ownershipReleased: true, detail: "Client entry is already absent." };
    if (current.state === "unknown") {
      return {
        changed: false,
        detail: "The exact owned endpoint could not be verified, so automatic removal was refused.",
        manualAction: `Verify and remove ${SERVER_NAME} from ${this.id} manually, then run am uninstall again.`,
      };
    }
    if (current.state === "conflict" && !context.replace) {
      throw new CliError("config_conflict", `${this.id}'s Agent Mandate endpoint changed outside this installer; use --replace to remove it explicitly.`);
    }
    if (context.dryRun) return { changed: true, ownershipReleased: true, detail: "Would remove the owned client entry." };
    await requireSuccess(context, mutate(this.#definition.executable, args), "client_remove_failed");
    return { changed: true, ownershipReleased: true, detail: "Removed the owned client entry." };
  }
}

class CursorClientAdapter implements ClientAdapter {
  readonly id = "cursor" as const;

  supportsScope(_scope: InstallScope): boolean {
    return true;
  }

  async detect(context: AdapterContext): Promise<boolean> {
    if (await this.#executable(context) !== undefined) return true;
    const path = cursorPath(context, "user");
    return (await readSafeJson(path, context.homeDir).catch(() => undefined))?.exists === true;
  }

  async status(context: AdapterContext, scope: InstallScope, tracked?: InstallationRecord): Promise<ClientStatus> {
    const path = cursorPath(context, scope, tracked?.projectRoot);
    const document = await readSafeJson(path, scope === "user" ? context.homeDir : (tracked?.projectRoot ?? context.cwd));
    if (!document.exists) return status(this.id, scope, tracked !== undefined, "missing", "Cursor MCP configuration is absent.");
    const servers = document.value.mcpServers;
    if (servers === undefined) return status(this.id, scope, tracked !== undefined, "missing", "Cursor has no MCP server map.");
    if (!isPlainRecord(servers)) throw new CliError("malformed_config", "Cursor mcpServers must be a JSON object.");
    const entry = servers[SERVER_NAME];
    if (entry === undefined) return status(this.id, scope, tracked !== undefined, "missing", "Cursor has no Agent Mandate entry.");
    if (!isPlainRecord(entry)) return status(this.id, scope, tracked !== undefined, "conflict", "Cursor's Agent Mandate entry is malformed.");
    refuseSecretEntry(entry);
    const keys = Object.keys(entry);
    const expected = tracked?.endpoint;
    if (keys.length === 1 && typeof entry.url === "string" && (!expected || entry.url === expected)) {
      const endpoint = safeStatusEndpoint(entry.url);
      if (endpoint !== undefined) return status(this.id, scope, tracked !== undefined, "configured", "Cursor is configured with a secret-free remote endpoint.", endpoint);
    }
    return status(
      this.id,
      scope,
      tracked !== undefined,
      "conflict",
      "Cursor has a conflicting Agent Mandate entry.",
      typeof entry.url === "string" ? safeStatusEndpoint(entry.url) : undefined,
    );
  }

  async install(context: AdapterContext, options: InstallCliOptions, tracked?: InstallationRecord): Promise<AdapterActionResult> {
    const path = cursorPath(context, options.scope);
    const base = options.scope === "user" ? context.homeDir : context.cwd;
    const document = await readSafeJson(path, base);
    const root = structuredClone(document.value);
    const originalRoot = structuredClone(document.value);
    const serversValue = root.mcpServers;
    if (serversValue !== undefined && !isPlainRecord(serversValue)) throw new CliError("malformed_config", "Cursor mcpServers must be a JSON object.");
    const servers = isPlainRecord(serversValue) ? structuredClone(serversValue) : {};
    const existing = servers[SERVER_NAME];
    if (existing !== undefined) {
      if (!isPlainRecord(existing)) throw new CliError("config_conflict", "Cursor's Agent Mandate entry is malformed; use a manual recovery rather than overwriting it.");
      refuseSecretEntry(existing);
      const exact = Object.keys(existing).length === 1 && existing.url === options.endpoint;
      if (exact && tracked) return { changed: false, detail: "Already configured with the owned endpoint.", configPath: path };
      if (!options.replace) throw new CliError("config_conflict", "Cursor already has an unowned or conflicting Agent Mandate entry; use --replace explicitly.");
    }
    servers[SERVER_NAME] = { url: options.endpoint };
    root.mcpServers = servers;
    const written = await atomicWriteJson(path, base, root, {
      dryRun: context.dryRun,
      backup: document.exists,
      privateMode: false,
      now: context.now,
    });
    return {
      changed: written.changed,
      detail: context.dryRun ? "Would atomically merge the Cursor configuration." : "Atomically merged the Cursor configuration.",
      configPath: path,
      ...(written.backupPath ? { backupPath: written.backupPath } : {}),
      ...(existing === undefined || context.dryRun || !written.changed ? {} : {
        rollback: async () => {
          const current = await readSafeJson(path, base);
          const currentServers = current.value.mcpServers;
          const currentEntry = isPlainRecord(currentServers) ? currentServers[SERVER_NAME] : undefined;
          if (!isPlainRecord(currentEntry) || Object.keys(currentEntry).length !== 1 || currentEntry.url !== options.endpoint) {
            throw new CliError("installation_rollback_failed", "Cursor changed again before its prior configuration could be restored.");
          }
          await atomicWriteJson(path, base, originalRoot, {
            dryRun: false,
            backup: false,
            privateMode: false,
            now: context.now,
          });
        },
      }),
    };
  }

  async connect(context: AdapterContext, _record: InstallationRecord): Promise<AdapterActionResult> {
    if (context.dryRun) return { changed: true, detail: "Would start Cursor's MCP OAuth login." };
    const executable = await this.#executable(context);
    if (executable === undefined) {
      return { changed: false, detail: "Cursor CLI login was unavailable.", manualAction: "Authenticate Agent Mandate from Cursor's MCP settings." };
    }
    const result = await context.runner.run(mutate(executable, ["mcp", "login", SERVER_NAME]));
    if (result.exitCode !== 0) {
      return { changed: false, detail: "Cursor CLI login was unavailable.", manualAction: "Authenticate Agent Mandate from Cursor's MCP settings." };
    }
    return { changed: true, detail: "Started Cursor's MCP OAuth login." };
  }

  async #executable(context: AdapterContext): Promise<"agent" | "cursor-agent" | undefined> {
    for (const executable of ["agent", "cursor-agent"] as const) {
      const result = await context.runner.run(readOnly(executable, ["mcp", "--help"]));
      if (result.exitCode === 0) return executable;
    }
    return undefined;
  }

  async uninstall(context: AdapterContext, record: InstallationRecord): Promise<AdapterActionResult> {
    const base = record.scope === "user" ? context.homeDir : (record.projectRoot ?? context.cwd);
    const path = cursorPath(context, record.scope, record.projectRoot);
    if (record.configPath && record.configPath !== path) throw new CliError("manifest_path_mismatch", "Owned Cursor configuration path does not match the current scope.");
    const document = await readSafeJson(path, base);
    if (!document.exists) return { changed: false, ownershipReleased: true, detail: "Cursor entry is already absent.", configPath: path };
    const root = structuredClone(document.value);
    const servers = root.mcpServers;
    if (!isPlainRecord(servers)) throw new CliError("malformed_config", "Cursor mcpServers must be a JSON object.");
    const entry = servers[SERVER_NAME];
    if (entry === undefined) return { changed: false, ownershipReleased: true, detail: "Cursor entry is already absent.", configPath: path };
    if (!isPlainRecord(entry)) throw new CliError("config_conflict", "Cursor's Agent Mandate entry is malformed.");
    refuseSecretEntry(entry);
    const exactOwnedEntry = Object.keys(entry).length === 1 && entry.url === record.endpoint;
    if (!exactOwnedEntry && !context.replace) {
      throw new CliError("config_conflict", "Cursor's Agent Mandate endpoint changed outside this installer; use --replace to remove it explicitly.");
    }
    delete servers[SERVER_NAME];
    root.mcpServers = servers;
    const written = await atomicWriteJson(path, base, root, {
      dryRun: context.dryRun,
      backup: true,
      privateMode: false,
      now: context.now,
    });
    return {
      changed: written.changed,
      ownershipReleased: true,
      detail: context.dryRun ? "Would remove the owned Cursor entry." : "Removed the owned Cursor entry.",
      configPath: path,
      ...(written.backupPath ? { backupPath: written.backupPath } : {}),
    };
  }
}

export function createClientAdapters(): ReadonlyMap<ClientId, ClientAdapter> {
  const adapters: ClientAdapter[] = [
    new NativeClientAdapter({
      id: "codex",
      executable: "codex",
      projectScope: false,
      install: (_scope, endpoint) => ["mcp", "add", SERVER_NAME, "--url", endpoint],
      remove: () => ["mcp", "remove", SERVER_NAME],
      status: () => ["mcp", "get", SERVER_NAME, "--json"],
      statusEndpoint: codexStatusEndpoint,
      connect: () => ["mcp", "login", SERVER_NAME, "--scopes", "agent-mandate:use"],
      manualConnect: "Run `codex mcp login agent-mandate --scopes agent-mandate:use`.",
    }),
    new NativeClientAdapter({
      id: "claude",
      executable: "claude",
      projectScope: true,
      install: (scope, endpoint) => ["mcp", "add", "--transport", "http", "--scope", scope, SERVER_NAME, endpoint],
      remove: (scope) => ["mcp", "remove", "--scope", scope, SERVER_NAME],
      status: () => ["mcp", "get", SERVER_NAME],
      statusEndpoint: claudeStatusEndpoint,
      manualConnect: "Open Claude Code and use `/mcp` to authenticate Agent Mandate.",
    }),
    new CursorClientAdapter(),
    new NativeClientAdapter({
      id: "vscode",
      executable: "code",
      projectScope: false,
      install: (_scope, endpoint) => ["--add-mcp", JSON.stringify({ name: SERVER_NAME, type: "http", url: endpoint })],
      manualConnect: "Open VS Code MCP settings and authenticate Agent Mandate.",
    }),
    new NativeClientAdapter({
      id: "gemini",
      executable: "gemini",
      projectScope: true,
      install: (scope, endpoint) => ["mcp", "add", SERVER_NAME, endpoint, "--transport", "http", "--scope", scope],
      remove: (scope) => ["mcp", "remove", SERVER_NAME, "--scope", scope],
      status: () => ["mcp", "list"],
      statusEndpoint: geminiStatusEndpoint,
      statusScopeVerifiable: false,
      manualConnect: "Open Gemini CLI and run `/mcp auth agent-mandate`.",
    }),
  ];
  return new Map(adapters.map((adapter) => [adapter.id, adapter]));
}

function cursorPath(context: AdapterContext, scope: InstallScope, projectRoot?: string): string {
  return scope === "user"
    ? join(context.homeDir, ".cursor", "mcp.json")
    : join(projectRoot ?? context.cwd, ".cursor", "mcp.json");
}

function refuseSecretEntry(entry: Record<string, unknown>): void {
  if (containsSecretMaterial(entry)) {
    throw new CliError("secret_config_refused", "Agent Mandate's client entry contains secret-bearing fields; remove them manually before continuing.");
  }
}

function status(
  client: ClientId,
  scope: InstallScope,
  tracked: boolean,
  state: ClientStatus["state"],
  detail: string,
  endpoint?: string,
): ClientStatus {
  return { client, scope, tracked, state, detail, ...(endpoint === undefined ? {} : { endpoint }) };
}

function readOnly(file: string, args: string[]): CommandInvocation {
  return { file, args: [...args], mutates: false, timeoutMs: 10_000 };
}

function mutate(file: string, args: string[]): CommandInvocation {
  return { file, args: [...args], mutates: true, timeoutMs: 30_000 };
}

async function requireSuccess(context: AdapterContext, invocation: CommandInvocation, code: string): Promise<void> {
  const result = await context.runner.run(invocation);
  if (result.exitCode !== 0) throw new CliError(code, "Client command failed without changing Agent Mandate's security claims.");
}

function codexStatusEndpoint(stdout: string): string | undefined {
  try {
    const value = JSON.parse(stdout) as unknown;
    if (!isPlainRecord(value) || value.name !== SERVER_NAME || value.enabled !== true || !isPlainRecord(value.transport)) return undefined;
    const transport = value.transport;
    const topLevelKeys = new Set([
      "name", "enabled", "disabled_reason", "transport", "enabled_tools", "disabled_tools", "startup_timeout_sec", "tool_timeout_sec",
    ]);
    const transportKeys = new Set([
      "type", "url", "bearer_token_env_var", "http_headers", "env_http_headers", "http_headers_helper",
    ]);
    if (
      Object.keys(value).some((key) => !topLevelKeys.has(key))
      || Object.keys(transport).some((key) => !transportKeys.has(key))
      || value.disabled_reason !== null
      || value.enabled_tools !== null
      || value.disabled_tools !== null
      || value.startup_timeout_sec !== null
      || value.tool_timeout_sec !== null
      || transport.type !== "streamable_http"
      || transport.bearer_token_env_var !== null
      || transport.http_headers !== null
      || transport.env_http_headers !== null
      || transport.http_headers_helper !== null
      || typeof transport.url !== "string"
    ) return undefined;
    return safeStatusEndpoint(transport.url);
  } catch {
    return undefined;
  }
}

function claudeStatusEndpoint(stdout: string, scope: InstallScope): string | undefined {
  const plain = stripAnsi(stdout);
  const expectedScope = scope === "user" ? "User config" : "Project config";
  if (!new RegExp(`^\\s*Scope:\\s*${expectedScope}\\b`, "im").test(plain)) return undefined;
  const allowedLabels = new Set(["Scope", "Status", "Type", "URL"]);
  for (const line of plain.split(/\r?\n/u)) {
    const label = line.match(/^\s{2,}([A-Za-z][A-Za-z ]*):/u)?.[1];
    if (label !== undefined && !allowedLabels.has(label)) return undefined;
  }
  if (!/^\s*Type:\s*http\s*$/imu.test(plain)) return undefined;
  const match = plain.match(/^\s*URL:\s*(\S+)\s*$/imu);
  return match?.[1] === undefined ? undefined : safeStatusEndpoint(match[1]);
}

function geminiStatusEndpoint(stdout: string): string | undefined {
  const plain = stripAnsi(stdout);
  const line = plain.split(/\r?\n/u).find((candidate) => new RegExp(`(?:^|\\s)${SERVER_NAME}:`, "u").test(candidate));
  if (line === undefined || !/\(http\)/iu.test(line)) return undefined;
  const urls = line.match(/https?:\/\/[^\s)]+/giu) ?? [];
  return urls.length === 1 ? safeStatusEndpoint(urls[0]!) : undefined;
}

function safeStatusEndpoint(value: string): string | undefined {
  try {
    return validateEndpoint(value);
  } catch {
    return undefined;
  }
}

function stripAnsi(value: string): string {
  return value.replace(/\u001b\[[0-?]*[ -/]*[@-~]/gu, "");
}
