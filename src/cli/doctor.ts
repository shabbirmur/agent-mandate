import { lstat } from "node:fs/promises";
import { join } from "node:path";
import { createClientAdapters } from "./clients.js";
import { isPlainRecord, readSafeTextForAudit, type ManifestStore } from "./files.js";
import type { AdapterContext, ClientId, CommandInvocation } from "./types.js";

const GITHUB_CREDENTIAL_ENV = /^(?:GH|GITHUB)(?:_[A-Z0-9]+)*_(?:TOKEN|SECRET|PASSWORD|PRIVATE_KEY)(?:_FILE)?$/u;

export interface BypassIndicator {
  code: "environment_token" | "gh_authenticated" | "credential_helper" | "ssh_private_key" | "direct_github_mcp" | "config_uninspectable";
  severity: "blocking" | "warning";
  detail: string;
}

export interface DoctorReport {
  mediated: {
    configured: boolean;
    clients: ClientId[];
    detail: string;
  };
  enforced: {
    status: "bypass_detected" | "not_verified";
    verified: false;
    detail: string;
  };
  bypassIndicators: BypassIndicator[];
  completeness: "common-indicators-only";
}

export async function runDoctor(context: AdapterContext, manifestStore: ManifestStore): Promise<DoctorReport> {
  const manifest = await manifestStore.read();
  const indicators: BypassIndicator[] = [];
  const adapters = createClientAdapters();

  const environmentNames = Object.keys(context.env)
    .filter((name) => GITHUB_CREDENTIAL_ENV.test(name) && Boolean(context.env[name]))
    .sort();
  if (environmentNames.length > 0) {
    indicators.push({
      code: "environment_token",
      severity: "blocking",
      detail: `A direct GitHub token is present in the environment (${environmentNames.join(", ")}); its value was not read or printed.`,
    });
  }

  const gh = await context.runner.run(readOnly("gh", ["auth", "status", "--hostname", "github.com"]));
  if (gh.exitCode === 0) {
    indicators.push({
      code: "gh_authenticated",
      severity: "blocking",
      detail: "GitHub CLI reports an authenticated session that may bypass Agent Mandate.",
    });
  }

  const helper = await context.runner.run(readOnly("git", ["config", "--global", "--get-all", "credential.helper"]));
  if (helper.exitCode === 0 && helper.stdout.trim().length > 0) {
    indicators.push({
      code: "credential_helper",
      severity: "warning",
      detail: "A global Git credential helper is configured; the scan did not inspect stored credentials.",
    });
  }

  if (await hasCommonSshPrivateKey(context.homeDir)) {
    indicators.push({
      code: "ssh_private_key",
      severity: "warning",
      detail: "A common SSH private-key filename exists; the scan cannot determine whether GitHub accepts it.",
    });
  }

  const configScan = await scanMcpConfigs(context);
  if (configScan.directGitHub) {
    indicators.push({
      code: "direct_github_mcp",
      severity: "blocking",
      detail: "Another MCP configuration appears to expose GitHub directly outside Agent Mandate.",
    });
  }
  const exactClients = new Set<ClientId>();
  let exactRecordCount = 0;
  let ownedConfigurationUnverifiable = false;
  for (const record of manifest.installations) {
    const adapter = adapters.get(record.client);
    if (adapter === undefined) {
      ownedConfigurationUnverifiable = true;
      continue;
    }
    try {
      const clientStatus = await adapter.status(context, record.scope, record);
      if (clientStatus.state === "configured" && clientStatus.endpoint === record.endpoint) {
        exactClients.add(record.client);
        exactRecordCount += 1;
      } else if (clientStatus.state !== "missing") {
        ownedConfigurationUnverifiable = true;
      }
    } catch {
      ownedConfigurationUnverifiable = true;
    }
  }
  if (configScan.uninspectable || ownedConfigurationUnverifiable) {
    indicators.push({
      code: "config_uninspectable",
      severity: "warning",
      detail: "At least one known or installer-owned MCP configuration could not be verified safely.",
    });
  }

  const clients = [...exactClients].sort();
  const staleOwnership = manifest.installations.length > exactRecordCount;
  const blocking = indicators.some((indicator) => indicator.severity === "blocking");
  return {
    mediated: {
      configured: clients.length > 0,
      clients,
      detail: clients.length > 0
        ? staleOwnership
          ? "At least one exact live Agent Mandate endpoint is verified; another ownership record is stale or unverifiable."
          : "At least one exact live client endpoint is verified to route Agent Mandate tools through the mediated service."
        : manifest.installations.length > 0
          ? "Installer ownership records exist, but no exact live Agent Mandate endpoint could be verified."
          : "No installer-owned Agent Mandate client configuration is recorded.",
    },
    enforced: {
      status: blocking ? "bypass_detected" : "not_verified",
      verified: false,
      detail: blocking
        ? "A common direct-access bypass was detected; Agent Mandate is not the exclusive route."
        : "No common blocking indicator was detected, but this local scan cannot prove process or network isolation.",
    },
    bypassIndicators: indicators,
    completeness: "common-indicators-only",
  };
}

async function hasCommonSshPrivateKey(homeDir: string): Promise<boolean> {
  const names = ["id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"];
  for (const name of names) {
    try {
      const stat = await lstat(join(homeDir, ".ssh", name));
      if (stat.isFile() && !stat.isSymbolicLink()) return true;
    } catch (error) {
      if (!isNodeError(error) || error.code !== "ENOENT") return false;
    }
  }
  return false;
}

async function scanMcpConfigs(context: AdapterContext): Promise<{ directGitHub: boolean; uninspectable: boolean }> {
  const paths = [...new Set([
    join(context.homeDir, ".cursor", "mcp.json"),
    join(context.cwd, ".cursor", "mcp.json"),
    join(context.cwd, ".mcp.json"),
    join(context.homeDir, ".gemini", "settings.json"),
    join(context.cwd, ".gemini", "settings.json"),
    join(context.cwd, ".vscode", "mcp.json"),
    join(context.homeDir, ".copilot", "mcp-config.json"),
    join(context.homeDir, ".claude.json"),
    join(context.homeDir, ".codex", "config.toml"),
    join(context.cwd, ".codex", "config.toml"),
  ])];
  let directGitHub = false;
  let uninspectable = false;
  for (const path of paths) {
    const text = await readSafeTextForAudit(path);
    if (text === undefined) continue;
    if (path.endsWith(".toml")) {
      if (tomlContainsDirectGitHubMcp(text)) directGitHub = true;
      continue;
    }
    try {
      const parsed: unknown = JSON.parse(text);
      if (jsonContainsDirectGitHubMcp(parsed)) directGitHub = true;
    } catch {
      uninspectable = true;
    }
  }
  return { directGitHub, uninspectable };
}

function jsonContainsDirectGitHubMcp(value: unknown): boolean {
  if (Array.isArray(value)) return value.some(jsonContainsDirectGitHubMcp);
  if (!isPlainRecord(value)) return false;
  for (const [key, nested] of Object.entries(value)) {
    if ((key === "mcpServers" || key === "servers") && isPlainRecord(nested)) {
      for (const [name, definition] of Object.entries(nested)) {
        if (name === "agent-mandate") continue;
        if (name.toLowerCase().includes("github") || safeSerialized(definition).includes("github")) return true;
      }
    }
    if (jsonContainsDirectGitHubMcp(nested)) return true;
  }
  return false;
}

function tomlContainsDirectGitHubMcp(text: string): boolean {
  let currentServer = "";
  for (const line of text.split(/\r?\n/)) {
    const section = line.match(/^\s*\[mcp_servers\.([A-Za-z0-9_-]+)(?:\]|\.)/);
    if (section) currentServer = section[1]!.toLowerCase();
    if (currentServer && currentServer !== "agent-mandate" && (currentServer.includes("github") || /github/i.test(line))) return true;
  }
  return false;
}

function safeSerialized(value: unknown): string {
  try {
    return JSON.stringify(value).toLowerCase();
  } catch {
    return "";
  }
}

function readOnly(file: string, args: string[]): CommandInvocation {
  return { file, args, mutates: false, timeoutMs: 10_000 };
}

function isNodeError(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error && "code" in error;
}
