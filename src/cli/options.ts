import { isIP } from "node:net";
import { CLIENT_IDS, CliError, type ClientId, type CliOptions, type InstallScope } from "./types.js";

export const DEFAULT_SELF_HOSTED_ENDPOINT = "http://127.0.0.1:8787/mcp";

const SECRET_OPTION_NAMES = new Set([
  "api-key",
  "apikey",
  "authorization",
  "bearer-token",
  "client-secret",
  "github-token",
  "header",
  "password",
  "private-key",
  "secret",
  "token",
]);

export function parseCliOptions(argv: readonly string[]): CliOptions {
  if (argv.length === 0 || argv[0] === "help" || argv[0] === "--help" || argv[0] === "-h") {
    throw new CliError("help", usage());
  }

  const command = argv[0] ?? "";
  if (!isCommand(command)) throw new CliError("invalid_command", "Unknown command. Run `am --help` for usage.");

  let index = 1;
  let provider: "github" | undefined;
  if (command === "protect") {
    if (argv[index] !== "github") throw new CliError("invalid_provider", "`am protect` currently requires the `github` provider.");
    provider = "github";
    index += 1;
  }

  let clients: ClientId[] | undefined;
  let scope: InstallScope = "user";
  let endpoint: string | undefined;
  let selfHosted = false;
  let dryRun = false;
  let replace = false;
  let json = false;

  while (index < argv.length) {
    const raw = argv[index]!;
    if (!raw.startsWith("--")) throw new CliError("unexpected_argument", "Unexpected positional argument.");
    const equals = raw.indexOf("=");
    const name = raw.slice(2, equals === -1 ? undefined : equals);
    if (SECRET_OPTION_NAMES.has(name.toLowerCase())) {
      throw new CliError("secret_option_refused", `Refusing secret-bearing option --${name}. Use browser OAuth; never place secrets in CLI arguments.`);
    }
    const inlineValue = equals === -1 ? undefined : raw.slice(equals + 1);

    switch (name) {
      case "clients": {
        const [value, next] = optionValue(argv, index, inlineValue);
        clients = parseClients(value);
        index = next;
        break;
      }
      case "scope": {
        const [value, next] = optionValue(argv, index, inlineValue);
        if (value !== "user" && value !== "project") throw new CliError("invalid_scope", "Scope must be `user` or `project`.");
        scope = value;
        index = next;
        break;
      }
      case "endpoint": {
        const [value, next] = optionValue(argv, index, inlineValue);
        endpoint = validateEndpoint(value);
        index = next;
        break;
      }
      case "self-hosted":
        ensureBooleanOptionHasNoValue(name, inlineValue);
        selfHosted = true;
        index += 1;
        break;
      case "dry-run":
        ensureBooleanOptionHasNoValue(name, inlineValue);
        dryRun = true;
        index += 1;
        break;
      case "replace":
        ensureBooleanOptionHasNoValue(name, inlineValue);
        replace = true;
        index += 1;
        break;
      case "json":
        ensureBooleanOptionHasNoValue(name, inlineValue);
        json = true;
        index += 1;
        break;
      case "help":
        throw new CliError("help", usage());
      default:
        throw new CliError("unknown_option", `Unknown option --${safeOptionName(name)}.`);
    }
  }

  if (selfHosted && endpoint !== undefined) {
    throw new CliError("conflicting_options", "Use either --self-hosted or --endpoint, not both; they identify different deployment modes.");
  }
  const effectiveEndpoint = endpoint ?? (selfHosted ? DEFAULT_SELF_HOSTED_ENDPOINT : undefined);
  if ((command === "protect" || command === "install") && !effectiveEndpoint) {
    throw new CliError("missing_endpoint", "No managed service endpoint is published. Pass --endpoint or select the explicit loopback profile with --self-hosted.");
  }
  return {
    command,
    ...(provider ? { provider } : {}),
    ...(clients ? { clients } : {}),
    scope,
    ...(effectiveEndpoint ? { endpoint: validateEndpoint(effectiveEndpoint) } : {}),
    selfHosted,
    dryRun,
    replace,
    json,
  };
}

export function validateEndpoint(value: string): string {
  if (value.length > 2_048) throw new CliError("invalid_endpoint", "Endpoint is too long.");
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new CliError("invalid_endpoint", "Endpoint must be an absolute HTTPS URL or loopback HTTP URL.");
  }
  if (parsed.username || parsed.password) throw new CliError("secret_endpoint_refused", "Endpoint must not contain embedded credentials.");
  if (parsed.search || parsed.hash) throw new CliError("secret_endpoint_refused", "Endpoint query strings and fragments are not accepted because they can expose secrets.");
  if (parsed.protocol !== "https:" && !(parsed.protocol === "http:" && isLoopback(parsed.hostname))) {
    throw new CliError("insecure_endpoint", "Endpoint must use HTTPS; HTTP is allowed only for localhost or loopback addresses.");
  }
  if (!parsed.hostname) throw new CliError("invalid_endpoint", "Endpoint must include a host.");
  return parsed.toString();
}

export function usage(): string {
  return [
    "Usage:",
    "  am protect github [options]",
    "  am install|connect|status|doctor|uninstall [options]",
    "",
    "Options:",
    "  --clients codex,claude,cursor,vscode,gemini",
    "  --scope user|project",
    "  --endpoint https://host/mcp  Required until a managed service is published",
    `  --self-hosted               Use ${DEFAULT_SELF_HOSTED_ENDPOINT}`,
    "  --dry-run",
    "  --replace                   Explicit replacement/removal; unsafe native replacements are refused",
    "  --json",
  ].join("\n");
}

function parseClients(value: string): ClientId[] | undefined {
  const normalized = value.trim().toLowerCase();
  if (normalized === "auto") return undefined;
  const aliases: Record<string, ClientId> = {
    codex: "codex",
    claude: "claude",
    "claude-code": "claude",
    cursor: "cursor",
    vscode: "vscode",
    "vs-code": "vscode",
    gemini: "gemini",
  };
  const requested = normalized === "all" ? [...CLIENT_IDS] : normalized.split(",").map((client) => aliases[client.trim()]);
  if (requested.length === 0 || requested.some((client) => client === undefined)) {
    throw new CliError("invalid_clients", "Clients must be a comma-separated subset of codex, claude, cursor, vscode, and gemini.");
  }
  return [...new Set(requested as ClientId[])];
}

function isCommand(value: string): value is CliOptions["command"] {
  return value === "protect" || value === "install" || value === "connect" || value === "status" || value === "doctor" || value === "uninstall";
}

function optionValue(argv: readonly string[], index: number, inline: string | undefined): [string, number] {
  if (inline !== undefined) {
    if (!inline) throw new CliError("missing_option_value", "Option value must not be empty.");
    return [inline, index + 1];
  }
  const value = argv[index + 1];
  if (!value || value.startsWith("--")) throw new CliError("missing_option_value", "Option requires a value.");
  return [value, index + 2];
}

function ensureBooleanOptionHasNoValue(name: string, value: string | undefined): void {
  if (value !== undefined) throw new CliError("invalid_option_value", `Option --${name} does not accept a value.`);
}

function isLoopback(hostname: string): boolean {
  const normalized = hostname.toLowerCase();
  if (normalized === "localhost") return true;
  if (normalized === "::1" || normalized === "[::1]") return true;
  return isIP(normalized) === 4 && normalized.split(".")[0] === "127";
}

function safeOptionName(name: string): string {
  return /^[a-z0-9-]{1,64}$/i.test(name) ? name : "(invalid-name)";
}
