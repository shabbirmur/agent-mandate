export const CLIENT_IDS = ["codex", "claude", "cursor", "vscode", "gemini"] as const;

export type ClientId = (typeof CLIENT_IDS)[number];
export type InstallScope = "user" | "project";
export type CliCommandName = "protect" | "install" | "connect" | "status" | "doctor" | "uninstall";

export interface CliOptions {
  command: CliCommandName;
  provider?: "github";
  clients?: ClientId[];
  scope: InstallScope;
  endpoint?: string;
  selfHosted: boolean;
  dryRun: boolean;
  replace: boolean;
  json: boolean;
}

export interface InstallCliOptions extends CliOptions {
  endpoint: string;
}

export interface CommandInvocation {
  file: string;
  args: string[];
  /** Read-only commands may still run during --dry-run. */
  mutates: boolean;
  timeoutMs?: number;
}

export interface CommandResult {
  exitCode: number;
  stdout: string;
  stderr: string;
}

export interface CommandRunner {
  run(invocation: CommandInvocation): Promise<CommandResult>;
}

export interface InstallationRecord {
  client: ClientId;
  scope: InstallScope;
  endpoint: string;
  mode: "managed" | "self-hosted";
  installedAt: string;
  projectRoot?: string;
  configPath?: string;
}

export interface InstallationManifest {
  version: 1;
  installations: InstallationRecord[];
}

export type ClientState = "configured" | "missing" | "conflict" | "unknown";

export interface ClientStatus {
  client: ClientId;
  state: ClientState;
  scope: InstallScope;
  tracked: boolean;
  detail: string;
  /** Exact normalized remote endpoint when the client exposes it safely. */
  endpoint?: string;
}

export interface AdapterActionResult {
  changed: boolean;
  detail: string;
  /** True when uninstall may safely remove the ownership record. */
  ownershipReleased?: boolean;
  configPath?: string;
  backupPath?: string;
  manualAction?: string;
  /** Restores the exact pre-install state if a later installation step fails. */
  rollback?: () => Promise<void>;
}

export interface AdapterContext {
  cwd: string;
  homeDir: string;
  env: Readonly<NodeJS.ProcessEnv>;
  runner: CommandRunner;
  dryRun: boolean;
  replace: boolean;
  now: () => Date;
}

export interface ClientAdapter {
  readonly id: ClientId;
  supportsScope(scope: InstallScope): boolean;
  detect(context: AdapterContext): Promise<boolean>;
  status(context: AdapterContext, scope: InstallScope, tracked?: InstallationRecord): Promise<ClientStatus>;
  install(context: AdapterContext, options: InstallCliOptions, tracked?: InstallationRecord): Promise<AdapterActionResult>;
  connect(context: AdapterContext, record: InstallationRecord): Promise<AdapterActionResult>;
  uninstall(context: AdapterContext, record: InstallationRecord): Promise<AdapterActionResult>;
}

export interface CliDependencies {
  cwd?: string;
  homeDir?: string;
  env?: NodeJS.ProcessEnv;
  runner?: CommandRunner;
  now?: () => Date;
  manifestPath?: string;
  stdout?: (text: string) => void;
  stderr?: (text: string) => void;
}

export interface CliRunResult {
  exitCode: number;
  output?: unknown;
}

export class CliError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = "CliError";
    this.code = code;
  }
}
