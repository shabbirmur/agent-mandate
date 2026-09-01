import { homedir } from "node:os";
import { resolve } from "node:path";
import { createClientAdapters } from "./clients.js";
import { runDoctor } from "./doctor.js";
import { installationKey, ManifestStore } from "./files.js";
import { parseCliOptions, usage } from "./options.js";
import { SpawnCommandRunner } from "./runner.js";
import {
  CLIENT_IDS,
  CliError,
  type AdapterActionResult,
  type AdapterContext,
  type ClientAdapter,
  type ClientId,
  type CliDependencies,
  type CliOptions,
  type CliRunResult,
  type InstallationManifest,
  type InstallationRecord,
  type InstallCliOptions,
} from "./types.js";

interface ClientActionOutput {
  client: ClientId;
  changed: boolean;
  detail: string;
  manualAction?: string;
  backupCreated?: boolean;
}

interface InstallOutcome {
  output: {
    command: "install" | "protect";
    provider?: "github";
    dryRun: boolean;
    mode: "managed" | "self-hosted";
    clients: ClientActionOutput[];
    manifestChanged: boolean;
  };
  records: InstallationRecord[];
}

export async function runCli(argv: readonly string[], dependencies: CliDependencies = {}): Promise<CliRunResult> {
  const stdout = dependencies.stdout ?? ((text: string) => process.stdout.write(text));
  const stderr = dependencies.stderr ?? ((text: string) => process.stderr.write(text));
  let options: CliOptions | undefined;
  try {
    options = parseCliOptions(argv);
    const application = createApplication(dependencies);
    const output = await application.execute(options);
    stdout(options.json ? `${JSON.stringify(output)}\n` : `${renderHuman(output)}\n`);
    return { exitCode: 0, output };
  } catch (error) {
    if (error instanceof CliError && error.code === "help") {
      stdout(`${error.message}\n`);
      return { exitCode: 0, output: { help: true } };
    }
    const failure = error instanceof CliError
      ? { error: error.code, message: error.message }
      : { error: "internal_error", message: "Unexpected CLI failure." };
    if (options?.json) stderr(`${JSON.stringify(failure)}\n`);
    else stderr(`Error [${failure.error}]: ${failure.message}\n`);
    return { exitCode: 1, output: failure };
  }
}

export class CliApplication {
  readonly #context: AdapterContext;
  readonly #manifest: ManifestStore;
  readonly #adapters: ReadonlyMap<ClientId, ClientAdapter>;

  constructor(context: AdapterContext, manifest: ManifestStore, adapters = createClientAdapters()) {
    this.#context = context;
    this.#manifest = manifest;
    this.#adapters = adapters;
  }

  async execute(options: CliOptions): Promise<unknown> {
    this.#context.dryRun = options.dryRun;
    this.#context.replace = options.replace;
    switch (options.command) {
      case "protect": {
        const installed = await this.#install(options, "protect");
        const connected = await this.#connectRecords(installed.records);
        return { ...installed.output, connections: connected };
      }
      case "install":
        return (await this.#install(options, "install")).output;
      case "connect":
        return await this.#connect(options);
      case "status":
        return await this.#status(options);
      case "doctor":
        return { command: "doctor", ...(await runDoctor(this.#context, this.#manifest)) };
      case "uninstall":
        return await this.#uninstall(options);
    }
  }

  async #install(options: CliOptions, command: "install" | "protect"): Promise<InstallOutcome> {
    if (!options.endpoint) throw new CliError("missing_endpoint", "Install requires --endpoint or --self-hosted.");
    const installOptions: InstallCliOptions = { ...options, endpoint: options.endpoint };
    const manifest = await this.#manifest.read();
    const clients = await this.#selectInstallClients(installOptions);
    for (const client of clients) {
      const adapter = this.#adapter(client);
      if (!adapter.supportsScope(installOptions.scope)) {
        throw new CliError("unsupported_scope", `${client} cannot be installed safely at the requested scope by its current native CLI.`);
      }
    }

    const projectRoot = installOptions.scope === "project" ? resolve(this.#context.cwd) : undefined;
    const currentByKey = new Map(manifest.installations.map((record) => [installationKey(record), record]));
    const statuses = new Map<ClientId, Awaited<ReturnType<ClientAdapter["status"]>>>();
    for (const client of clients) {
      const key = installationKey({ client, scope: installOptions.scope, ...(projectRoot ? { projectRoot } : {}) });
      const tracked = currentByKey.get(key);
      if (tracked && tracked.endpoint !== installOptions.endpoint && !installOptions.replace) {
        throw new CliError("config_conflict", `${client} is owned at a different endpoint; use --replace explicitly.`);
      }
      const clientStatus = await this.#adapter(client).status(this.#context, installOptions.scope, tracked);
      if (clientStatus.state === "conflict" && !installOptions.replace) {
        throw new CliError("config_conflict", `${client} has a conflicting Agent Mandate configuration; use --replace explicitly.`);
      }
      if (!tracked && clientStatus.state === "configured" && !installOptions.replace) {
        throw new CliError("config_conflict", `${client} has an unowned Agent Mandate configuration; use --replace explicitly.`);
      }
      if (clientStatus.state === "unknown" && (!tracked || tracked.endpoint !== installOptions.endpoint)) {
        throw new CliError("ownership_unverifiable", `${client}'s exact endpoint cannot be verified, so it cannot be changed automatically.`);
      }
      statuses.set(client, clientStatus);
    }
    await this.#manifest.preflightWrite(installOptions.dryRun);

    const actionOutputs: ClientActionOutput[] = [];
    const effectiveRecords: InstallationRecord[] = [];
    const completed: Array<{
      record: InstallationRecord;
      tracked: boolean;
      rollback?: () => Promise<void>;
    }> = [];
    try {
      for (const client of clients) {
        const key = installationKey({ client, scope: installOptions.scope, ...(projectRoot ? { projectRoot } : {}) });
        const tracked = currentByKey.get(key);
        const clientStatus = statuses.get(client)!;
        let action: AdapterActionResult;
        if (tracked?.endpoint === installOptions.endpoint && clientStatus.state === "configured") {
          action = { changed: false, detail: "Already configured with the exact owned endpoint.", ...(tracked.configPath ? { configPath: tracked.configPath } : {}) };
        } else if (tracked?.endpoint === installOptions.endpoint && clientStatus.state === "unknown") {
          action = {
            changed: false,
            detail: "Installation is owned, but this client cannot independently prove the exact endpoint; no mutation was attempted.",
            ...(tracked.configPath ? { configPath: tracked.configPath } : {}),
          };
        } else {
          action = await this.#adapter(client).install(this.#context, installOptions, tracked);
        }
        const record: InstallationRecord = {
          client,
          scope: installOptions.scope,
          endpoint: installOptions.endpoint,
          mode: installOptions.selfHosted ? "self-hosted" : "managed",
          installedAt: tracked?.installedAt ?? this.#context.now().toISOString(),
          ...(projectRoot ? { projectRoot } : {}),
          ...(action.configPath ? { configPath: action.configPath } : tracked?.configPath ? { configPath: tracked.configPath } : {}),
        };
        effectiveRecords.push(record);
        if (action.changed) completed.push({
          record,
          tracked: tracked !== undefined,
          ...(action.rollback === undefined ? {} : { rollback: action.rollback }),
        });
        currentByKey.set(key, record);
        actionOutputs.push(toActionOutput(client, action));
      }

      const nextManifest: InstallationManifest = { version: 1, installations: [...currentByKey.values()] };
      const manifestWrite = await this.#manifest.write(nextManifest, installOptions.dryRun, this.#context.now);
      return {
        output: {
          command,
          ...(options.provider ? { provider: options.provider } : {}),
          dryRun: installOptions.dryRun,
          mode: installOptions.selfHosted ? "self-hosted" : "managed",
          clients: actionOutputs,
          manifestChanged: manifestWrite.changed,
        },
        records: effectiveRecords,
      };
    } catch (error) {
      let rollbackFailed = false;
      if (!installOptions.dryRun) {
        for (const completedAction of completed.reverse()) {
          try {
            if (completedAction.rollback !== undefined) {
              await completedAction.rollback();
            } else if (!completedAction.tracked) {
              const rolledBack = await this.#adapter(completedAction.record.client).uninstall(this.#context, completedAction.record);
              if (rolledBack.ownershipReleased !== true) rollbackFailed = true;
            } else {
              rollbackFailed = true;
            }
          } catch {
            rollbackFailed = true;
          }
        }
      }
      if (rollbackFailed) throw new CliError("installation_rollback_failed", "A client installation failed and at least one earlier change could not be restored automatically.");
      throw error;
    }
  }

  async #connect(options: CliOptions): Promise<unknown> {
    const manifest = await this.#manifest.read();
    const records = this.#matchingRecords(manifest, options);
    if (records.length === 0) throw new CliError("not_installed", "No owned Agent Mandate installation matches this scope.");
    return { command: "connect", dryRun: options.dryRun, clients: await this.#connectRecords(records) };
  }

  async #connectRecords(records: readonly InstallationRecord[]): Promise<ClientActionOutput[]> {
    const outputs: ClientActionOutput[] = [];
    for (const record of records) {
      const action = await this.#adapter(record.client).connect(this.#context, record);
      outputs.push(toActionOutput(record.client, action));
    }
    return outputs;
  }

  async #status(options: CliOptions): Promise<unknown> {
    const manifest = await this.#manifest.read();
    const selected = options.clients ?? this.#matchingRecords(manifest, options).map((record) => record.client);
    const clients = uniqueClients(selected);
    const statuses = [];
    for (const client of clients) {
      const record = this.#recordFor(manifest, client, options);
      statuses.push(await this.#adapter(client).status(this.#context, options.scope, record));
    }
    return { command: "status", clients: statuses };
  }

  async #uninstall(options: CliOptions): Promise<unknown> {
    const manifest = await this.#manifest.read();
    const selected = options.clients ?? this.#matchingRecords(manifest, options).map((record) => record.client);
    const clients = uniqueClients(selected);
    if (clients.some((client) => this.#recordFor(manifest, client, options) !== undefined)) {
      await this.#manifest.preflightWrite(options.dryRun);
    }
    const recordsByKey = new Map(manifest.installations.map((record) => [installationKey(record), record]));
    const outputs: ClientActionOutput[] = [];
    let manifestChanged = false;
    for (const client of clients) {
      const record = this.#recordFor(manifest, client, options);
      if (!record) {
        outputs.push({ client, changed: false, detail: "No installer-owned entry matches this scope." });
        continue;
      }
      const action = await this.#adapter(client).uninstall(this.#context, record);
      outputs.push(toActionOutput(client, action));
      if (action.ownershipReleased) {
        recordsByKey.delete(installationKey(record));
        manifestChanged = true;
      }
    }
    if (manifestChanged) await this.#manifest.write({ version: 1, installations: [...recordsByKey.values()] }, options.dryRun, this.#context.now);
    return { command: "uninstall", dryRun: options.dryRun, clients: outputs, manifestChanged };
  }

  async #selectInstallClients(options: CliOptions): Promise<ClientId[]> {
    if (options.clients) return options.clients;
    const detected: ClientId[] = [];
    for (const client of CLIENT_IDS) {
      if (await this.#adapter(client).detect(this.#context)) detected.push(client);
    }
    if (detected.length === 0) throw new CliError("no_clients_detected", "No supported agent client was detected; specify --clients after installing one.");
    return detected;
  }

  #matchingRecords(manifest: InstallationManifest, options: CliOptions): InstallationRecord[] {
    const projectRoot = options.scope === "project" ? resolve(this.#context.cwd) : undefined;
    return manifest.installations.filter((record) => record.scope === options.scope
      && (record.scope !== "project" || record.projectRoot === projectRoot)
      && (!options.clients || options.clients.includes(record.client)));
  }

  #recordFor(manifest: InstallationManifest, client: ClientId, options: CliOptions): InstallationRecord | undefined {
    return this.#matchingRecords(manifest, options).find((record) => record.client === client);
  }

  #adapter(client: ClientId): ClientAdapter {
    const adapter = this.#adapters.get(client);
    if (!adapter) throw new CliError("unsupported_client", "Requested client is not supported.");
    return adapter;
  }
}

function createApplication(dependencies: CliDependencies): CliApplication {
  const environment = { ...(dependencies.env ?? process.env) };
  const cwd = resolve(dependencies.cwd ?? process.cwd());
  const homeDir = resolve(dependencies.homeDir ?? environment.HOME ?? homedir());
  const now = dependencies.now ?? (() => new Date());
  const context: AdapterContext = {
    cwd,
    homeDir,
    env: environment,
    runner: dependencies.runner ?? new SpawnCommandRunner(environment, cwd),
    dryRun: false,
    replace: false,
    now,
  };
  return new CliApplication(context, new ManifestStore(homeDir, dependencies.manifestPath));
}

function uniqueClients(clients: readonly ClientId[]): ClientId[] {
  return [...new Set(clients)];
}

function toActionOutput(client: ClientId, action: AdapterActionResult): ClientActionOutput {
  return {
    client,
    changed: action.changed,
    detail: action.detail,
    ...(action.manualAction ? { manualAction: action.manualAction } : {}),
    ...(action.backupPath ? { backupCreated: true } : {}),
  };
}

function renderHuman(output: unknown): string {
  if (!output || typeof output !== "object") return "Agent Mandate command completed.";
  const record = output as Record<string, unknown>;
  const lines = [`Agent Mandate ${typeof record.command === "string" ? record.command : "result"}`];
  const clients = record.clients;
  if (Array.isArray(clients)) {
    for (const client of clients) {
      if (!client || typeof client !== "object") continue;
      const item = client as Record<string, unknown>;
      if (typeof item.client === "string" && typeof item.detail === "string") lines.push(`- ${item.client}: ${item.detail}`);
      if (typeof item.manualAction === "string") lines.push(`  Next: ${item.manualAction}`);
    }
  }
  const connections = record.connections;
  if (Array.isArray(connections)) {
    for (const connection of connections) {
      if (!connection || typeof connection !== "object") continue;
      const item = connection as Record<string, unknown>;
      if (typeof item.client === "string" && typeof item.detail === "string") lines.push(`- ${item.client} connection: ${item.detail}`);
      if (typeof item.manualAction === "string") lines.push(`  Next: ${item.manualAction}`);
    }
  }
  if (record.enforced && typeof record.enforced === "object") {
    const enforced = record.enforced as Record<string, unknown>;
    if (typeof enforced.detail === "string") lines.push(`- enforcement: ${enforced.detail}`);
  }
  if (Array.isArray(record.bypassIndicators)) {
    for (const indicator of record.bypassIndicators) {
      if (!indicator || typeof indicator !== "object") continue;
      const item = indicator as Record<string, unknown>;
      if (typeof item.code === "string" && typeof item.detail === "string") lines.push(`- bypass ${item.code}: ${item.detail}`);
    }
  }
  return lines.join("\n");
}

export { parseCliOptions, usage };
