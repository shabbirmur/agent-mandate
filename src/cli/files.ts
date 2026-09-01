import { constants, type Stats } from "node:fs";
import { chmod, copyFile, lstat, mkdir, open, readFile, realpath, rename, unlink } from "node:fs/promises";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { randomUUID } from "node:crypto";
import { validateEndpoint } from "./options.js";
import {
  CLIENT_IDS,
  CliError,
  type ClientId,
  type InstallationManifest,
  type InstallationRecord,
  type InstallScope,
} from "./types.js";

const MAX_CONFIG_BYTES = 1_048_576;
const SECRET_KEY = /(?:authorization|bearer|client.?secret|password|private.?key|token|api.?key|credential|headers?|env|auth)/i;

export interface SafeJsonDocument {
  path: string;
  value: Record<string, unknown>;
  exists: boolean;
}

export interface AtomicWriteResult {
  changed: boolean;
  backupPath?: string;
}

export class ManifestStore {
  readonly path: string;
  readonly #baseDir: string;

  constructor(homeDir: string, overridePath?: string) {
    this.path = overridePath ?? join(homeDir, ".config", "agent-mandate", "installations.json");
    this.#baseDir = overridePath ? dirname(overridePath) : homeDir;
    assertWithin(this.#baseDir, this.path);
  }

  async read(): Promise<InstallationManifest> {
    const document = await readSafeJson(this.path, this.#baseDir, { requirePrivateMode: true });
    if (!document.exists) return { version: 1, installations: [] };
    return parseManifest(document.value);
  }

  async write(manifest: InstallationManifest, dryRun: boolean, now: () => Date): Promise<AtomicWriteResult> {
    const normalized = parseManifest(manifest as unknown as Record<string, unknown>);
    normalized.installations.sort((left, right) => installationKey(left).localeCompare(installationKey(right)));
    return await atomicWriteJson(this.path, this.#baseDir, normalized as unknown as Record<string, unknown>, {
      dryRun,
      backup: true,
      privateMode: true,
      now,
    });
  }

  /** Validate and create the owned state directory before mutating any client. */
  async preflightWrite(dryRun: boolean): Promise<void> {
    if (dryRun) {
      await assertExistingAncestorWithinBase(dirname(this.path), this.#baseDir);
      return;
    }
    await assertSafeParent(this.path, this.#baseDir, true);
    const target = await optionalLstat(this.path);
    if (target) assertSafeRegularFile(this.path, target, true);
  }
}

export async function readSafeJson(
  path: string,
  baseDir: string,
  options: { requirePrivateMode?: boolean } = {},
): Promise<SafeJsonDocument> {
  assertWithin(baseDir, path);
  await assertSafeParent(path, baseDir, false);
  const stat = await optionalLstat(path);
  if (!stat) return { path, value: {}, exists: false };
  assertSafeRegularFile(path, stat, options.requirePrivateMode === true);
  if (stat.size > MAX_CONFIG_BYTES) throw new CliError("config_too_large", "Configuration file exceeds the safe size limit.");
  const text = await readFile(path, "utf8");
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new CliError("malformed_config", "Configuration is malformed; refusing to modify it.");
  }
  if (!isPlainRecord(parsed)) throw new CliError("malformed_config", "Configuration root must be a JSON object.");
  return { path, value: parsed, exists: true };
}

export async function atomicWriteJson(
  path: string,
  baseDir: string,
  value: Record<string, unknown>,
  options: { dryRun: boolean; backup: boolean; privateMode: boolean; now: () => Date },
): Promise<AtomicWriteResult> {
  assertWithin(baseDir, path);
  const serialized = `${JSON.stringify(value, null, 2)}\n`;
  const current = await readSafeText(path, baseDir, options.privateMode);
  if (current === serialized) return { changed: false };
  if (options.dryRun) return { changed: true };

  await assertSafeParent(path, baseDir, true);
  let backupPath: string | undefined;
  if (current !== undefined && options.backup) {
    backupPath = `${path}.am-backup-${safeTimestamp(options.now())}-${randomUUID()}`;
    await copyFile(path, backupPath, constants.COPYFILE_EXCL);
    await chmod(backupPath, 0o600);
  }

  const temporary = join(dirname(path), `.${pathName(path)}.am-tmp-${process.pid}-${randomUUID()}`);
  let handle: Awaited<ReturnType<typeof open>> | undefined;
  try {
    const flags = constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY
      | (typeof constants.O_NOFOLLOW === "number" ? constants.O_NOFOLLOW : 0);
    handle = await open(temporary, flags, 0o600);
    await handle.writeFile(serialized, "utf8");
    await handle.sync();
    await handle.close();
    handle = undefined;

    const target = await optionalLstat(path);
    if (target) assertSafeRegularFile(path, target, options.privateMode);
    await rename(temporary, path);
    await chmod(path, 0o600);
  } catch (error) {
    await handle?.close().catch(() => undefined);
    await unlink(temporary).catch(() => undefined);
    throw error;
  }
  return { changed: true, ...(backupPath ? { backupPath } : {}) };
}

export function installationKey(record: Pick<InstallationRecord, "client" | "scope" | "projectRoot">): string {
  return `${record.client}:${record.scope}:${record.projectRoot ?? ""}`;
}

export function containsSecretMaterial(value: unknown): boolean {
  if (!isPlainRecord(value)) return false;
  for (const [key, nested] of Object.entries(value)) {
    if (SECRET_KEY.test(key)) return true;
    if (Array.isArray(nested) && nested.some((item) => containsSecretMaterial(item))) return true;
    if (isPlainRecord(nested) && containsSecretMaterial(nested)) return true;
  }
  return false;
}

export function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

export async function readSafeTextForAudit(path: string): Promise<string | undefined> {
  const stat = await optionalLstat(path);
  if (!stat || stat.isSymbolicLink() || !stat.isFile() || stat.size > MAX_CONFIG_BYTES) return undefined;
  return await readFile(path, "utf8").catch(() => undefined);
}

async function readSafeText(path: string, baseDir: string, requirePrivateMode: boolean): Promise<string | undefined> {
  assertWithin(baseDir, path);
  await assertSafeParent(path, baseDir, false);
  const stat = await optionalLstat(path);
  if (!stat) return undefined;
  assertSafeRegularFile(path, stat, requirePrivateMode);
  if (stat.size > MAX_CONFIG_BYTES) throw new CliError("config_too_large", "Configuration file exceeds the safe size limit.");
  return await readFile(path, "utf8");
}

async function assertSafeParent(path: string, baseDir: string, create: boolean): Promise<void> {
  assertWithin(baseDir, path);
  const parent = dirname(path);
  const existing = await optionalLstat(parent);
  if (!existing && create) {
    await assertExistingAncestorWithinBase(parent, baseDir);
    await mkdir(parent, { recursive: true, mode: 0o700 });
  }
  const stat = await optionalLstat(parent);
  if (!stat) return;
  if (stat.isSymbolicLink() || !stat.isDirectory()) throw new CliError("unsafe_config_path", "Configuration parent must be a real directory, not a symlink.");
  const [realBase, realParent] = await Promise.all([realpath(resolve(baseDir)), realpath(resolve(parent))]);
  if (!isWithinOrEqual(realBase, realParent)) {
    throw new CliError("unsafe_config_path", "Configuration parent resolves outside its allowed base directory.");
  }
  assertOwned(stat.uid);
  if (process.platform !== "win32" && (stat.mode & 0o022) !== 0) {
    throw new CliError("unsafe_config_path", "Configuration parent must not be group- or world-writable.");
  }
}

async function assertExistingAncestorWithinBase(path: string, baseDir: string): Promise<void> {
  const [base, target] = await Promise.all([
    nearestExistingAncestor(resolve(baseDir)),
    nearestExistingAncestor(resolve(path)),
  ]);
  if (base.stat.isSymbolicLink() || target.stat.isSymbolicLink()) {
    throw new CliError("unsafe_config_path", "Configuration path contains an intermediate symlink.");
  }
  const [realBase, realTarget] = await Promise.all([realpath(base.path), realpath(target.path)]);
  if (!isWithinOrEqual(realBase, realTarget)) {
    throw new CliError("unsafe_config_path", "Configuration path resolves outside its allowed base directory.");
  }
}

async function nearestExistingAncestor(start: string): Promise<{ path: string; stat: Stats }> {
  let current = start;
  while (true) {
    const stat = await optionalLstat(current);
    if (stat) return { path: current, stat };
    const parent = dirname(current);
    if (parent === current) throw new CliError("unsafe_config_path", "Configuration path has no existing filesystem anchor.");
    current = parent;
  }
}

function isWithinOrEqual(baseDir: string, path: string): boolean {
  const relation = relative(resolve(baseDir), resolve(path));
  return relation === "" || relation !== ".." && !relation.startsWith(`..${sep}`) && !isAbsolute(relation);
}

function assertSafeRegularFile(path: string, stat: Stats, requirePrivateMode: boolean): void {
  if (stat.isSymbolicLink() || !stat.isFile()) throw new CliError("unsafe_config_file", "Configuration must be a regular file, not a symlink or special file.");
  assertOwned(stat.uid);
  if (process.platform !== "win32" && (stat.mode & 0o022) !== 0) {
    throw new CliError("unsafe_config_file", "Configuration must not be group- or world-writable.");
  }
  if (process.platform !== "win32" && requirePrivateMode && (stat.mode & 0o077) !== 0) {
    throw new CliError("unsafe_manifest_permissions", "Agent Mandate's ownership manifest must have mode 0600.");
  }
  if (!isAbsolute(path)) throw new CliError("unsafe_config_path", "Configuration path must be absolute.");
}

function assertOwned(uid: number): void {
  const getuid = process.getuid;
  if (typeof getuid === "function" && uid !== getuid()) throw new CliError("unsafe_config_owner", "Configuration path is not owned by the current user.");
}

function assertWithin(baseDir: string, path: string): void {
  const base = resolve(baseDir);
  const target = resolve(path);
  const relation = relative(base, target);
  if (relation === "" || relation === ".." || relation.startsWith(`..${sep}`) || isAbsolute(relation)) {
    throw new CliError("unsafe_config_path", "Configuration path escapes its allowed base directory.");
  }
}

async function optionalLstat(path: string): Promise<Stats | undefined> {
  try {
    return await lstat(path);
  } catch (error) {
    if (isNodeError(error) && error.code === "ENOENT") return undefined;
    throw error;
  }
}

function parseManifest(value: Record<string, unknown>): InstallationManifest {
  if (value.version !== 1 || !Array.isArray(value.installations)) {
    throw new CliError("malformed_manifest", "Agent Mandate's ownership manifest is malformed.");
  }
  if (Object.keys(value).some((key) => key !== "version" && key !== "installations")) {
    throw new CliError("malformed_manifest", "Agent Mandate's ownership manifest contains unsupported fields.");
  }
  const installations = value.installations.map(parseInstallation);
  const keys = installations.map(installationKey);
  if (new Set(keys).size !== keys.length) throw new CliError("malformed_manifest", "Agent Mandate's ownership manifest contains duplicate records.");
  return { version: 1, installations };
}

function parseInstallation(value: unknown): InstallationRecord {
  if (!isPlainRecord(value)) throw new CliError("malformed_manifest", "Agent Mandate's ownership manifest contains an invalid record.");
  const allowed = new Set(["client", "scope", "endpoint", "mode", "installedAt", "projectRoot", "configPath"]);
  if (Object.keys(value).some((key) => !allowed.has(key) || SECRET_KEY.test(key))) {
    throw new CliError("malformed_manifest", "Agent Mandate's ownership manifest contains unsupported fields.");
  }
  const client = value.client;
  const scope = value.scope;
  const mode = value.mode;
  if (!CLIENT_IDS.includes(client as ClientId)) throw new CliError("malformed_manifest", "Manifest contains an unknown client.");
  if (scope !== "user" && scope !== "project") throw new CliError("malformed_manifest", "Manifest contains an invalid scope.");
  if (mode !== "managed" && mode !== "self-hosted") throw new CliError("malformed_manifest", "Manifest contains an invalid mode.");
  if (typeof value.endpoint !== "string" || validateEndpoint(value.endpoint) !== value.endpoint) {
    throw new CliError("malformed_manifest", "Manifest contains an invalid endpoint.");
  }
  if (typeof value.installedAt !== "string" || !Number.isFinite(Date.parse(value.installedAt))) {
    throw new CliError("malformed_manifest", "Manifest contains an invalid timestamp.");
  }
  if (value.projectRoot !== undefined && typeof value.projectRoot !== "string") throw new CliError("malformed_manifest", "Manifest contains an invalid project root.");
  if (value.configPath !== undefined && typeof value.configPath !== "string") throw new CliError("malformed_manifest", "Manifest contains an invalid configuration path.");
  if (scope === "project" && !value.projectRoot) throw new CliError("malformed_manifest", "Project-scoped manifest record is missing its project root.");
  return {
    client: client as ClientId,
    scope: scope as InstallScope,
    endpoint: value.endpoint,
    mode,
    installedAt: value.installedAt,
    ...(typeof value.projectRoot === "string" ? { projectRoot: value.projectRoot } : {}),
    ...(typeof value.configPath === "string" ? { configPath: value.configPath } : {}),
  };
}

function safeTimestamp(date: Date): string {
  return date.toISOString().replace(/[^0-9TZ]/g, "-");
}

function pathName(path: string): string {
  const parts = path.split(sep);
  return parts[parts.length - 1] || "config";
}

function isNodeError(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error && "code" in error;
}
