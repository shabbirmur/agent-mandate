import { Pool, type PoolConfig, type QueryResultRow } from "pg";
import { toJsonValue } from "../canonical.js";
import type { ProviderConnectionRepository } from "../ports.js";
import type {
  JsonValue,
  ProviderConnection,
  ProviderConnectionResource,
  ProviderConnectionStatus,
  ProviderResourceStatus,
} from "../types.js";

type DatabaseRow = QueryResultRow & Record<string, unknown>;
export type PostgresProviderConnectionRepositoryConfiguration = Pool | PoolConfig | string;

export class PostgresProviderConnectionRepository implements ProviderConnectionRepository {
  readonly #pool: Pool;

  constructor(configuration: PostgresProviderConnectionRepositoryConfiguration) {
    this.#pool = typeof configuration === "string"
      ? new Pool({ connectionString: configuration })
      : configuration instanceof Pool
        ? configuration
        : new Pool(configuration);
  }

  async putConnection(
    input: Omit<ProviderConnection, "createdAt" | "updatedAt">,
    now: Date,
  ): Promise<ProviderConnection> {
    validateConnection(input);
    const at = validDate(now);
    const result = await this.#pool.query<DatabaseRow>(
      `INSERT INTO provider_connections (
         id, tenant_id, provider_id, external_account_id, display_name,
         secret_ref, metadata_json, status, created_at, updated_at
       ) VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9, $9)
       ON CONFLICT (tenant_id, id) DO UPDATE SET
         display_name = EXCLUDED.display_name,
         secret_ref = EXCLUDED.secret_ref,
         metadata_json = EXCLUDED.metadata_json,
         status = EXCLUDED.status,
         updated_at = EXCLUDED.updated_at
       WHERE provider_connections.provider_id = EXCLUDED.provider_id
         AND provider_connections.external_account_id = EXCLUDED.external_account_id
       RETURNING *`,
      [
        input.id,
        input.tenantId,
        input.providerId,
        input.externalAccountId,
        input.displayName,
        input.secretRef,
        JSON.stringify(input.metadata),
        input.status,
        at,
      ],
    );
    if (result.rows[0] === undefined) throw new Error("provider_connection_identity_conflict");
    return mapConnection(result.rows[0]);
  }

  async putResource(
    input: Omit<ProviderConnectionResource, "createdAt" | "updatedAt">,
    now: Date,
  ): Promise<ProviderConnectionResource> {
    validateResource(input);
    const at = validDate(now);
    const result = await this.#pool.query<DatabaseRow>(
      `INSERT INTO provider_connection_resources (
         tenant_id, connection_id, provider_resource_id, display_name,
         selector_json, status, created_at, updated_at
       ) VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7, $7)
       ON CONFLICT (tenant_id, connection_id, provider_resource_id) DO UPDATE SET
         display_name = EXCLUDED.display_name,
         selector_json = EXCLUDED.selector_json,
         status = EXCLUDED.status,
         updated_at = EXCLUDED.updated_at
       RETURNING *`,
      [
        input.tenantId,
        input.connectionId,
        input.providerResourceId,
        input.displayName,
        JSON.stringify(input.selector),
        input.status,
        at,
      ],
    );
    return mapResource(first(result.rows, "provider resource"));
  }

  async findConnection(tenantId: string, providerId: string, connectionId: string): Promise<ProviderConnection | undefined> {
    const result = await this.#pool.query<DatabaseRow>(
      `SELECT * FROM provider_connections
       WHERE tenant_id = $1 AND provider_id = $2 AND id = $3`,
      [required(tenantId), required(providerId), required(connectionId)],
    );
    return result.rows[0] === undefined ? undefined : mapConnection(result.rows[0]);
  }

  async findResource(
    tenantId: string,
    connectionId: string,
    providerResourceId: string,
  ): Promise<ProviderConnectionResource | undefined> {
    const result = await this.#pool.query<DatabaseRow>(
      `SELECT * FROM provider_connection_resources
       WHERE tenant_id = $1 AND connection_id = $2 AND provider_resource_id = $3`,
      [required(tenantId), required(connectionId), required(providerResourceId)],
    );
    return result.rows[0] === undefined ? undefined : mapResource(result.rows[0]);
  }

  async setConnectionStatus(
    tenantId: string,
    providerId: string,
    connectionId: string,
    status: ProviderConnectionStatus,
    now: Date,
  ): Promise<boolean> {
    if (status !== "active" && status !== "suspended" && status !== "revoked") throw new Error("invalid_connection_status");
    const result = await this.#pool.query(
      `UPDATE provider_connections SET status = $4, updated_at = $5
       WHERE tenant_id = $1 AND provider_id = $2 AND id = $3`,
      [required(tenantId), required(providerId), required(connectionId), status, validDate(now)],
    );
    return result.rowCount !== 0;
  }

  async setResourceStatus(
    tenantId: string,
    connectionId: string,
    providerResourceId: string,
    status: ProviderResourceStatus,
    now: Date,
  ): Promise<boolean> {
    if (status !== "active" && status !== "removed") throw new Error("invalid_resource_status");
    const result = await this.#pool.query(
      `UPDATE provider_connection_resources SET status = $4, updated_at = $5
       WHERE tenant_id = $1 AND connection_id = $2 AND provider_resource_id = $3`,
      [required(tenantId), required(connectionId), required(providerResourceId), status, validDate(now)],
    );
    return result.rowCount !== 0;
  }

  async listResources(tenantId: string, providerId: string, connectionId: string): Promise<ProviderConnectionResource[]> {
    const result = await this.#pool.query<DatabaseRow>(
      `SELECT resource.* FROM provider_connection_resources AS resource
       JOIN provider_connections AS connection
         ON connection.tenant_id = resource.tenant_id
        AND connection.id = resource.connection_id
       WHERE resource.tenant_id = $1 AND connection.provider_id = $2
         AND resource.connection_id = $3
       ORDER BY resource.display_name ASC, resource.provider_resource_id ASC`,
      [required(tenantId), required(providerId), required(connectionId)],
    );
    return result.rows.map(mapResource);
  }

  async readiness(): Promise<boolean> {
    try {
      await this.#pool.query("SELECT 1 FROM provider_connections LIMIT 0");
      return true;
    } catch {
      return false;
    }
  }

  close(): Promise<void> {
    return this.#pool.end();
  }
}

function validateConnection(input: Omit<ProviderConnection, "createdAt" | "updatedAt">): void {
  for (const value of [input.id, input.tenantId, input.providerId, input.externalAccountId, input.displayName, input.secretRef]) required(value);
  if (!/^(?:kms|vault|env):\/\/[A-Za-z0-9_.:/-]+$/.test(input.secretRef)) throw new Error("invalid_secret_reference");
  if (input.status !== "active" && input.status !== "suspended" && input.status !== "revoked") throw new Error("invalid_connection_status");
  jsonObject(input.metadata, "connection metadata");
}

function validateResource(input: Omit<ProviderConnectionResource, "createdAt" | "updatedAt">): void {
  for (const value of [input.tenantId, input.connectionId, input.providerResourceId, input.displayName]) required(value);
  if (input.status !== "active" && input.status !== "removed") throw new Error("invalid_resource_status");
  jsonObject(input.selector, "resource selector");
}

function mapConnection(row: DatabaseRow): ProviderConnection {
  const status = required(row.status);
  if (status !== "active" && status !== "suspended" && status !== "revoked") throw new Error("invalid_connection_status");
  return {
    id: required(row.id),
    tenantId: required(row.tenant_id),
    providerId: required(row.provider_id),
    externalAccountId: required(row.external_account_id),
    displayName: required(row.display_name),
    secretRef: required(row.secret_ref),
    metadata: jsonObject(row.metadata_json, "connection metadata"),
    status,
    createdAt: dateIso(row.created_at),
    updatedAt: dateIso(row.updated_at),
  };
}

function mapResource(row: DatabaseRow): ProviderConnectionResource {
  const status = required(row.status);
  if (status !== "active" && status !== "removed") throw new Error("invalid_resource_status");
  return {
    tenantId: required(row.tenant_id),
    connectionId: required(row.connection_id),
    providerResourceId: required(row.provider_resource_id),
    displayName: required(row.display_name),
    selector: jsonObject(row.selector_json, "resource selector"),
    status,
    createdAt: dateIso(row.created_at),
    updatedAt: dateIso(row.updated_at),
  };
}

function jsonObject(value: unknown, label: string): Record<string, JsonValue> {
  let parsed = value;
  if (typeof value === "string") parsed = JSON.parse(value) as unknown;
  let json: JsonValue;
  try {
    json = toJsonValue(parsed);
  } catch (error) {
    throw new Error(`${label} is invalid`, { cause: error });
  }
  if (json === null || Array.isArray(json) || typeof json !== "object") throw new Error(`${label} must be an object`);
  return json;
}

function required(value: unknown): string {
  if (typeof value !== "string" || value.length === 0) throw new Error("non-empty string required");
  return value;
}

function validDate(value: Date): Date {
  if (!(value instanceof Date) || !Number.isFinite(value.getTime())) throw new Error("valid date required");
  return new Date(value.getTime());
}

function dateIso(value: unknown): string {
  return validDate(value instanceof Date ? value : new Date(required(value))).toISOString();
}

function first<Row>(rows: Row[], label: string): Row {
  if (rows[0] === undefined) throw new Error(`${label} was not returned`);
  return rows[0];
}
