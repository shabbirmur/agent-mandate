import { Pool, type PoolClient, type PoolConfig } from "pg";

export function postgresPoolConfig(connectionString: string, operationTimeoutMs: number): PoolConfig {
  if (!connectionString) throw new TypeError("connectionString is required");
  if (!Number.isInteger(operationTimeoutMs) || operationTimeoutMs < 2) {
    throw new TypeError("operationTimeoutMs must be an integer of at least 2");
  }
  const acquisitionTimeoutMs = Math.floor(operationTimeoutMs / 2);
  const queryTimeoutMs = operationTimeoutMs - acquisitionTimeoutMs;
  return {
    connectionString,
    connectionTimeoutMillis: acquisitionTimeoutMs,
    query_timeout: queryTimeoutMs,
    statement_timeout: queryTimeoutMs,
  };
}

/** Create a pool whose sequential acquisition and query phases share one total budget. */
export function createPostgresPool(
  connectionString: string,
  operationTimeoutMs: number,
  onIdleError: (error: Error) => void,
): Pool {
  const pool = new Pool(postgresPoolConfig(connectionString, operationTimeoutMs));
  pool.on("error", onIdleError);
  return pool;
}

/**
 * Run a transaction and discard its connection after any failed operation.
 * This prevents a client-side timeout or failed rollback from returning an
 * unresolved transaction to the pool.
 */
export async function withPostgresTransaction<T>(
  pool: Pick<Pool, "connect">,
  work: (client: PoolClient) => Promise<T>,
): Promise<T> {
  const client = await pool.connect();
  let releaseError: Error | undefined;
  try {
    await client.query("BEGIN");
    const result = await work(client);
    await client.query("COMMIT");
    return result;
  } catch (error) {
    const transactionError = asError(error);
    releaseError = transactionError;
    try {
      await client.query("ROLLBACK");
    } catch (rollbackError) {
      const rollbackFailure = asError(rollbackError);
      releaseError = rollbackFailure;
      throw new AggregateError([transactionError, rollbackFailure], "PostgreSQL transaction and rollback failed");
    }
    throw error;
  } finally {
    client.release(releaseError);
  }
}

function asError(value: unknown): Error {
  return value instanceof Error ? value : new Error(String(value));
}
