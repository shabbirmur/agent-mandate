import assert from "node:assert/strict";
import test from "node:test";
import type { Pool, PoolClient } from "pg";
import { postgresPoolConfig, withPostgresTransaction } from "../src/storage/pool.js";

test("PostgreSQL acquisition and query phases split the configured total bound", () => {
  const config = postgresPoolConfig("postgres://mandate:secret@postgres:5432/agent_mandate", 750);
  assert.equal(config.connectionTimeoutMillis, 375);
  assert.equal(config.query_timeout, 375);
  assert.equal(config.statement_timeout, 375);
  assert.throws(() => postgresPoolConfig("", 750), /connectionString/);
  assert.throws(() => postgresPoolConfig("postgres://example", 0), /operationTimeoutMs/);
});

test("failed transactions destroy their client after a successful rollback", async () => {
  const primaryError = new Error("Query read timeout");
  const observed = fakeTransactionPool();
  await assert.rejects(withPostgresTransaction(observed.pool, async () => Promise.reject(primaryError)), /Query read timeout/);
  assert.deepEqual(observed.queries, ["BEGIN", "ROLLBACK"]);
  assert.equal(observed.releaseErrors[0], primaryError);
});

test("rollback failure destroys the client and preserves both errors", async () => {
  const primaryError = new Error("Query read timeout");
  const rollbackError = new Error("rollback also timed out");
  const observed = fakeTransactionPool(rollbackError);
  await assert.rejects(
    withPostgresTransaction(observed.pool, async () => Promise.reject(primaryError)),
    (error: unknown) =>
      error instanceof AggregateError && error.errors[0] === primaryError && error.errors[1] === rollbackError,
  );
  assert.deepEqual(observed.queries, ["BEGIN", "ROLLBACK"]);
  assert.equal(observed.releaseErrors[0], rollbackError);
});

function fakeTransactionPool(rollbackError?: Error): {
  pool: Pick<Pool, "connect">;
  queries: string[];
  releaseErrors: Array<Error | undefined>;
} {
  const queries: string[] = [];
  const releaseErrors: Array<Error | undefined> = [];
  const client = {
    query: async (sql: string) => {
      queries.push(sql);
      if (sql === "ROLLBACK" && rollbackError !== undefined) throw rollbackError;
      return { rows: [], rowCount: 0 };
    },
    release: (error?: Error) => releaseErrors.push(error),
  } as unknown as PoolClient;
  const pool = { connect: async () => client } as unknown as Pick<Pool, "connect">;
  return { pool, queries, releaseErrors };
}
