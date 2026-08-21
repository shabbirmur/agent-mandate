import { readFile, readdir } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";
import type { Pool } from "pg";
import { loadDatabaseTimeoutMs } from "../config.js";
import { createPostgresPool, withPostgresTransaction } from "./pool.js";

const MIGRATION_NAME = /^\d+_[a-z0-9_]+\.up\.sql$/;

/** Apply each checked-in up migration exactly once under a database lock. */
export async function applyMigrations(pool: Pool, directory = path.resolve(process.cwd(), "migrations")): Promise<void> {
  await withPostgresTransaction(pool, async (client) => {
    await client.query("SELECT pg_advisory_xact_lock($1)", [1_836_279_316]);
    await client.query(`
      CREATE TABLE IF NOT EXISTS agent_mandate_schema_migrations (
        name text PRIMARY KEY,
        applied_at timestamptz NOT NULL DEFAULT clock_timestamp()
      )
    `);

    const names = (await readdir(directory)).filter((name) => MIGRATION_NAME.test(name)).sort();
    for (const name of names) {
      const applied = await client.query("SELECT 1 FROM agent_mandate_schema_migrations WHERE name = $1", [name]);
      if (applied.rowCount !== 0) continue;

      const sql = await readFile(path.join(directory, name), "utf8");
      await client.query(sql);
      await client.query("INSERT INTO agent_mandate_schema_migrations (name) VALUES ($1)", [name]);
    }
  });
}

/**
 * Apply checked-in down migrations in reverse order. Each SQL file contains its
 * own evidence-retention guard; populated pilot schemas intentionally fail.
 */
export async function revertMigrations(pool: Pool, directory = path.resolve(process.cwd(), "migrations")): Promise<void> {
  await withPostgresTransaction(pool, async (client) => {
    await client.query("SELECT pg_advisory_xact_lock($1)", [1_836_279_316]);
    const table = await client.query("SELECT to_regclass('agent_mandate_schema_migrations') AS name");
    if (table.rows[0]?.name === null) {
      return;
    }

    const applied = await client.query<{ name: string }>(
      "SELECT name FROM agent_mandate_schema_migrations ORDER BY name DESC",
    );
    for (const row of applied.rows) {
      if (!MIGRATION_NAME.test(row.name)) throw new Error(`invalid recorded migration name: ${row.name}`);
      const downName = row.name.replace(/\.up\.sql$/, ".down.sql");
      const sql = await readFile(path.join(directory, downName), "utf8");
      await client.query(sql);
      await client.query("DELETE FROM agent_mandate_schema_migrations WHERE name = $1", [row.name]);
    }
  });
}

async function runCli(): Promise<void> {
  const command = process.argv[2];
  if (command !== "up" && command !== "down") throw new Error("usage: migrations.js <up|down>");
  const connectionString = process.env.DATABASE_URL;
  if (!connectionString) throw new Error("DATABASE_URL is required");
  const pool = createPostgresPool(connectionString, loadDatabaseTimeoutMs(), () => {
    process.stderr.write(`${JSON.stringify({ level: "error", event: "postgres.idle_client_error" })}\n`);
  });
  try {
    if (command === "up") await applyMigrations(pool);
    else await revertMigrations(pool);
  } finally {
    await pool.end();
  }
}

const entrypoint = process.argv[1];
if (entrypoint !== undefined && import.meta.url === pathToFileURL(path.resolve(entrypoint)).href) {
  runCli().catch((error: unknown) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
