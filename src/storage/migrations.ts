import { readFile, readdir } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { Pool } from "pg";

const MIGRATION_NAME = /^\d+_[a-z0-9_]+\.up\.sql$/;

/** Apply each checked-in up migration exactly once under a database lock. */
export async function applyMigrations(pool: Pool, directory = path.resolve(process.cwd(), "migrations")): Promise<void> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
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
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

/**
 * Apply checked-in down migrations in reverse order. Each SQL file contains its
 * own evidence-retention guard; populated pilot schemas intentionally fail.
 */
export async function revertMigrations(pool: Pool, directory = path.resolve(process.cwd(), "migrations")): Promise<void> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("SELECT pg_advisory_xact_lock($1)", [1_836_279_316]);
    const table = await client.query("SELECT to_regclass('agent_mandate_schema_migrations') AS name");
    if (table.rows[0]?.name === null) {
      await client.query("COMMIT");
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
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

async function runCli(): Promise<void> {
  const command = process.argv[2];
  if (command !== "up" && command !== "down") throw new Error("usage: migrations.js <up|down>");
  const connectionString = process.env.DATABASE_URL;
  if (!connectionString) throw new Error("DATABASE_URL is required");
  const pool = new Pool({ connectionString });
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
