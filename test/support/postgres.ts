import { randomUUID } from "node:crypto";
import test, { type TestContext } from "node:test";
import { Pool } from "pg";
import { applyMigrations } from "../../src/storage/migrations.js";
import { PostgresMandateRepository } from "../../src/storage/postgres.js";

export interface PostgresFixture {
  pool: Pool;
  repository: PostgresMandateRepository;
}

const databaseUrl = process.env.TEST_DATABASE_URL;

export function postgresTest(name: string, body: (fixture: PostgresFixture, context: TestContext) => Promise<void>): void {
  test(name, { skip: databaseUrl === undefined ? "set TEST_DATABASE_URL to run PostgreSQL integration tests" : false }, async (context) => {
    if (databaseUrl === undefined) return;
    const schema = `agent_mandate_test_${randomUUID().replaceAll("-", "")}`;
    const administrator = new Pool({ connectionString: databaseUrl, max: 1 });
    const pool = new Pool({ connectionString: databaseUrl, options: `-c search_path=${schema}`, max: 8 });
    const repository = new PostgresMandateRepository(pool);
    try {
      await administrator.query(`CREATE SCHEMA "${schema}"`);
      await applyMigrations(pool);
      await body({ pool, repository }, context);
    } finally {
      await repository.close().catch(() => undefined);
      await administrator.query(`DROP SCHEMA IF EXISTS "${schema}" CASCADE`);
      await administrator.end();
    }
  });
}
