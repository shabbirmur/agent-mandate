import assert from "node:assert/strict";
import test from "node:test";
import { loadConfig } from "../src/config.js";

const valid = {
  DATABASE_URL: "postgres://mandate:secret@localhost:5432/mandate",
  OIDC_ISSUER: "https://idp.example",
  OIDC_AUDIENCE: "control",
  OIDC_JWKS_URL: "https://idp.example/jwks",
  WORKLOAD_ISSUER: "https://workload.example",
  WORKLOAD_AUDIENCE: "gateway",
  WORKLOAD_JWKS_URL: "https://workload.example/jwks",
  DOWNSTREAM_AUDIENCE: "https://payments.example",
  TOKEN_EXCHANGE_URL: "https://payments.example/oauth/token",
  TOKEN_EXCHANGE_CLIENT_ID: "mandate",
  TOKEN_EXCHANGE_CLIENT_SECRET: "secret",
  DOWNSTREAM_URL: "https://payments.example",
};

test("loads bounded, explicit pilot configuration", () => {
  const config = loadConfig(valid);
  assert.equal(config.tenantId, "pilot");
  assert.equal(config.databaseTimeoutMs, 1_000);
  assert.equal(config.requestTimeoutMs, 5_000);
  assert.equal(config.oidc.clockToleranceSeconds, 60);
});

test("fails fast for missing secrets and invalid bounds", () => {
  assert.throws(() => loadConfig({ ...valid, TOKEN_EXCHANGE_CLIENT_SECRET: "" }), /missing_config/);
  assert.throws(() => loadConfig({ ...valid, DATABASE_TIMEOUT_MS: "0" }), /invalid_config/);
  assert.throws(() => loadConfig({ ...valid, DATABASE_TIMEOUT_MS: "2000" }), /invalid_config/);
  assert.throws(() => loadConfig({ ...valid, REQUEST_TIMEOUT_MS: "60000" }), /invalid_config/);
});
