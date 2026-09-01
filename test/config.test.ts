import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { loadConfig } from "../src/config.js";
import { loadProductConfig } from "../src/product/config.js";

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

test("product config requires explicit GitHub, OAuth, and independent 256-bit service keys", () => {
  const environment = productEnvironment();
  const config = loadProductConfig(environment);
  assert.equal(config.publicBaseUrl, "http://127.0.0.1:8788");
  assert.equal(config.host, "127.0.0.1");
  assert.equal(config.productAccess.authorizationUrl, "http://127.0.0.1:9000/authorize");
  assert.equal(config.productAccess.tokenUrl, "http://127.0.0.1:9000/token");
  assert.equal(config.github.repository, "octo/demo");
  assert.equal(config.github.repositoryId, 987654);
  assert.equal(config.github.connectionId, "github-installation:123");
  assert.equal(config.github.privateKeyReference, "env://GITHUB_APP_PRIVATE_KEY");
  assert.equal(config.internalGrantKey.byteLength, 32);
  assert.equal(config.approvalCookieKey.byteLength, 32);

  assert.throws(() => loadProductConfig({ ...environment, INTERNAL_GRANT_KEY: "short" }), /invalid_config:INTERNAL_GRANT_KEY/);
  assert.throws(() => loadProductConfig({ ...environment, PRODUCT_PUBLIC_BASE_URL: "http://public.example" }), /invalid_config:PRODUCT_PUBLIC_BASE_URL/);
  assert.throws(() => loadProductConfig({ ...environment, GITHUB_REPOSITORY: "octo/demo/extra" }), /invalid_config:GITHUB_REPOSITORY/);
  assert.throws(() => loadProductConfig({ ...environment, GITHUB_APP_PRIVATE_KEY: "github-token" }), /invalid_config:GITHUB_APP_PRIVATE_KEY/);
  assert.throws(() => loadProductConfig({ ...environment, PRODUCT_BIND_HOST: "public.example" }), /invalid_config:PRODUCT_BIND_HOST/);
  assert.throws(
    () => loadProductConfig({ ...environment, APPROVAL_OIDC_REDIRECT_URI: "http://127.0.0.1:8788/different" }),
    /invalid_config:APPROVAL_OIDC_REDIRECT_URI/,
  );
});

test("product config accepts deployment secret files and refuses ambiguous secret sources", () => {
  const root = mkdtempSync(join(tmpdir(), "agent-mandate-config-"));
  const grantPath = join(root, "grant");
  const cookiePath = join(root, "cookie");
  const privateKeyPath = join(root, "github.pem");
  const environment = productEnvironment();
  writeFileSync(grantPath, `${environment.INTERNAL_GRANT_KEY}\n`, { mode: 0o600 });
  writeFileSync(cookiePath, `${environment.APPROVAL_COOKIE_KEY}\n`, { mode: 0o600 });
  writeFileSync(privateKeyPath, `${environment.GITHUB_APP_PRIVATE_KEY!.replaceAll("\\n", "\n")}\n`, { mode: 0o600 });
  delete environment.INTERNAL_GRANT_KEY;
  delete environment.APPROVAL_COOKIE_KEY;
  delete environment.GITHUB_APP_PRIVATE_KEY;
  environment.INTERNAL_GRANT_KEY_FILE = grantPath;
  environment.APPROVAL_COOKIE_KEY_FILE = cookiePath;
  environment.GITHUB_APP_PRIVATE_KEY_FILE = privateKeyPath;

  const config = loadProductConfig(environment);
  assert.equal(config.internalGrantKey.byteLength, 32);
  assert.equal(config.approvalCookieKey.byteLength, 32);
  assert.match(config.github.privateKeyPem, /BEGIN PRIVATE KEY/);
  assert.equal(config.github.privateKeyReference, "env://GITHUB_APP_PRIVATE_KEY_FILE");
  assert.throws(
    () => loadProductConfig({ ...environment, INTERNAL_GRANT_KEY: Buffer.alloc(32, 3).toString("base64url") }),
    /invalid_config:INTERNAL_GRANT_KEY/,
  );
});

test("product config accepts the PKCS1 RSA PEM envelope issued by GitHub Apps", () => {
  const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const pem = privateKey.export({ format: "pem", type: "pkcs1" }).toString();
  const config = loadProductConfig({
    ...productEnvironment(),
    GITHUB_APP_PRIVATE_KEY: pem,
  });

  assert.match(config.github.privateKeyPem, /BEGIN RSA PRIVATE KEY/);
});

function productEnvironment(): NodeJS.ProcessEnv {
  return {
    PORT: "8788",
    DATABASE_URL: "postgres://localhost/agent_mandate",
    PRODUCT_PUBLIC_BASE_URL: "http://127.0.0.1:8788",
    INTERNAL_GRANT_KEY: Buffer.alloc(32, 1).toString("base64url"),
    APPROVAL_COOKIE_KEY: Buffer.alloc(32, 2).toString("base64url"),
    PRODUCT_ACCESS_ISSUER: "http://127.0.0.1:9000",
    PRODUCT_ACCESS_AUDIENCE: "agent-mandate-mcp",
    PRODUCT_ACCESS_JWKS_URL: "http://127.0.0.1:9000/jwks.json",
    APPROVAL_OIDC_ISSUER: "http://127.0.0.1:9000",
    APPROVAL_OIDC_JWKS_URL: "http://127.0.0.1:9000/jwks.json",
    APPROVAL_OIDC_AUTHORIZATION_URL: "http://127.0.0.1:9000/authorize",
    APPROVAL_OIDC_TOKEN_URL: "http://127.0.0.1:9000/token",
    APPROVAL_OIDC_CLIENT_ID: "agent-mandate-approval",
    GITHUB_APP_ID: "42",
    GITHUB_APP_PRIVATE_KEY: placeholderPem("PRIVATE KEY"),
    GITHUB_INSTALLATION_ID: "123",
    GITHUB_REPOSITORY_ID: "987654",
    GITHUB_REPOSITORY: "octo/demo",
  };
}

function placeholderPem(label: "PRIVATE KEY" | "RSA PRIVATE KEY"): string {
  const fence = "-----";
  return `${fence}BEGIN ${label}${fence}\\nplaceholder-material-not-used-by-config-tests-0000000000\\n${fence}END ${label}${fence}`;
}
