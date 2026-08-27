import { readFileSync } from "node:fs";

export interface ProductConfig {
  host: string;
  port: number;
  databaseUrl: string;
  databaseTimeoutMs: number;
  requestTimeoutMs: number;
  tenantId: string;
  publicBaseUrl: string;
  internalGrantKey: Uint8Array;
  approvalCookieKey: Uint8Array;
  productAccess: ProductJwtConfig & {
    authorizationUrl: string;
    tokenUrl: string;
    registrationUrl?: string;
  };
  approvalOidc: ProductJwtConfig & {
    authorizationUrl: string;
    tokenUrl: string;
    clientId: string;
    clientSecret?: string;
    redirectUri: string;
  };
  github: {
    appId: number;
    privateKeyPem: string;
    privateKeyReference: string;
    installationId: number;
    repositoryId: number;
    repository: string;
    connectionId: string;
  };
}

interface ProductJwtConfig {
  issuer: string;
  audience: string;
  jwksUrl: string;
  clockToleranceSeconds: number;
}

export function loadProductConfig(environment: NodeJS.ProcessEnv = process.env): ProductConfig {
  const publicBaseUrl = url(required(environment, "PRODUCT_PUBLIC_BASE_URL"), "PRODUCT_PUBLIC_BASE_URL", true);
  const expectedApprovalRedirect = `${publicBaseUrl}/oauth/callback`;
  const approvalRedirect = url(
    environment.APPROVAL_OIDC_REDIRECT_URI?.trim() || expectedApprovalRedirect,
    "APPROVAL_OIDC_REDIRECT_URI",
    true,
  );
  if (approvalRedirect !== expectedApprovalRedirect) throw new Error("invalid_config:APPROVAL_OIDC_REDIRECT_URI");
  const repository = repositoryName(required(environment, "GITHUB_REPOSITORY"));
  const clockToleranceSeconds = integer(environment.CLOCK_TOLERANCE_SECONDS ?? "60", "CLOCK_TOLERANCE_SECONDS", 0, 300);
  const approvalAuthorizationUrl = url(required(environment, "APPROVAL_OIDC_AUTHORIZATION_URL"), "APPROVAL_OIDC_AUTHORIZATION_URL", true);
  const approvalTokenUrl = url(required(environment, "APPROVAL_OIDC_TOKEN_URL"), "APPROVAL_OIDC_TOKEN_URL", true);
  return {
    host: bindHost(environment.PRODUCT_BIND_HOST?.trim() || "127.0.0.1"),
    port: integer(environment.PORT ?? "8787", "PORT", 1, 65_535),
    databaseUrl: required(environment, "DATABASE_URL"),
    databaseTimeoutMs: integer(environment.DATABASE_TIMEOUT_MS ?? "1000", "DATABASE_TIMEOUT_MS", 100, 1_500),
    requestTimeoutMs: integer(environment.REQUEST_TIMEOUT_MS ?? "5000", "REQUEST_TIMEOUT_MS", 100, 30_000),
    tenantId: environment.AGENT_MANDATE_TENANT_ID?.trim() || "default",
    publicBaseUrl,
    internalGrantKey: secretKey(secretValue(environment, "INTERNAL_GRANT_KEY"), "INTERNAL_GRANT_KEY"),
    approvalCookieKey: secretKey(secretValue(environment, "APPROVAL_COOKIE_KEY"), "APPROVAL_COOKIE_KEY"),
    productAccess: {
      issuer: url(required(environment, "PRODUCT_ACCESS_ISSUER"), "PRODUCT_ACCESS_ISSUER", true),
      audience: required(environment, "PRODUCT_ACCESS_AUDIENCE"),
      jwksUrl: url(required(environment, "PRODUCT_ACCESS_JWKS_URL"), "PRODUCT_ACCESS_JWKS_URL", true),
      clockToleranceSeconds,
      authorizationUrl: url(
        environment.PRODUCT_ACCESS_AUTHORIZATION_URL?.trim() || approvalAuthorizationUrl,
        "PRODUCT_ACCESS_AUTHORIZATION_URL",
        true,
      ),
      tokenUrl: url(
        environment.PRODUCT_ACCESS_TOKEN_URL?.trim() || approvalTokenUrl,
        "PRODUCT_ACCESS_TOKEN_URL",
        true,
      ),
      ...optionalUrl(environment, "PRODUCT_ACCESS_REGISTRATION_URL", "registrationUrl", true),
    },
    approvalOidc: {
      issuer: url(required(environment, "APPROVAL_OIDC_ISSUER"), "APPROVAL_OIDC_ISSUER", true),
      audience: required(environment, "APPROVAL_OIDC_CLIENT_ID"),
      jwksUrl: url(required(environment, "APPROVAL_OIDC_JWKS_URL"), "APPROVAL_OIDC_JWKS_URL", true),
      clockToleranceSeconds,
      authorizationUrl: approvalAuthorizationUrl,
      tokenUrl: approvalTokenUrl,
      clientId: required(environment, "APPROVAL_OIDC_CLIENT_ID"),
      ...optional(environment, "APPROVAL_OIDC_CLIENT_SECRET", "clientSecret"),
      redirectUri: url(approvalRedirect, "APPROVAL_OIDC_REDIRECT_URI", true),
    },
    github: {
      appId: integer(required(environment, "GITHUB_APP_ID"), "GITHUB_APP_ID", 1, Number.MAX_SAFE_INTEGER),
      privateKeyPem: privateKey(secretValue(environment, "GITHUB_APP_PRIVATE_KEY")),
      privateKeyReference: environment.GITHUB_APP_PRIVATE_KEY_FILE?.trim()
        ? "env://GITHUB_APP_PRIVATE_KEY_FILE"
        : "env://GITHUB_APP_PRIVATE_KEY",
      installationId: integer(required(environment, "GITHUB_INSTALLATION_ID"), "GITHUB_INSTALLATION_ID", 1, Number.MAX_SAFE_INTEGER),
      repositoryId: integer(required(environment, "GITHUB_REPOSITORY_ID"), "GITHUB_REPOSITORY_ID", 1, Number.MAX_SAFE_INTEGER),
      repository,
      connectionId: environment.GITHUB_CONNECTION_ID?.trim() || `github-installation:${required(environment, "GITHUB_INSTALLATION_ID")}`,
    },
  };
}

function required(environment: NodeJS.ProcessEnv, name: string): string {
  const value = environment[name]?.trim();
  if (!value) throw new Error(`missing_config:${name}`);
  return value;
}

function secretValue(environment: NodeJS.ProcessEnv, name: string): string {
  const inline = environment[name]?.trim();
  const fileName = `${name}_FILE`;
  const path = environment[fileName]?.trim();
  if (inline && path) throw new Error(`invalid_config:${name}`);
  if (inline) return inline;
  if (!path) throw new Error(`missing_config:${name}`);
  try {
    const value = readFileSync(path, "utf8").trim();
    if (!value || Buffer.byteLength(value, "utf8") > 128 * 1_024) throw new Error("invalid secret file");
    return value;
  } catch {
    throw new Error(`invalid_config:${fileName}`);
  }
}

function optional<Key extends string>(environment: NodeJS.ProcessEnv, name: string, key: Key): { [K in Key]?: string } {
  const value = environment[name]?.trim();
  return value ? { [key]: value } as { [K in Key]?: string } : {};
}

function optionalUrl<Key extends string>(
  environment: NodeJS.ProcessEnv,
  name: string,
  key: Key,
  allowLoopback: boolean,
): { [K in Key]?: string } {
  const value = environment[name]?.trim();
  return value ? { [key]: url(value, name, allowLoopback) } as { [K in Key]?: string } : {};
}

function integer(value: string, name: string, minimum: number, maximum: number): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) throw new Error(`invalid_config:${name}`);
  return parsed;
}

function url(value: string, name: string, allowLoopback: boolean): string {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error(`invalid_config:${name}`);
  }
  const loopback = parsed.hostname === "127.0.0.1" || parsed.hostname === "localhost" || parsed.hostname === "::1";
  if (parsed.protocol !== "https:" && !(allowLoopback && parsed.protocol === "http:" && loopback)) throw new Error(`invalid_config:${name}`);
  if (parsed.username || parsed.password || parsed.hash) throw new Error(`invalid_config:${name}`);
  return parsed.toString().replace(/\/$/, "");
}

function secretKey(value: string, name: string): Uint8Array {
  let decoded: Buffer;
  try {
    decoded = Buffer.from(value, "base64url");
  } catch {
    throw new Error(`invalid_config:${name}`);
  }
  if (decoded.byteLength !== 32 || decoded.toString("base64url") !== value.replace(/=+$/u, "")) throw new Error(`invalid_config:${name}`);
  return decoded;
}

function privateKey(value: string): string {
  const normalized = value.includes("\\n") ? value.replaceAll("\\n", "\n") : value;
  const pkcs8 = hasPemEnvelope(normalized, "PRIVATE KEY");
  const pkcs1 = hasPemEnvelope(normalized, "RSA PRIVATE KEY");
  if (!pkcs8 && !pkcs1) {
    throw new Error("invalid_config:GITHUB_APP_PRIVATE_KEY");
  }
  return normalized;
}

function hasPemEnvelope(value: string, label: "PRIVATE KEY" | "RSA PRIVATE KEY"): boolean {
  const fence = "-----";
  return value.startsWith(`${fence}BEGIN ${label}${fence}\n`)
    && value.endsWith(`\n${fence}END ${label}${fence}`);
}

function repositoryName(value: string): string {
  if (!/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})\/[A-Za-z0-9._-]{1,100}$/.test(value)) throw new Error("invalid_config:GITHUB_REPOSITORY");
  return value;
}

function bindHost(value: string): string {
  if (value === "127.0.0.1" || value === "::1" || value === "0.0.0.0" || value === "::") return value;
  throw new Error("invalid_config:PRODUCT_BIND_HOST");
}
