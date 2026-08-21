export interface AppConfig {
  port: number;
  databaseUrl: string;
  tenantId: string;
  oidc: JwtIssuerConfig;
  workload: JwtIssuerConfig;
  downstreamAudience: string;
  tokenExchangeUrl: string;
  tokenExchangeClientId: string;
  tokenExchangeClientSecret: string;
  downstreamUrl: string;
  requestTimeoutMs: number;
  clockToleranceSeconds: number;
  opaUrl?: string;
}

export interface JwtIssuerConfig {
  issuer: string;
  audience: string;
  jwksUrl: string;
  clockToleranceSeconds: number;
}

export function loadConfig(environment: NodeJS.ProcessEnv = process.env): AppConfig {
  const clockToleranceSeconds = integer(environment.CLOCK_TOLERANCE_SECONDS ?? "60", "CLOCK_TOLERANCE_SECONDS", 0, 300);
  const opaUrl = optionalUrl(environment.OPA_URL, "OPA_URL");
  return {
    port: integer(environment.PORT ?? "8787", "PORT", 1, 65_535),
    databaseUrl: required(environment, "DATABASE_URL"),
    tenantId: environment.PILOT_TENANT_ID ?? "pilot",
    oidc: {
      issuer: url(required(environment, "OIDC_ISSUER"), "OIDC_ISSUER"),
      audience: required(environment, "OIDC_AUDIENCE"),
      jwksUrl: url(required(environment, "OIDC_JWKS_URL"), "OIDC_JWKS_URL"),
      clockToleranceSeconds,
    },
    workload: {
      issuer: url(required(environment, "WORKLOAD_ISSUER"), "WORKLOAD_ISSUER"),
      audience: required(environment, "WORKLOAD_AUDIENCE"),
      jwksUrl: url(required(environment, "WORKLOAD_JWKS_URL"), "WORKLOAD_JWKS_URL"),
      clockToleranceSeconds,
    },
    downstreamAudience: url(required(environment, "DOWNSTREAM_AUDIENCE"), "DOWNSTREAM_AUDIENCE"),
    tokenExchangeUrl: url(required(environment, "TOKEN_EXCHANGE_URL"), "TOKEN_EXCHANGE_URL"),
    tokenExchangeClientId: required(environment, "TOKEN_EXCHANGE_CLIENT_ID"),
    tokenExchangeClientSecret: required(environment, "TOKEN_EXCHANGE_CLIENT_SECRET"),
    downstreamUrl: url(required(environment, "DOWNSTREAM_URL"), "DOWNSTREAM_URL"),
    requestTimeoutMs: integer(environment.REQUEST_TIMEOUT_MS ?? "5000", "REQUEST_TIMEOUT_MS", 100, 30_000),
    clockToleranceSeconds,
    ...(opaUrl ? { opaUrl } : {}),
  };
}

function required(environment: NodeJS.ProcessEnv, name: string): string {
  const value = environment[name]?.trim();
  if (!value) throw new Error(`missing_config:${name}`);
  return value;
}

function integer(value: string, name: string, minimum: number, maximum: number): number {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < minimum || parsed > maximum) throw new Error(`invalid_config:${name}`);
  return parsed;
}

function url(value: string, name: string): string {
  try {
    return new URL(value).toString().replace(/\/$/, "");
  } catch {
    throw new Error(`invalid_config:${name}`);
  }
}

function optionalUrl(value: string | undefined, name: string): string | undefined {
  return value?.trim() ? url(value, name) : undefined;
}
