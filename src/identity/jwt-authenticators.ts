import {
  createRemoteJWKSet,
  jwtVerify,
  type JWTVerifyGetKey,
  type JWTVerifyOptions,
  type KeyInput,
  type JWTPayload,
} from "jose";
import type { PrincipalAuthenticator, WorkloadAuthenticator } from "../ports.js";
import type { ErrorCode, PrincipalContext, WorkloadContext } from "../types.js";

export type JwtVerificationKey = KeyInput | JWTVerifyGetKey;

interface JwtAuthenticatorConfig {
  issuer: string | readonly string[];
  audience: string | readonly string[];
  verificationKey: JwtVerificationKey;
  /** Optional JWS algorithm allow-list. Key compatibility is always checked by jose. */
  algorithms?: readonly string[];
  clockToleranceSeconds?: number;
}

export interface OidcPrincipalAuthenticatorConfig extends JwtAuthenticatorConfig {
  tenantIdClaim?: string;
  principalIdClaim?: string;
}

export interface JwtWorkloadAuthenticatorConfig extends JwtAuthenticatorConfig {
  tenantIdClaim?: string;
  agentIdClaim?: string;
  workloadIdClaim?: string;
}

export class IdentityAuthenticationError extends Error {
  readonly code: "invalid_principal" | "invalid_workload_identity";

  constructor(code: IdentityAuthenticationError["code"], options?: ErrorOptions) {
    super(code, options);
    this.name = "IdentityAuthenticationError";
    this.code = code;
  }
}

/**
 * Validates a human OIDC JWT before deriving any trusted principal context.
 * Callers may require the exact nonce issued for an individual login attempt.
 */
export class OidcPrincipalAuthenticator implements PrincipalAuthenticator {
  readonly #config: NormalizedJwtConfig;
  readonly #tenantIdClaim: string;
  readonly #principalIdClaim: string;

  constructor(config: OidcPrincipalAuthenticatorConfig) {
    this.#config = normalizeConfig(config);
    this.#tenantIdClaim = normalizeClaimName(config.tenantIdClaim ?? "tenant_id", "tenantIdClaim");
    this.#principalIdClaim = normalizeClaimName(config.principalIdClaim ?? "sub", "principalIdClaim");
  }

  async authenticate(token: string, expectedNonce?: string): Promise<PrincipalContext> {
    const failureCode = "invalid_principal" as const;
    try {
      if (typeof token !== "string" || token.length === 0) throw new Error("missing token");
      if (expectedNonce !== undefined && expectedNonce.length === 0) throw new Error("empty expected nonce");

      const payload = await verify(token, this.#config, [this.#tenantIdClaim, this.#principalIdClaim]);
      const nonce = optionalStringClaim(payload, "nonce", failureCode);
      if (expectedNonce !== undefined && nonce !== expectedNonce) throw new IdentityAuthenticationError(failureCode);

      return {
        tenantId: requiredStringClaim(payload, this.#tenantIdClaim, failureCode),
        principalId: requiredStringClaim(payload, this.#principalIdClaim, failureCode),
        issuer: requiredStringClaim(payload, "iss", failureCode),
        subject: requiredStringClaim(payload, "sub", failureCode),
        ...(nonce !== undefined ? { nonce } : {}),
      };
    } catch (error) {
      if (error instanceof IdentityAuthenticationError) throw error;
      throw new IdentityAuthenticationError(failureCode, { cause: error });
    }
  }
}

/** Validates a separately issued workload JWT and derives all workload identity from its claims. */
export class JwtWorkloadAuthenticator implements WorkloadAuthenticator {
  readonly #config: NormalizedJwtConfig;
  readonly #tenantIdClaim: string;
  readonly #agentIdClaim: string;
  readonly #workloadIdClaim: string;

  constructor(config: JwtWorkloadAuthenticatorConfig) {
    this.#config = normalizeConfig(config);
    this.#tenantIdClaim = normalizeClaimName(config.tenantIdClaim ?? "tenant_id", "tenantIdClaim");
    this.#agentIdClaim = normalizeClaimName(config.agentIdClaim ?? "agent_id", "agentIdClaim");
    this.#workloadIdClaim = normalizeClaimName(config.workloadIdClaim ?? "workload_id", "workloadIdClaim");
  }

  async authenticate(token: string): Promise<WorkloadContext> {
    const failureCode = "invalid_workload_identity" as const;
    try {
      if (typeof token !== "string" || token.length === 0) throw new Error("missing token");

      const payload = await verify(token, this.#config, [this.#tenantIdClaim, this.#agentIdClaim, this.#workloadIdClaim]);
      return {
        tenantId: requiredStringClaim(payload, this.#tenantIdClaim, failureCode),
        agentId: requiredStringClaim(payload, this.#agentIdClaim, failureCode),
        workloadId: requiredStringClaim(payload, this.#workloadIdClaim, failureCode),
        issuer: requiredStringClaim(payload, "iss", failureCode),
        subject: requiredStringClaim(payload, "sub", failureCode),
      };
    } catch (error) {
      if (error instanceof IdentityAuthenticationError) throw error;
      throw new IdentityAuthenticationError(failureCode, { cause: error });
    }
  }
}

/** Production helper for rotating issuer keys published through JWKS. */
export function createRemoteJwtKeyResolver(jwksUri: string | URL): JWTVerifyGetKey {
  return createRemoteJWKSet(typeof jwksUri === "string" ? new URL(jwksUri) : jwksUri);
}

interface NormalizedJwtConfig {
  issuer: string | string[];
  audience: string | string[];
  verificationKey: JwtVerificationKey;
  algorithms?: string[];
  clockToleranceSeconds: number;
}

function normalizeConfig(config: JwtAuthenticatorConfig): NormalizedJwtConfig {
  const issuer = normalizeExpectedClaim(config.issuer, "issuer");
  const audience = normalizeExpectedClaim(config.audience, "audience");
  const clockToleranceSeconds = config.clockToleranceSeconds ?? 0;
  if (!Number.isFinite(clockToleranceSeconds) || clockToleranceSeconds < 0) {
    throw new TypeError("clockToleranceSeconds must be a finite non-negative number");
  }
  if (config.algorithms !== undefined && (config.algorithms.length === 0 || config.algorithms.some((value) => !value))) {
    throw new TypeError("algorithms must be a non-empty list of names");
  }

  return {
    issuer,
    audience,
    verificationKey: config.verificationKey,
    ...(config.algorithms !== undefined ? { algorithms: [...config.algorithms] } : {}),
    clockToleranceSeconds,
  };
}

function normalizeExpectedClaim(value: string | readonly string[], label: string): string | string[] {
  if (typeof value === "string") {
    if (value.length === 0) throw new TypeError(`${label} must not be empty`);
    return value;
  }
  if (value.length === 0 || value.some((item) => item.length === 0)) {
    throw new TypeError(`${label} must be a non-empty string or list`);
  }
  return [...value];
}

function normalizeClaimName(value: string, label: string): string {
  if (value.length === 0) throw new TypeError(`${label} must not be empty`);
  return value;
}

async function verify(token: string, config: NormalizedJwtConfig, identityClaims: readonly string[]): Promise<JWTPayload> {
  const options: JWTVerifyOptions = {
    issuer: config.issuer,
    audience: config.audience,
    requiredClaims: [...new Set(["iss", "aud", "sub", "exp", ...identityClaims])],
    clockTolerance: config.clockToleranceSeconds,
    ...(config.algorithms !== undefined ? { algorithms: config.algorithms } : {}),
  };
  const { payload } = await jwtVerify(token, config.verificationKey, options);
  return payload;
}

function requiredStringClaim(payload: JWTPayload, name: string, code: ErrorCode): string {
  const value = payload[name];
  if (typeof value !== "string" || value.length === 0) {
    throw new IdentityAuthenticationError(asIdentityCode(code));
  }
  return value;
}

function optionalStringClaim(payload: JWTPayload, name: string, code: ErrorCode): string | undefined {
  const value = payload[name];
  if (value === undefined) return undefined;
  if (typeof value !== "string" || value.length === 0) {
    throw new IdentityAuthenticationError(asIdentityCode(code));
  }
  return value;
}

function asIdentityCode(code: ErrorCode): IdentityAuthenticationError["code"] {
  if (code === "invalid_principal" || code === "invalid_workload_identity") return code;
  throw new TypeError("not an identity error code");
}
