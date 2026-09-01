import { jwtVerify, type JWTVerifyGetKey, type JWTVerifyOptions, type KeyInput, type JWTPayload } from "jose";
import { canonicalHash } from "../canonical.js";
import type { ProductContext } from "../product/index.js";

export interface AuthenticatedProductContext extends ProductContext {
  oauthClientId: string;
  accessExpiresAt: number;
  accessScopes: readonly string[];
}

export interface ProductAccessAuthenticator {
  authenticate(token: string): Promise<AuthenticatedProductContext>;
}

export interface JwtProductAccessAuthenticatorConfig {
  issuer: string | readonly string[];
  audience: string | readonly string[];
  verificationKey: KeyInput | JWTVerifyGetKey;
  algorithms?: readonly string[];
  clockToleranceSeconds?: number;
  tenantIdClaim?: string;
  principalIdClaim?: string;
  agentIdClaim?: string;
  workloadIdClaim?: string;
  clientIdClaim?: string;
  requiredScope?: string;
}

/**
 * Authenticates the single OAuth/JWT token presented to the product MCP/API
 * surface. Every product context field comes from verified claims; tool
 * arguments and bridge headers are ignored as identity authorities.
 */
export class JwtProductAccessAuthenticator implements ProductAccessAuthenticator {
  readonly #config: JwtProductAccessAuthenticatorConfig;
  readonly #claims: Required<Pick<JwtProductAccessAuthenticatorConfig,
    "tenantIdClaim" | "principalIdClaim" | "agentIdClaim" | "workloadIdClaim" | "clientIdClaim"
  >>;

  constructor(config: JwtProductAccessAuthenticatorConfig) {
    validateExpected(config.issuer, "issuer");
    validateExpected(config.audience, "audience");
    if (config.algorithms !== undefined && (config.algorithms.length === 0 || config.algorithms.some((value) => !value))) {
      throw new TypeError("algorithms must contain non-empty names");
    }
    if ((config.clockToleranceSeconds ?? 0) < 0) throw new TypeError("clockToleranceSeconds must be non-negative");
    this.#config = config;
    this.#claims = {
      tenantIdClaim: claimName(config.tenantIdClaim ?? "tenant_id"),
      principalIdClaim: claimName(config.principalIdClaim ?? "sub"),
      agentIdClaim: claimName(config.agentIdClaim ?? "agent_id"),
      workloadIdClaim: claimName(config.workloadIdClaim ?? "workload_id"),
      clientIdClaim: claimName(config.clientIdClaim ?? "client_id"),
    };
  }

  async authenticate(token: string): Promise<AuthenticatedProductContext> {
    try {
      if (!token || token.length > 128 * 1_024 || /\s/u.test(token)) throw new Error("missing or malformed access token");
      const requiredClaims = [
        "iss", "aud", "sub", "exp", "iat",
        this.#claims.tenantIdClaim,
        this.#claims.principalIdClaim,
        this.#claims.agentIdClaim,
        this.#claims.workloadIdClaim,
      ];
      const options: JWTVerifyOptions = {
        issuer: normalizeExpected(this.#config.issuer),
        audience: normalizeExpected(this.#config.audience),
        requiredClaims: [...new Set(requiredClaims)],
        clockTolerance: this.#config.clockToleranceSeconds ?? 0,
        ...(this.#config.algorithms === undefined ? {} : { algorithms: [...this.#config.algorithms] }),
      };
      const { payload } = await jwtVerify(token, this.#config.verificationKey, options);
      const scopes = requireScope(payload, this.#config.requiredScope);
      const issuer = stringClaim(payload, "iss");
      const subject = stringClaim(payload, "sub");
      const tenantId = stringClaim(payload, this.#claims.tenantIdClaim);
      const principalId = stringClaim(payload, this.#claims.principalIdClaim);
      const agentId = stringClaim(payload, this.#claims.agentIdClaim);
      const workloadId = stringClaim(payload, this.#claims.workloadIdClaim);
      const clientId = optionalStringClaim(payload, this.#claims.clientIdClaim) ?? optionalStringClaim(payload, "azp");
      if (clientId === undefined) throw new ProductAccessAuthenticationError();
      const expiresAt = payload.exp;
      const issuedAt = payload.iat;
      if (!Number.isSafeInteger(expiresAt) || expiresAt! <= 0) throw new ProductAccessAuthenticationError();
      if (!Number.isSafeInteger(issuedAt) || issuedAt! <= 0) throw new ProductAccessAuthenticationError();
      return {
        tenantId,
        principalId,
        agentId,
        workloadId,
        // Token refreshes commonly rotate jti. Bind approval resume to the
        // verified OAuth client and workload identity so refresh is seamless
        // without accepting a caller-supplied session identifier.
        mcpSessionId: canonicalHash({ issuer, subject, tenantId, principalId, agentId, workloadId, clientId }),
        oauthClientId: clientId,
        accessExpiresAt: expiresAt!,
        accessScopes: scopes,
      };
    } catch (error) {
      if (error instanceof ProductAccessAuthenticationError) throw error;
      throw new ProductAccessAuthenticationError({ cause: error });
    }
  }
}

export class ProductAccessAuthenticationError extends Error {
  readonly code = "invalid_product_access_token" as const;

  constructor(options?: ErrorOptions) {
    super("invalid_product_access_token", options);
    this.name = "ProductAccessAuthenticationError";
  }
}

function requireScope(payload: JWTPayload, required: string | undefined): readonly string[] {
  const scope = payload.scope;
  if (typeof scope !== "string" || scope.length > 4_096 || /[\u0000-\u001f\u007f]/u.test(scope)) throw new ProductAccessAuthenticationError();
  const scopes = [...new Set(scope.split(/\s+/u).filter(Boolean))];
  if (
    scopes.length === 0
    || scopes.length > 64
    || scopes.some((value) => value.length > 256)
    || required !== undefined && !scopes.includes(required)
  ) throw new ProductAccessAuthenticationError();
  return Object.freeze(scopes);
}

function stringClaim(payload: JWTPayload, name: string): string {
  const value = payload[name];
  if (typeof value !== "string" || value.length === 0 || value.length > 512 || /[\u0000-\u001f\u007f]/u.test(value)) {
    throw new ProductAccessAuthenticationError();
  }
  return value;
}

function optionalStringClaim(payload: JWTPayload, name: string): string | undefined {
  const value = payload[name];
  if (value === undefined) return undefined;
  if (typeof value !== "string" || value.length === 0 || value.length > 512 || /[\u0000-\u001f\u007f]/u.test(value)) {
    throw new ProductAccessAuthenticationError();
  }
  return value;
}

function claimName(value: string): string {
  if (!value) throw new TypeError("claim names must not be empty");
  return value;
}

function validateExpected(value: string | readonly string[], label: string): void {
  if (typeof value === "string" ? value.length === 0 : value.length === 0 || value.some((item) => !item)) {
    throw new TypeError(`${label} must not be empty`);
  }
}

function normalizeExpected(value: string | readonly string[]): string | string[] {
  return typeof value === "string" ? value : [...value];
}
