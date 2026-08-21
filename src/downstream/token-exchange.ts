import type { TokenExchangeAdapter } from "../ports.js";
import type { DownstreamCredential } from "../types.js";
import { TokenExchangeAudienceMismatchError, TokenExchangeError } from "./errors.js";

const TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange";
const ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";

export interface HttpTokenExchangeAdapterOptions {
  tokenEndpoint: string;
  clientId: string;
  clientSecret?: string;
  allowedAudiences: readonly string[];
  timeoutMs?: number;
  fetch?: typeof fetch;
  now?: () => Date;
  subjectTokenType?: string;
  /** Defaults to RFC 8707's resource parameter. */
  targetParameter?: "resource" | "audience" | "both";
}

/** RFC 8693 exchange with exact RFC 8707 target-resource enforcement. */
export class HttpTokenExchangeAdapter implements TokenExchangeAdapter {
  readonly #tokenEndpoint: string;
  readonly #clientId: string;
  readonly #clientSecret: string | undefined;
  readonly #allowedAudiences: ReadonlySet<string>;
  readonly #timeoutMs: number;
  readonly #fetch: typeof fetch;
  readonly #now: () => Date;
  readonly #subjectTokenType: string;
  readonly #targetParameter: "resource" | "audience" | "both";

  constructor(options: HttpTokenExchangeAdapterOptions) {
    const endpoint = new URL(options.tokenEndpoint);
    if (endpoint.username || endpoint.password) throw new TypeError("token endpoint must not contain credentials");
    if (options.allowedAudiences.length === 0) throw new TypeError("at least one downstream audience is required");
    this.#tokenEndpoint = endpoint.toString();
    this.#clientId = options.clientId;
    this.#clientSecret = options.clientSecret;
    this.#allowedAudiences = new Set(options.allowedAudiences);
    this.#timeoutMs = options.timeoutMs ?? 3_000;
    this.#fetch = options.fetch ?? globalThis.fetch;
    this.#now = options.now ?? (() => new Date());
    this.#subjectTokenType = options.subjectTokenType ?? ACCESS_TOKEN_TYPE;
    this.#targetParameter = options.targetParameter ?? "resource";
    if (!this.#clientId) throw new TypeError("clientId is required");
    if (!Number.isFinite(this.#timeoutMs) || this.#timeoutMs <= 0) throw new TypeError("timeoutMs must be positive");
  }

  async exchange(input: Parameters<TokenExchangeAdapter["exchange"]>[0]): Promise<DownstreamCredential> {
    if (!this.#allowedAudiences.has(input.audience)) throw new TokenExchangeAudienceMismatchError();
    if (!input.subjectGrant) throw new TokenExchangeError("subject grant is required");

    const body = new URLSearchParams({
      grant_type: TOKEN_EXCHANGE_GRANT,
      subject_token: input.subjectGrant,
      subject_token_type: this.#subjectTokenType,
      requested_token_type: ACCESS_TOKEN_TYPE,
      client_id: this.#clientId,
      scope: input.scope,
    });
    if (this.#targetParameter === "resource" || this.#targetParameter === "both") body.append("resource", input.audience);
    if (this.#targetParameter === "audience" || this.#targetParameter === "both") body.append("audience", input.audience);

    const headers: Record<string, string> = { "content-type": "application/x-www-form-urlencoded" };
    if (this.#clientSecret !== undefined) {
      const basicUser = formEncode(this.#clientId);
      const basicPassword = formEncode(this.#clientSecret);
      headers.authorization = `Basic ${Buffer.from(`${basicUser}:${basicPassword}`, "utf8").toString("base64")}`;
      body.delete("client_id");
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.#timeoutMs);
    try {
      const response = await this.#fetch(this.#tokenEndpoint, {
        method: "POST",
        headers,
        body,
        signal: controller.signal,
      });
      if (!response.ok) throw new TokenExchangeError();
      return parseTokenResponse(await response.json(), input.audience, this.#now());
    } catch (error) {
      if (error instanceof TokenExchangeError) throw error;
      throw new TokenExchangeError();
    } finally {
      clearTimeout(timeout);
    }
  }
}

function parseTokenResponse(value: unknown, expectedAudience: string, now: Date): DownstreamCredential {
  if (!isRecord(value) || typeof value.access_token !== "string" || value.access_token.length === 0) throw new TokenExchangeError();
  if (value.issued_token_type !== ACCESS_TOKEN_TYPE) throw new TokenExchangeError();
  const tokenType = normalizeTokenType(value.token_type);
  if (tokenType === undefined) throw new TokenExchangeError();
  if (typeof value.expires_in !== "number" || !Number.isFinite(value.expires_in) || value.expires_in <= 0) throw new TokenExchangeError();

  const audiences = extractAudiences(value, value.access_token);
  if (audiences.length === 0 || !audiences.includes(expectedAudience)) {
    throw new TokenExchangeAudienceMismatchError();
  }

  return {
    accessToken: value.access_token,
    tokenType,
    audience: expectedAudience,
    expiresAt: new Date(now.getTime() + value.expires_in * 1_000).toISOString(),
  };
}

function normalizeTokenType(value: unknown): DownstreamCredential["tokenType"] | undefined {
  if (typeof value !== "string") return undefined;
  if (value.toLowerCase() === "bearer") return "Bearer";
  if (value.toLowerCase() === "dpop") return "DPoP";
  return undefined;
}

function extractAudiences(response: Record<string, unknown>, accessToken: string): string[] {
  for (const field of [response.audience, response.resource]) {
    if (typeof field === "string") return [field];
    if (Array.isArray(field) && field.every((item) => typeof item === "string")) return field;
  }

  const segments = accessToken.split(".");
  if (segments.length !== 3 || !segments[1]) return [];
  try {
    const payload = JSON.parse(Buffer.from(segments[1], "base64url").toString("utf8")) as unknown;
    if (!isRecord(payload)) return [];
    if (typeof payload.aud === "string") return [payload.aud];
    if (Array.isArray(payload.aud) && payload.aud.every((item) => typeof item === "string")) return payload.aud;
  } catch {
    return [];
  }
  return [];
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function formEncode(value: string): string {
  return new URLSearchParams({ value }).toString().slice("value=".length);
}
