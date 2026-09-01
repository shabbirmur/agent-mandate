import { createPrivateKey, type KeyObject } from "node:crypto";
import { SignJWT } from "jose";
import type { DownstreamCredential } from "../../types.js";
import { ProviderConfigurationError, ProviderCredentialError } from "../types.js";
import {
  GITHUB_ACCEPT,
  GITHUB_API_ORIGIN,
  GITHUB_API_VERSION,
  GITHUB_TOKEN_RESPONSE_BYTES,
} from "./constants.js";
import { readBoundedJson } from "./bounded-json.js";

type Fetch = (input: string | URL | Request, init?: RequestInit) => Promise<Response>;

export interface GitHubAppCredentialMinterOptions {
  appId: number;
  privateKeyPem: string;
  fetch?: Fetch;
  now?: () => Date;
  timeoutMs?: number;
}

export interface GitHubInstallationCredentialRequest {
  installationId: number;
  repositoryId: number;
}

/**
 * Mints an installation token narrowed to one repository and Issues write.
 * Neither callers nor configuration may replace the GitHub origin, route, or
 * requested permissions.
 */
export class GitHubAppCredentialMinter {
  readonly #appId: number;
  readonly #signingKey: KeyObject;
  readonly #fetch: Fetch;
  readonly #now: () => Date;
  readonly #timeoutMs: number;

  constructor(options: GitHubAppCredentialMinterOptions) {
    if (!Number.isSafeInteger(options.appId) || options.appId <= 0) throw new ProviderConfigurationError();
    if (
      typeof options.privateKeyPem !== "string"
      || options.privateKeyPem.length < 64
      || options.privateKeyPem.length > 64 * 1_024
    ) throw new ProviderConfigurationError();
    const timeoutMs = options.timeoutMs ?? 5_000;
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 30_000) throw new ProviderConfigurationError();

    let signingKey: KeyObject;
    try {
      signingKey = createPrivateKey(options.privateKeyPem);
      if (
        signingKey.type !== "private"
        || signingKey.asymmetricKeyType !== "rsa"
        || (signingKey.asymmetricKeyDetails?.modulusLength ?? 0) < 2_048
      ) throw new Error("unsupported GitHub App signing key");
    } catch {
      throw new ProviderConfigurationError();
    }

    this.#appId = options.appId;
    this.#signingKey = signingKey;
    this.#fetch = options.fetch ?? globalThis.fetch;
    this.#now = options.now ?? (() => new Date());
    this.#timeoutMs = timeoutMs;
  }

  async mint(request: GitHubInstallationCredentialRequest): Promise<DownstreamCredential> {
    validatePositiveSafeInteger(request.installationId);
    validatePositiveSafeInteger(request.repositoryId);
    const now = validNow(this.#now());

    let appJwt: string;
    try {
      appJwt = await new SignJWT({})
        .setProtectedHeader({ alg: "RS256", typ: "JWT" })
        .setIssuer(String(this.#appId))
        .setIssuedAt(Math.floor(now.getTime() / 1_000) - 60)
        .setExpirationTime(Math.floor(now.getTime() / 1_000) + 9 * 60)
        .sign(this.#signingKey);
    } catch {
      throw new ProviderCredentialError();
    }

    const endpoint = `${GITHUB_API_ORIGIN}/app/installations/${request.installationId}/access_tokens`;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.#timeoutMs);
    try {
      const response = await this.#fetch(endpoint, {
        method: "POST",
        redirect: "manual",
        headers: {
          accept: GITHUB_ACCEPT,
          authorization: `Bearer ${appJwt}`,
          "content-type": "application/json",
          "x-github-api-version": GITHUB_API_VERSION,
        },
        body: JSON.stringify({
          repository_ids: [request.repositoryId],
          permissions: { issues: "write" },
        }),
        signal: controller.signal,
      });
      if (isRedirect(response.status) || response.status !== 201) throw new ProviderCredentialError();
      const payload = await readBoundedJson(response, GITHUB_TOKEN_RESPONSE_BYTES);
      return parseCredential(payload, request.repositoryId, now);
    } catch (error) {
      if (error instanceof ProviderCredentialError) throw error;
      throw new ProviderCredentialError();
    } finally {
      clearTimeout(timeout);
    }
  }
}

function parseCredential(value: unknown, repositoryId: number, now: Date): DownstreamCredential {
  if (!isPlainRecord(value)) throw new ProviderCredentialError();
  const token = value.token;
  const expiresAt = value.expires_at;
  if (
    typeof token !== "string"
    || token.length < 8
    || token.length > 8_192
    || /\s/u.test(token)
    || typeof expiresAt !== "string"
  ) throw new ProviderCredentialError();

  const expiry = Date.parse(expiresAt);
  if (!Number.isFinite(expiry) || expiry <= now.getTime() || expiry > now.getTime() + 65 * 60 * 1_000) {
    throw new ProviderCredentialError();
  }
  if (value.repository_selection !== "selected") throw new ProviderCredentialError();
  if (!Array.isArray(value.repositories) || value.repositories.length !== 1) throw new ProviderCredentialError();
  const repository = value.repositories[0];
  if (!isPlainRecord(repository) || repository.id !== repositoryId) throw new ProviderCredentialError();
  if (!isPlainRecord(value.permissions) || value.permissions.issues !== "write") throw new ProviderCredentialError();
  for (const [name, level] of Object.entries(value.permissions)) {
    if (name === "issues" && level === "write") continue;
    if (name === "metadata" && level === "read") continue;
    throw new ProviderCredentialError();
  }

  return {
    accessToken: token,
    tokenType: "Bearer",
    audience: GITHUB_API_ORIGIN,
    expiresAt: new Date(expiry).toISOString(),
  };
}

function validatePositiveSafeInteger(value: number): void {
  if (!Number.isSafeInteger(value) || value <= 0) throw new ProviderCredentialError();
}

function validNow(value: Date): Date {
  if (!(value instanceof Date) || !Number.isFinite(value.getTime())) throw new ProviderCredentialError();
  return new Date(value.getTime());
}

function isRedirect(status: number): boolean {
  return status >= 300 && status < 400;
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}
