import {
  ACTION_ENVELOPE_VERSION,
  type ActionEnvelope,
  type DownstreamCredential,
  type DownstreamResult,
  type JsonValue,
} from "../../types.js";
import { canonicalJson } from "../../canonical.js";
import {
  GITHUB_AUDIENCE,
  GITHUB_ISSUE_CREATE_PROFILE_ID,
  bodyWithGithubCorrelation,
  githubRepositoryResource,
  parseCanonicalGitHubIssueParameters,
  type CanonicalGitHubIssueParameters,
} from "../../actions/github-issue-create.js";
import {
  DownstreamAudienceMismatchError,
  DownstreamExecutionError,
  DownstreamTimeoutError,
} from "../../downstream/errors.js";
import type { ProviderExecutionInput, ProviderExecutor } from "../types.js";
import { readBoundedJson } from "./bounded-json.js";
import {
  GITHUB_ACCEPT,
  GITHUB_API_ORIGIN,
  GITHUB_API_VERSION,
  GITHUB_ISSUE_RESPONSE_BYTES,
  GITHUB_RECONCILIATION_RESPONSE_BYTES,
} from "./constants.js";

type Fetch = (input: string | URL | Request, init?: RequestInit) => Promise<Response>;

export interface GitHubIssueExecutorOptions {
  fetch?: Fetch;
  now?: () => Date;
  timeoutMs?: number;
}

export interface GitHubIssueResult extends Record<string, JsonValue> {
  id: number;
  nodeId: string;
  number: number;
  htmlUrl: string;
  state: "open" | "closed";
  title: string;
}

/** Fixed-route GitHub issue executor with correlation-only reconciliation. */
export class GitHubIssueExecutor implements ProviderExecutor {
  readonly #fetch: Fetch;
  readonly #now: () => Date;
  readonly #timeoutMs: number;

  constructor(options: GitHubIssueExecutorOptions = {}) {
    const timeoutMs = options.timeoutMs ?? 5_000;
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 30_000) {
      throw new TypeError("invalid GitHub timeout");
    }
    this.#fetch = options.fetch ?? globalThis.fetch;
    this.#now = options.now ?? (() => new Date());
    this.#timeoutMs = timeoutMs;
  }

  async execute(input: ProviderExecutionInput): Promise<DownstreamResult> {
    const parameters = validateExecutionInput(input, this.#now());
    const { owner, repository } = repositoryParts(parameters.repository);
    const endpoint = issueEndpoint(owner, repository);
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.#timeoutMs);
    try {
      let response: Response;
      try {
        response = await this.#fetch(endpoint, {
          method: "POST",
          redirect: "manual",
          headers: githubHeaders(input.credential),
          body: canonicalJson({
            title: parameters.title,
            body: bodyWithGithubCorrelation(parameters.body, parameters.correlationId),
          }),
          signal: controller.signal,
        });
      } catch {
        // Fetch rejection cannot prove whether GitHub committed the mutation.
        throw new DownstreamTimeoutError();
      }

      if (isRedirect(response.status)) throw new DownstreamTimeoutError();
      if (response.status >= 500 || (response.status >= 200 && response.status !== 201)) {
        throw new DownstreamTimeoutError();
      }
      if (response.status !== 201) {
        return { status: response.status, body: { error: "github_request_failed" } };
      }

      try {
        const payload = await readBoundedJson(response, GITHUB_ISSUE_RESPONSE_BYTES);
        return { status: 201, body: allowlistedIssue(payload, parameters) };
      } catch {
        // A 201 with an unreadable response means the side effect is already committed.
        throw new DownstreamTimeoutError();
      }
    } finally {
      clearTimeout(timeout);
    }
  }

  async reconcile(input: ProviderExecutionInput): Promise<DownstreamResult | undefined> {
    let parameters: CanonicalGitHubIssueParameters;
    try {
      parameters = validateExecutionInput(input, this.#now());
    } catch {
      return undefined;
    }
    const { owner, repository } = repositoryParts(parameters.repository);
    const endpoint = `${issueEndpoint(owner, repository)}?state=all&sort=created&direction=desc&per_page=100`;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.#timeoutMs);
    try {
      const response = await this.#fetch(endpoint, {
        method: "GET",
        redirect: "manual",
        headers: githubHeaders(input.credential),
        signal: controller.signal,
      });
      if (response.status !== 200 || isRedirect(response.status)) return undefined;
      const payload = await readBoundedJson(response, GITHUB_RECONCILIATION_RESPONSE_BYTES);
      if (!Array.isArray(payload)) return undefined;

      const matches: GitHubIssueResult[] = [];
      for (const candidate of payload) {
        try {
          matches.push(allowlistedIssue(candidate, parameters));
        } catch {
          // Non-matching issues are expected in the repository listing.
        }
      }
      return matches.length === 1 ? { status: 200, body: matches[0]! } : undefined;
    } catch {
      return undefined;
    } finally {
      clearTimeout(timeout);
    }
  }
}

function validateExecutionInput(input: ProviderExecutionInput, now: Date): CanonicalGitHubIssueParameters {
  const envelope = input.envelope;
  if (
    envelope.version !== ACTION_ENVELOPE_VERSION
    || envelope.audience !== GITHUB_AUDIENCE
    || envelope.action !== GITHUB_ISSUE_CREATE_PROFILE_ID
  ) throw new DownstreamExecutionError("github_action_binding_invalid");

  const parameters = parseCanonicalGitHubIssueParameters(envelope.parameters);
  if (
    envelope.resource !== githubRepositoryResource(parameters.repositoryId)
    || input.idempotencyKey !== parameters.correlationId
  ) throw new DownstreamExecutionError("github_action_binding_invalid");
  validateCredential(input.credential, now);
  return parameters;
}

function validateCredential(credential: DownstreamCredential, now: Date): void {
  if (credential.audience !== GITHUB_API_ORIGIN) throw new DownstreamAudienceMismatchError();
  if (credential.tokenType !== "Bearer" || !credential.accessToken || /\s/u.test(credential.accessToken)) {
    throw new DownstreamExecutionError("github_credential_invalid");
  }
  const expiry = Date.parse(credential.expiresAt);
  if (!Number.isFinite(now.getTime()) || !Number.isFinite(expiry) || expiry <= now.getTime()) {
    throw new DownstreamExecutionError("github_credential_invalid");
  }
}

function allowlistedIssue(value: unknown, parameters: CanonicalGitHubIssueParameters): GitHubIssueResult {
  if (!isPlainRecord(value)) throw new DownstreamExecutionError("github_response_invalid");
  const id = value.id;
  const nodeId = value.node_id;
  const number = value.number;
  const htmlUrl = value.html_url;
  const repositoryUrl = value.repository_url;
  const state = value.state;
  const title = value.title;
  const body = value.body;
  const expectedBody = bodyWithGithubCorrelation(parameters.body, parameters.correlationId);
  if (
    !isPositiveSafeInteger(id)
    || typeof nodeId !== "string"
    || nodeId.length < 1
    || nodeId.length > 256
    || !isPositiveSafeInteger(number)
    || typeof htmlUrl !== "string"
    || typeof repositoryUrl !== "string"
    || (state !== "open" && state !== "closed")
    || title !== parameters.title
    || body !== expectedBody
  ) throw new DownstreamExecutionError("github_response_invalid");

  const { owner, repository } = repositoryParts(parameters.repository);
  requireRepositoryUrl(repositoryUrl, owner, repository);
  requireIssueUrl(htmlUrl, owner, repository, number);
  return { id, nodeId, number, htmlUrl, state, title };
}

function githubHeaders(credential: DownstreamCredential): Record<string, string> {
  return {
    accept: GITHUB_ACCEPT,
    authorization: `Bearer ${credential.accessToken}`,
    "content-type": "application/json",
    "x-github-api-version": GITHUB_API_VERSION,
  };
}

function issueEndpoint(owner: string, repository: string): string {
  return `${GITHUB_API_ORIGIN}/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repository)}/issues`;
}

function repositoryParts(fullName: string): { owner: string; repository: string } {
  const [owner, repository] = fullName.split("/");
  if (!owner || !repository) throw new DownstreamExecutionError("github_action_binding_invalid");
  return { owner, repository };
}

function requireRepositoryUrl(value: string, owner: string, repository: string): void {
  const url = safeUrl(value);
  const expectedPath = `/repos/${owner}/${repository}`.toLowerCase();
  if (
    url.protocol !== "https:"
    || url.hostname !== "api.github.com"
    || url.port !== ""
    || url.username !== ""
    || url.password !== ""
    || url.search !== ""
    || url.hash !== ""
    || url.pathname.toLowerCase() !== expectedPath
  ) throw new DownstreamExecutionError("github_response_invalid");
}

function requireIssueUrl(value: string, owner: string, repository: string, issueNumber: number): void {
  const url = safeUrl(value);
  const expectedPath = `/${owner}/${repository}/issues/${issueNumber}`.toLowerCase();
  if (
    url.protocol !== "https:"
    || url.hostname !== "github.com"
    || url.port !== ""
    || url.username !== ""
    || url.password !== ""
    || url.search !== ""
    || url.hash !== ""
    || url.pathname.toLowerCase() !== expectedPath
  ) throw new DownstreamExecutionError("github_response_invalid");
}

function safeUrl(value: string): URL {
  try {
    return new URL(value);
  } catch {
    throw new DownstreamExecutionError("github_response_invalid");
  }
}

function isRedirect(status: number): boolean {
  return status >= 300 && status < 400;
}

function isPositiveSafeInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0;
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}
