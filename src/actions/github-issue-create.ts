import { canonicalHash } from "../canonical.js";
import type { JsonValue } from "../types.js";
import {
  ActionProfileValidationError,
  type ActionProfileManifest,
  type TrustedActionIntent,
  type TrustedActionProfile,
} from "./types.js";

export const GITHUB_PROVIDER_ID = "github" as const;
export const GITHUB_AUDIENCE = "https://api.github.com" as const;
export const GITHUB_ISSUE_CREATE_PROFILE_ID = "github.issue.create.v1" as const;
export const GITHUB_CORRELATION_MARKER_PREFIX = "<!-- agent-mandate-correlation:" as const;

const MAX_TITLE_CHARACTERS = 256;
const MAX_TITLE_BYTES = 1_024;
const MAX_BODY_CHARACTERS = 65_000;
const MAX_BODY_BYTES = 256 * 1_024;
const MAX_CORRELATION_CHARACTERS = 128;
const OWNER = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/;
const REPOSITORY = /^[A-Za-z0-9._-]{1,100}$/;
const CORRELATION = /^[A-Za-z0-9_-]{16,128}$/;

export interface GitHubIssueCreateArguments {
  repository: string;
  title: string;
  body?: string;
}

export interface GitHubRepositoryTarget {
  /** Stable numeric GitHub repository database ID, supplied by trusted connection resolution. */
  repositoryId: number;
  owner: string;
  name: string;
}

export interface CanonicalGitHubIssueParameters extends Record<string, JsonValue> {
  repositoryId: number;
  repository: string;
  title: string;
  body: string;
  correlationId: string;
}

const manifest = deepFreeze({
  id: GITHUB_ISSUE_CREATE_PROFILE_ID,
  providerId: GITHUB_PROVIDER_ID,
  audience: GITHUB_AUDIENCE,
  risk: "consequential",
  requiredPermissions: { issues: "write" },
  tool: {
    name: "github_create_issue",
    description: "Create one exactly approved GitHub issue in a connected repository.",
    inputSchema: {
      type: "object",
      properties: {
        repository: {
          type: "string",
          description: "Connected repository in owner/name form.",
          minLength: 3,
          maxLength: 140,
        },
        title: { type: "string", minLength: 1, maxLength: MAX_TITLE_CHARACTERS },
        body: { type: "string", maxLength: MAX_BODY_CHARACTERS },
      },
      required: ["repository", "title"],
      additionalProperties: false,
    },
  },
  canonicalization: {
    version: 1,
    resource: "github:repository:<base10-safe-integer-id>",
    parameters: ["repositoryId", "repository", "title", "body", "correlationId"],
    repositoryNameSource: "trusted-resolved-target",
    bodyCorrelation: "append-hidden-html-comment-v1",
  },
} satisfies ActionProfileManifest);

export const GITHUB_ISSUE_CREATE_PROFILE_HASH = canonicalHash(manifest);

export const githubIssueCreateProfile: TrustedActionProfile<GitHubIssueCreateArguments, GitHubRepositoryTarget> = Object.freeze({
  manifest,
  profileHash: GITHUB_ISSUE_CREATE_PROFILE_HASH,
  prepare(input: unknown, target: GitHubRepositoryTarget, correlationId: string): TrustedActionIntent {
    const args = parseArguments(input);
    const canonicalTarget = validateTarget(target);
    validateCorrelationId(correlationId);
    if (args.repository.toLowerCase() !== canonicalTarget.fullName.toLowerCase()) invalid();

    const parameters: CanonicalGitHubIssueParameters = {
      repositoryId: canonicalTarget.repositoryId,
      repository: canonicalTarget.fullName,
      title: args.title,
      body: args.body ?? "",
      correlationId,
    };
    return {
      profileId: GITHUB_ISSUE_CREATE_PROFILE_ID,
      profileHash: GITHUB_ISSUE_CREATE_PROFILE_HASH,
      providerId: GITHUB_PROVIDER_ID,
      audience: GITHUB_AUDIENCE,
      action: GITHUB_ISSUE_CREATE_PROFILE_ID,
      risk: "consequential",
      resource: githubRepositoryResource(canonicalTarget.repositoryId),
      parameters,
    };
  },
});

export function githubRepositoryResource(repositoryId: number): string {
  validatePositiveSafeInteger(repositoryId);
  return `github:repository:${repositoryId}`;
}

export function githubCorrelationMarker(correlationId: string): string {
  validateCorrelationId(correlationId);
  return `${GITHUB_CORRELATION_MARKER_PREFIX}${correlationId} -->`;
}

export function bodyWithGithubCorrelation(body: string, correlationId: string): string {
  validateBody(body);
  const marker = githubCorrelationMarker(correlationId);
  return body.length === 0 ? marker : `${body}\n\n${marker}`;
}

export function parseCanonicalGitHubIssueParameters(value: Record<string, JsonValue>): CanonicalGitHubIssueParameters {
  requireExactKeys(value, ["repositoryId", "repository", "title", "body", "correlationId"]);
  const repositoryId = value.repositoryId;
  const repository = value.repository;
  const title = value.title;
  const body = value.body;
  const correlationId = value.correlationId;
  if (
    typeof repositoryId !== "number"
    || typeof repository !== "string"
    || typeof title !== "string"
    || typeof body !== "string"
    || typeof correlationId !== "string"
  ) invalid();
  validatePositiveSafeInteger(repositoryId);
  validateFullName(repository);
  validateTitle(title);
  validateBody(body);
  validateCorrelationId(correlationId);
  return { repositoryId, repository, title, body, correlationId };
}

function parseArguments(value: unknown): Required<GitHubIssueCreateArguments> {
  if (!isPlainRecord(value)) invalid();
  requireExactKeys(value, value.body === undefined ? ["repository", "title"] : ["repository", "title", "body"]);
  if (typeof value.repository !== "string" || typeof value.title !== "string") invalid();
  if (value.body !== undefined && typeof value.body !== "string") invalid();
  validateFullName(value.repository);
  validateTitle(value.title);
  const body = value.body ?? "";
  validateBody(body);
  return { repository: value.repository, title: value.title, body };
}

function validateTarget(target: GitHubRepositoryTarget): GitHubRepositoryTarget & { fullName: string } {
  if (!isPlainRecord(target)) invalid();
  requireExactKeys(target, ["repositoryId", "owner", "name"]);
  if (typeof target.repositoryId !== "number" || typeof target.owner !== "string" || typeof target.name !== "string") invalid();
  validatePositiveSafeInteger(target.repositoryId);
  validateRepositorySegment(target.owner, OWNER);
  validateRepositorySegment(target.name, REPOSITORY);
  if (target.name === "." || target.name === "..") invalid();
  return { ...target, fullName: `${target.owner}/${target.name}` };
}

function validateFullName(value: string): void {
  if (value.length > 140 || value.includes("%") || value.includes("?") || value.includes("#") || value.includes("\\")) invalid();
  const parts = value.split("/");
  if (parts.length !== 2) invalid();
  const owner = parts[0];
  const repository = parts[1];
  if (!owner || !repository) invalid();
  validateRepositorySegment(owner, OWNER);
  validateRepositorySegment(repository, REPOSITORY);
  if (repository === "." || repository === "..") invalid();
}

function validateRepositorySegment(value: string, pattern: RegExp): void {
  if (!pattern.test(value)) invalid();
}

function validateTitle(value: string): void {
  if (
    value.trim().length === 0
    || characterLength(value) > MAX_TITLE_CHARACTERS
    || Buffer.byteLength(value, "utf8") > MAX_TITLE_BYTES
    || /[\u0000\r\n]/u.test(value)
  ) invalid();
}

function validateBody(value: string): void {
  if (
    characterLength(value) > MAX_BODY_CHARACTERS
    || Buffer.byteLength(value, "utf8") > MAX_BODY_BYTES
    || value.includes("\u0000")
    || value.includes(GITHUB_CORRELATION_MARKER_PREFIX)
  ) invalid();
}

function validateCorrelationId(value: string): void {
  if (value.length > MAX_CORRELATION_CHARACTERS || !CORRELATION.test(value)) invalid();
}

function validatePositiveSafeInteger(value: number): void {
  if (!Number.isSafeInteger(value) || value <= 0) invalid();
}

function requireExactKeys(value: Record<string, unknown>, expected: readonly string[]): void {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) invalid();
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function characterLength(value: string): number {
  return Array.from(value).length;
}

function deepFreeze<Value>(value: Value): Readonly<Value> {
  if (typeof value !== "object" || value === null || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function invalid(): never {
  throw new ActionProfileValidationError();
}
