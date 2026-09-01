#!/usr/bin/env node
import { isIP } from "node:net";

const MAX_RESPONSE_BYTES = 512 * 1024;
const POLL_INTERVAL_MS = 2_000;

class DemoError extends Error {
  constructor(code, detail) {
    super(detail);
    this.name = "DemoError";
    this.code = code;
  }
}

let baseUrl;
let accessToken;
let repository;
let timeoutSeconds;
let title;
let body;

try {
  baseUrl = serviceOrigin(required("AGENT_MANDATE_URL"));
  accessToken = bearerSecret(required("AGENT_MANDATE_ACCESS_TOKEN"));
  repository = repositoryName(required("GITHUB_REPOSITORY"));
  timeoutSeconds = boundedInteger(process.env.AM_DEMO_TIMEOUT_SECONDS ?? "300", 30, 900, "AM_DEMO_TIMEOUT_SECONDS");
  title = boundedText(
    process.env.AM_DEMO_ISSUE_TITLE ?? `Agent Mandate protected issue ${new Date().toISOString()}`,
    1,
    256,
    "AM_DEMO_ISSUE_TITLE",
  );
  body = boundedText(
    process.env.AM_DEMO_ISSUE_BODY ?? "This issue was created through one exact, separately approved Agent Mandate action.",
    0,
    65_000,
    "AM_DEMO_ISSUE_BODY",
  );
  await run();
} catch (error) {
  const failure = error instanceof DemoError
    ? { status: "failed", code: error.code, detail: error.message }
    : { status: "failed", code: "unexpected_failure", detail: "The demonstration stopped safely." };
  process.stderr.write(`${JSON.stringify(failure)}\n`);
  process.exitCode = 1;
}

async function run() {
  const ready = await api("/readyz", { method: "GET", authenticated: false, expected: [200] });
  if (ready.body.ok !== true) throw new DemoError("service_not_ready", "Agent Mandate is not ready.");

  const injected = await api("/v1/product/github/issues/proposals", {
    method: "POST",
    body: {
      repository,
      title,
      body,
      action: "github.repository.delete",
      providerCredential: "prompt-injected-master-key-request",
    },
    expected: [400],
  });
  if (injected.body.error !== "invalid_request") {
    throw new DemoError("drift_not_denied", "The injected authority-drift request was not rejected as expected.");
  }
  print({ step: "authority_drift", status: "denied", reason: "invalid_request" });

  const proposalResponse = await api("/v1/product/github/issues/proposals", {
    method: "POST",
    body: { repository, title, body },
    expected: [202],
  });
  const proposal = exactProposal(proposalResponse.body);
  print({
    step: "approval",
    status: "required",
    requestId: proposal.requestId,
    approvalUrl: proposal.approvalUrl,
    expiresAt: proposal.expiresAt,
    intentHash: proposal.intentHash,
  });
  process.stdout.write("Approve or deny the immutable request in the URL above. The demo will wait without retrying execution.\n");

  const deadline = Math.min(Date.now() + timeoutSeconds * 1_000, Date.parse(proposal.expiresAt));
  let status;
  while (Date.now() < deadline) {
    const response = await api(`/v1/product/approvals/${encodeURIComponent(proposal.requestId)}`, {
      method: "GET",
      expected: [200],
    });
    status = exactStatus(response.body, proposal.requestId);
    if (status.status !== "pending") break;
    await delay(POLL_INTERVAL_MS);
  }
  if (!status || status.status === "pending") throw new DemoError("approval_timeout", "No approval decision arrived before the bounded wait expired.");
  if (status.status !== "approved") {
    print({ step: "approval", status: status.status, requestId: proposal.requestId });
    return;
  }
  print({ step: "approval", status: "approved", requestId: proposal.requestId });

  let resumed;
  try {
    resumed = await api("/v1/product/approvals/resume", {
      method: "POST",
      body: { resumeHandle: proposal.resumeHandle },
      expected: [200],
    });
  } catch (error) {
    if (error instanceof DemoError && error.code === "network_failure") {
      throw new DemoError(
        "execution_response_ambiguous",
        "The resume response was lost. Execution was not retried; inspect status and the receipt before any operator action.",
      );
    }
    throw error;
  }
  const execution = exactExecution(resumed.body, proposal.requestId);
  print({
    step: "execution",
    status: execution.status,
    requestId: execution.requestId,
    receiptId: execution.receiptId,
    issue: execution.issue,
  });
  if (execution.status !== "succeeded") {
    throw new DemoError("execution_not_successful", `Execution ended in terminal state ${execution.status}.`);
  }

  const receiptResponse = await api(`/v1/product/approvals/${encodeURIComponent(proposal.requestId)}/receipt`, {
    method: "GET",
    expected: [200],
  });
  const receipt = exactReceipt(receiptResponse.body, proposal.requestId);
  if (receipt.chainVerified !== true) throw new DemoError("receipt_chain_not_verified", "A receipt was returned but its chain did not verify.");
  print({
    step: "receipt",
    status: "verified",
    requestId: proposal.requestId,
    receiptId: receipt.receiptId,
    outcome: receipt.outcome,
    attemptCount: receipt.attemptCount,
    chainVerified: true,
  });
}

async function api(path, options) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 10_000);
  let response;
  try {
    response = await fetch(new URL(path, baseUrl), {
      method: options.method,
      redirect: "manual",
      headers: {
        accept: "application/json",
        ...(options.authenticated === false ? {} : { authorization: `Bearer ${accessToken}` }),
        ...(options.body === undefined ? {} : { "content-type": "application/json" }),
      },
      ...(options.body === undefined ? {} : { body: JSON.stringify(options.body) }),
      signal: controller.signal,
    });
  } catch {
    throw new DemoError("network_failure", "The Agent Mandate request did not return a trustworthy response.");
  } finally {
    clearTimeout(timer);
  }
  if (response.status >= 300 && response.status < 400) {
    await response.body?.cancel().catch(() => undefined);
    throw new DemoError("redirect_refused", "Unexpected redirects are not followed by the demo client.");
  }
  const text = await boundedResponseText(response);
  let body;
  try {
    body = text ? JSON.parse(text) : {};
  } catch {
    throw new DemoError("invalid_response", "Agent Mandate returned invalid JSON.");
  }
  if (!options.expected.includes(response.status)) {
    const code = isRecord(body) && typeof body.error === "string" ? body.error : "unexpected_http_status";
    throw new DemoError(code, `Agent Mandate returned HTTP ${response.status}.`);
  }
  if (!isRecord(body)) throw new DemoError("invalid_response", "Agent Mandate returned a non-object response.");
  return { status: response.status, body };
}

async function boundedResponseText(response) {
  if (!response.body) return "";
  const reader = response.body.getReader();
  const chunks = [];
  let bytes = 0;
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    bytes += value.byteLength;
    if (bytes > MAX_RESPONSE_BYTES) {
      await reader.cancel().catch(() => undefined);
      throw new DemoError("response_too_large", "Agent Mandate returned an oversized response.");
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks.map((chunk) => Buffer.from(chunk))).toString("utf8");
}

function exactProposal(value) {
  const keys = ["status", "requestId", "resumeHandle", "approvalUrl", "expiresAt", "intentHash"];
  if (!hasExactKeys(value, keys) || value.status !== "approval_required") throw invalidResponse();
  if (!identifier(value.requestId) || !opaque(value.resumeHandle) || !opaque(value.intentHash)) throw invalidResponse();
  if (!safeUrl(value.approvalUrl) || !timestamp(value.expiresAt)) throw invalidResponse();
  return value;
}

function exactStatus(value, requestId) {
  if (!isRecord(value) || value.requestId !== requestId || !["pending", "approved", "denied", "expired", "cancelled"].includes(value.status)) {
    throw invalidResponse();
  }
  return value;
}

function exactExecution(value, requestId) {
  if (!isRecord(value) || value.requestId !== requestId || !["succeeded", "failed", "ambiguous"].includes(value.status)) throw invalidResponse();
  const receipt = isRecord(value.execution) && isRecord(value.execution.receipt) ? value.execution.receipt : undefined;
  const result = isRecord(value.execution) && isRecord(value.execution.result) ? value.execution.result : undefined;
  const issue = result && isRecord(result.body) && typeof result.body.htmlUrl === "string"
    ? { number: result.body.number, title: result.body.title, htmlUrl: result.body.htmlUrl }
    : undefined;
  return { status: value.status, requestId, receiptId: receipt?.id, issue };
}

function exactReceipt(value, requestId) {
  if (!isRecord(value) || value.status !== "available" || value.requestId !== requestId || !isRecord(value.receipt)) throw invalidResponse();
  if (!identifier(value.receipt.id) || !["pending", "succeeded", "failed", "ambiguous"].includes(value.receipt.outcome)) throw invalidResponse();
  if (!Number.isSafeInteger(value.receipt.attemptCount) || value.receipt.attemptCount < 0) throw invalidResponse();
  return {
    receiptId: value.receipt.id,
    outcome: value.receipt.outcome,
    attemptCount: value.receipt.attemptCount,
    chainVerified: value.chainVerified,
  };
}

function invalidResponse() {
  return new DemoError("invalid_response", "Agent Mandate returned a response outside the v0.2 product contract.");
}

function hasExactKeys(value, keys) {
  return isRecord(value) && Object.keys(value).sort().join("\0") === [...keys].sort().join("\0");
}

function required(name) {
  const value = process.env[name]?.trim();
  if (!value) throw new DemoError("missing_configuration", `${name} is required.`);
  return value;
}

function serviceOrigin(value) {
  let url;
  try { url = new URL(value); } catch { throw new DemoError("invalid_configuration", "AGENT_MANDATE_URL must be an absolute URL."); }
  const loopback = url.hostname === "localhost" || url.hostname === "::1" || (isIP(url.hostname) === 4 && url.hostname.startsWith("127."));
  if (url.protocol !== "https:" && !(url.protocol === "http:" && loopback)) throw new DemoError("invalid_configuration", "AGENT_MANDATE_URL must use HTTPS or loopback HTTP.");
  if (url.username || url.password || url.search || url.hash || (url.pathname !== "/" && url.pathname !== "")) throw new DemoError("invalid_configuration", "AGENT_MANDATE_URL must be a secret-free origin.");
  return url.origin;
}

function repositoryName(value) {
  if (!/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})\/[A-Za-z0-9._-]{1,100}$/u.test(value)) throw new DemoError("invalid_configuration", "GITHUB_REPOSITORY must be owner/name.");
  return value;
}

function bearerSecret(value) {
  if (value.length > 128 * 1_024 || /\s/u.test(value)) throw new DemoError("invalid_configuration", "AGENT_MANDATE_ACCESS_TOKEN is malformed.");
  return value;
}

function boundedText(value, minimum, maximum, name) {
  if (typeof value !== "string" || value.length < minimum || value.length > maximum || value.includes("\0")) throw new DemoError("invalid_configuration", `${name} is outside its bound.`);
  return value;
}

function boundedInteger(value, minimum, maximum, name) {
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number < minimum || number > maximum) throw new DemoError("invalid_configuration", `${name} is outside its bound.`);
  return number;
}

function identifier(value) {
  return typeof value === "string" && /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(value);
}

function opaque(value) {
  return typeof value === "string" && /^[A-Za-z0-9_-]{43}$/u.test(value);
}

function safeUrl(value) {
  try {
    const url = new URL(value);
    return (url.protocol === "https:" || (url.protocol === "http:" && ["localhost", "127.0.0.1", "::1"].includes(url.hostname))) && !url.username && !url.password;
  } catch { return false; }
}

function timestamp(value) {
  return typeof value === "string" && Number.isFinite(Date.parse(value));
}

function isRecord(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function print(value) {
  process.stdout.write(`${JSON.stringify(value)}\n`);
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
