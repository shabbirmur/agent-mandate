import assert from "node:assert/strict";
import test from "node:test";
import { SignJWT } from "jose";
import {
  IdentityAuthenticationError,
  JwtWorkloadAuthenticator,
  OidcPrincipalAuthenticator,
} from "../src/identity/index.js";

const principalKey = new TextEncoder().encode("principal-test-key-with-at-least-32-bytes");
const otherKey = new TextEncoder().encode("another-test-key-with-at-least-32-bytes!!");
const workloadKey = new TextEncoder().encode("workload-test-key-with-at-least-32-bytes!");

async function signPrincipal(
  claims: Record<string, unknown> = {},
  options: { issuer?: string; audience?: string; key?: Uint8Array; expiration?: number | string; includeExpiration?: boolean } = {},
): Promise<string> {
  let token = new SignJWT({ tenant_id: "pilot", ...claims })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuer(options.issuer ?? "https://id.example")
    .setAudience(options.audience ?? "agent-mandate")
    .setSubject("user:alice")
    .setIssuedAt();
  if (options.includeExpiration !== false) token = token.setExpirationTime(options.expiration ?? "2m");
  return token.sign(options.key ?? principalKey);
}

function principalAuthenticator() {
  return new OidcPrincipalAuthenticator({
    issuer: "https://id.example",
    audience: "agent-mandate",
    verificationKey: principalKey,
    algorithms: ["HS256"],
  });
}

async function rejectsWithCode(promise: Promise<unknown>, code: IdentityAuthenticationError["code"]): Promise<void> {
  await assert.rejects(promise, (error: unknown) => error instanceof IdentityAuthenticationError && error.code === code);
}

test("OIDC validation derives principal identity from verified claims and enforces an exact nonce", async () => {
  const token = await signPrincipal({ nonce: "login-nonce", tenantId: "untrusted-camel-case-value" });
  const context = await principalAuthenticator().authenticate(token, "login-nonce");

  assert.deepEqual(context, {
    tenantId: "pilot",
    principalId: "user:alice",
    issuer: "https://id.example",
    subject: "user:alice",
    nonce: "login-nonce",
  });
  await rejectsWithCode(principalAuthenticator().authenticate(token, "different-nonce"), "invalid_principal");
  await rejectsWithCode(principalAuthenticator().authenticate(await signPrincipal(), "required-but-missing"), "invalid_principal");
});

test("OIDC validation rejects invalid signature, issuer, audience, expiry, and missing expiry", async () => {
  const invalidTokens = [
    await signPrincipal({}, { key: otherKey }),
    await signPrincipal({}, { issuer: "https://attacker.example" }),
    await signPrincipal({}, { audience: "different-service" }),
    await signPrincipal({}, { expiration: Math.floor(Date.now() / 1_000) - 1 }),
    await signPrincipal({}, { includeExpiration: false }),
  ];

  for (const token of invalidTokens) {
    await rejectsWithCode(principalAuthenticator().authenticate(token), "invalid_principal");
  }
});

test("OIDC clock tolerance is explicit and bounded", async () => {
  const tolerant = new OidcPrincipalAuthenticator({
    issuer: "https://id.example",
    audience: "agent-mandate",
    verificationKey: principalKey,
    algorithms: ["HS256"],
    clockToleranceSeconds: 60,
  });
  const now = Math.floor(Date.now() / 1_000);
  assert.equal((await tolerant.authenticate(await signPrincipal({}, { expiration: now - 30 }))).principalId, "user:alice");
  await rejectsWithCode(tolerant.authenticate(await signPrincipal({}, { expiration: now - 61 })), "invalid_principal");
});

test("principal claim names are configurable and non-string identity claims fail closed", async () => {
  const custom = new OidcPrincipalAuthenticator({
    issuer: "https://id.example",
    audience: "agent-mandate",
    verificationKey: principalKey,
    tenantIdClaim: "org",
    principalIdClaim: "actor",
  });
  const context = await custom.authenticate(await signPrincipal({ org: "tenant:custom", actor: "principal:custom" }));
  assert.equal(context.tenantId, "tenant:custom");
  assert.equal(context.principalId, "principal:custom");

  await rejectsWithCode(custom.authenticate(await signPrincipal({ org: ["not", "a", "string"], actor: "principal:custom" })), "invalid_principal");
});

test("workload JWT validation uses a separate trust configuration and derives workload bindings", async () => {
  const authenticator = new JwtWorkloadAuthenticator({
    issuer: "https://workloads.example",
    audience: "agent-mandate-gateway",
    verificationKey: workloadKey,
    algorithms: ["HS256"],
  });
  const token = await new SignJWT({ tenant_id: "pilot", agent_id: "agent:payments", workload_id: "workload:payments-1" })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuer("https://workloads.example")
    .setAudience("agent-mandate-gateway")
    .setSubject("spiffe://pilot/payments-1")
    .setIssuedAt()
    .setExpirationTime("2m")
    .sign(workloadKey);

  assert.deepEqual(await authenticator.authenticate(token), {
    tenantId: "pilot",
    agentId: "agent:payments",
    workloadId: "workload:payments-1",
    issuer: "https://workloads.example",
    subject: "spiffe://pilot/payments-1",
  });
  await rejectsWithCode(authenticator.authenticate(await signPrincipal()), "invalid_workload_identity");
});
