import assert from "node:assert/strict";
import test from "node:test";
import { McpExecutionMiddleware, McpToolError, defineMcpTool } from "../src/mcp/index.js";
import type { ActionRequest } from "../src/types.js";

test("MCP middleware derives authority only from trusted metadata and uses HTTP gateway parity", async () => {
  let forwarded: ActionRequest | undefined;
  const middleware = new McpExecutionMiddleware({
    execute: async (request) => {
      forwarded = request;
      return { decision: { allowed: true, code: "allowed", decisionId: "decision-1" } };
    },
  }, [defineMcpTool<{ paymentId: string; amount: number; currency: string }>({
    name: "create_payment",
    audience: "https://payments.sandbox",
    action: "payment.create",
    resource: (args) => `payment:${args.paymentId}`,
    parameters: ({ paymentId: _, ...parameters }) => parameters,
  })]);

  await middleware.execute({
    name: "create_payment",
    arguments: { paymentId: "42", amount: 480, currency: "USD", action: "admin.delete", audience: "https://attacker.example" },
  }, {
    grant: "mandate.secret",
    tenantId: "pilot",
    agentId: "agent:pay",
    workloadId: "workload:pay-1",
    issuer: "https://workload.example",
    subject: "workload-subject",
    taskId: "task:pay-42",
    idempotencyKey: "idem-42",
  });

  assert.equal(forwarded?.action, "payment.create");
  assert.equal(forwarded?.audience, "https://payments.sandbox");
  assert.equal(forwarded?.resource, "payment:42");
  assert.deepEqual(forwarded?.parameters, { amount: 480, currency: "USD", action: "admin.delete", audience: "https://attacker.example" });
});
test("MCP middleware rejects unknown tools and missing authenticated context before gateway", async () => {
  let calls = 0;
  const middleware = new McpExecutionMiddleware({ execute: async () => { calls += 1; throw new Error("not reached"); } }, [{
    name: "pay", action: "payment.create", audience: "https://payments.sandbox", resource: "payment:42",
  }]);
  const context = {
    grant: "mandate.secret", tenantId: "pilot", agentId: "agent:pay", workloadId: "workload:1",
    issuer: "issuer", subject: "subject", taskId: "task:1", idempotencyKey: "idem",
  };
  await assert.rejects(() => middleware.call({ name: "untrusted" }, context), (error: unknown) => error instanceof McpToolError && error.code === "unknown_tool");
  await assert.rejects(() => middleware.call({ name: "pay" }, { ...context, taskId: "" }), (error: unknown) => error instanceof McpToolError && error.code === "missing_identity_or_context");
  assert.equal(calls, 0);
});
