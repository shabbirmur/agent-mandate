import assert from "node:assert/strict";
import test from "node:test";
import {
  DownstreamExecutionError,
  DownstreamTimeoutError,
  HttpDownstreamExecutor,
  type HttpDownstreamExecutorOptions,
} from "../src/downstream/index.js";
import { ACTION_ENVELOPE_VERSION, type ActionEnvelope, type DownstreamCredential } from "../src/types.js";

const audience = "https://api.github.example";
const secret = "github-installation-token-secret";
const encoder = new TextEncoder();

const envelope: ActionEnvelope = {
  version: ACTION_ENVELOPE_VERSION,
  tenantId: "tenant:one",
  principalId: "user:alice",
  agentId: "agent:coder",
  workloadId: "workload:coder-1",
  taskId: "task:create-issue",
  audience,
  action: "github.issue.create",
  resource: "github:repository:42",
  parameters: { title: "Bounded change", body: "Exact approved body" },
};

const credential: DownstreamCredential = {
  accessToken: secret,
  tokenType: "Bearer",
  audience,
  expiresAt: "2099-01-01T00:00:00.000Z",
};

const execution = {
  envelope,
  credential,
  idempotencyKey: "action-instance-42",
};

function createExecutor(options: Partial<HttpDownstreamExecutorOptions> = {}): HttpDownstreamExecutor {
  return new HttpDownstreamExecutor({
    url: `${audience}/mutations`,
    audience,
    timeoutMs: 100,
    ...options,
  });
}

async function rejectsAmbiguous(promise: Promise<unknown>): Promise<DownstreamTimeoutError> {
  try {
    await promise;
    assert.fail("expected an ambiguous downstream result");
  } catch (error) {
    assert.ok(error instanceof DownstreamTimeoutError);
    assert.equal(error.retryable, false);
    assert.equal(String(error).includes(secret), false);
    return error;
  }
}

test("a hard execution deadline makes an abort-ignoring dispatched fetch ambiguous without retry", async () => {
  let calls = 0;
  const executor = createExecutor({
    timeoutMs: 10,
    fetch: () => {
      calls += 1;
      return new Promise<Response>(() => {});
    },
  });

  await rejectsAmbiguous(executor.execute(execution));
  assert.equal(calls, 1);
});

for (const [name, failure] of [
  ["connection reset", new TypeError(`read ECONNRESET ${secret}`)],
  ["TLS failure", new Error(`certificate verify failed for ${secret}`)],
] as const) {
  test(`${name} after dispatch is ambiguous, fixed-message, and never retried`, async () => {
    let calls = 0;
    const executor = createExecutor({
      fetch: async () => {
        calls += 1;
        throw failure;
      },
    });

    const error = await rejectsAmbiguous(executor.execute(execution));
    assert.equal(error.message, "downstream result is ambiguous");
    assert.equal(calls, 1);
  });
}

test("a truncated response stream is ambiguous and does not leak its transport error", async () => {
  let calls = 0;
  const executor = createExecutor({
    fetch: async () => {
      calls += 1;
      let pulls = 0;
      return new Response(new ReadableStream<Uint8Array>({
        pull(controller) {
          if (pulls++ === 0) controller.enqueue(encoder.encode('{"id":42'));
          else controller.error(new TypeError(`terminated while reading ${secret}`));
        },
      }), { status: 201 });
    },
  });

  await rejectsAmbiguous(executor.execute(execution));
  assert.equal(calls, 1);
});

test("a cleanly ended but malformed declared-JSON response is ambiguous", async () => {
  let calls = 0;
  const executor = createExecutor({
    fetch: async () => {
      calls += 1;
      return new Response('{"id":42', {
        status: 201,
        headers: { "content-type": "application/json" },
      });
    },
  });

  await rejectsAmbiguous(executor.execute(execution));
  assert.equal(calls, 1);
});

test("an unreadable UTF-8 response is ambiguous", async () => {
  let calls = 0;
  const executor = createExecutor({
    fetch: async () => {
      calls += 1;
      return new Response(Uint8Array.from([0xc3, 0x28]), { status: 201 });
    },
  });

  await rejectsAmbiguous(executor.execute(execution));
  assert.equal(calls, 1);
});

test("an oversized response is stopped at the configured byte bound and remains ambiguous", async () => {
  let calls = 0;
  const executor = createExecutor({
    maxResponseBytes: 16,
    fetch: async () => {
      calls += 1;
      return new Response("x".repeat(17), { status: 201 });
    },
  });

  await rejectsAmbiguous(executor.execute(execution));
  assert.equal(calls, 1);
});

test("the response bound cannot be disabled by unsafe configuration", () => {
  assert.throws(() => createExecutor({ maxResponseBytes: 0 }), /maxResponseBytes/);
  assert.throws(() => createExecutor({ maxResponseBytes: 16 * 1024 * 1024 + 1 }), /maxResponseBytes/);
});

test("redirects are requested in manual mode, rejected as ambiguous, and never followed", async () => {
  let calls = 0;
  let redirectMode: RequestRedirect | undefined;
  const executor = createExecutor({
    fetch: async (_url, init) => {
      calls += 1;
      redirectMode = init?.redirect;
      return new Response(null, {
        status: 307,
        headers: { location: "https://attacker.example/capture" },
      });
    },
  });

  await rejectsAmbiguous(executor.execute(execution));
  assert.equal(redirectMode, "manual");
  assert.equal(calls, 1);
});

test("successful response bodies redact credential fields and embedded token values", async () => {
  const executor = createExecutor({
    fetch: async () => new Response(JSON.stringify({
      access_token: secret,
      echoed: `Bearer ${secret}`,
      issue: { id: 42 },
    }), { status: 201 }),
  });

  const result = await executor.execute(execution);
  assert.equal(result.status, 201);
  assert.equal(JSON.stringify(result).includes(secret), false);
  assert.deepEqual(result.body, {
    access_token: "[REDACTED]",
    echoed: "Bearer [REDACTED]",
    issue: { id: 42 },
  });
});

test("reconciliation is separate from mutation dispatch, redacted, and invoked only explicitly", async () => {
  let executeCalls = 0;
  let reconcileCalls = 0;
  const executor = createExecutor({
    fetch: async () => {
      executeCalls += 1;
      throw new TypeError(`socket reset ${secret}`);
    },
    reconcile: async () => {
      reconcileCalls += 1;
      return { status: 200, body: { token: secret, state: "committed" } };
    },
  });

  await rejectsAmbiguous(executor.execute(execution));
  assert.equal(executeCalls, 1);
  assert.equal(reconcileCalls, 0);

  const result = await executor.reconcile(execution);
  assert.equal(reconcileCalls, 1);
  assert.equal(executeCalls, 1);
  assert.deepEqual(result, { status: 200, body: { token: "[REDACTED]", state: "committed" } });
});

test("reconciliation has a hard deadline and bounded output", async () => {
  let calls = 0;
  const stalled = createExecutor({
    timeoutMs: 10,
    reconcile: () => {
      calls += 1;
      return new Promise<never>(() => {});
    },
  });
  assert.equal(await stalled.reconcile(execution), undefined);
  assert.equal(calls, 1);

  const oversized = createExecutor({
    maxResponseBytes: 16,
    reconcile: async () => ({ status: 200, body: "x".repeat(17) }),
  });
  assert.equal(await oversized.reconcile(execution), undefined);
});

test("a provably pre-dispatch proof failure remains failed and never reaches fetch", async () => {
  let calls = 0;
  const executor = createExecutor({
    fetch: async () => {
      calls += 1;
      return new Response("{}", { status: 201 });
    },
    dpopProof: async () => { throw new Error(`proof helper exposed ${secret}`); },
  });

  await assert.rejects(
    executor.execute({ ...execution, credential: { ...credential, tokenType: "DPoP" } }),
    (error: unknown) => (
      error instanceof DownstreamExecutionError
      && !(error instanceof DownstreamTimeoutError)
      && error.message === "DPoP proof generation failed"
      && !String(error).includes(secret)
    ),
  );
  assert.equal(calls, 0);
});
