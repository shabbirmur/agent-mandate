import assert from "node:assert/strict";
import { Readable } from "node:stream";
import test from "node:test";
import type { IncomingMessage } from "node:http";
import { HttpError, bearer, readJson } from "../src/http.js";

function request(body: string, contentType = "application/json"): IncomingMessage {
  const stream = Readable.from([body]) as IncomingMessage;
  stream.headers = { "content-type": contentType, authorization: "Bearer token-1" };
  return stream;
}

test("accepts bounded JSON and extracts bearer tokens", async () => {
  const input = request('{"ok":true}');
  assert.deepEqual(await readJson(input), { ok: true });
  assert.equal(bearer(input), "token-1");
  input.headers.authorization = "bearer token-2";
  assert.equal(bearer(input), "token-2");
});

test("rejects ambiguous, whitespace-bearing, and oversized bearer headers", () => {
  const input = request("{}");
  for (const authorization of [
    ["Bearer one", "Bearer two"],
    "Bearer one two",
    "Bearer one,two",
    `Bearer ${"x".repeat(128 * 1_024)}`,
  ]) {
    input.headers.authorization = authorization;
    assert.throws(() => bearer(input), (error: unknown) => error instanceof HttpError && error.status === 401);
  }
});

test("rejects wrong content type and oversized payloads", async () => {
  await assert.rejects(readJson(request("{}", "text/plain")), (error: unknown) => error instanceof HttpError && error.status === 415);
  await assert.rejects(readJson(request('{"value":"too large"}'), 4), (error: unknown) => error instanceof HttpError && error.status === 413);
});
