import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { canonicalHash, canonicalJson } from "../src/canonical.js";

test("canonical JSON recursively sorts keys without mutating input", () => {
  const input = { z: 1, a: { y: true, x: [3, { b: null, a: "value" }] } };
  assert.equal(canonicalJson(input), '{"a":{"x":[3,{"a":"value","b":null}],"y":true},"z":1}');
  assert.deepEqual(Object.keys(input), ["z", "a"]);
});

test("canonical hash is SHA-256 over canonical UTF-8 bytes", () => {
  const canonical = '{"a":"₹","b":2}';
  const expected = createHash("sha256").update(canonical, "utf8").digest("base64url");
  assert.equal(canonicalHash({ b: 2, a: "₹" }), expected);
  assert.equal(canonicalHash({ a: "₹", b: 2 }), expected);
});

test("canonical JSON rejects values JSON would discard or coerce", () => {
  assert.throws(() => canonicalJson({ missing: undefined }), /invalid_json/);
  assert.throws(() => canonicalJson([1, , 2]), /sparse arrays/);
  assert.throws(() => canonicalJson({ value: Number.NaN }), /finite/);
  assert.throws(() => canonicalJson(new Date()), /plain objects/);
  assert.throws(() => canonicalJson({ [Symbol("hidden")]: true }), /symbol keys/);
  const accessor = Object.defineProperty({}, "value", { enumerable: true, get: () => "computed" });
  assert.throws(() => canonicalJson(accessor), /data properties/);
  const cyclic: Record<string, unknown> = {};
  cyclic.self = cyclic;
  assert.throws(() => canonicalJson(cyclic), /cyclic/);
});
