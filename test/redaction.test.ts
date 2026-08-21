import assert from "node:assert/strict";
import test from "node:test";
import { redactMessage, redactSensitive } from "../src/security/redaction.js";

test("redaction recursively removes secrets and PII without mutating input", () => {
  const input = {
    access_token: "downstream-secret",
    profile: { email: "alice@example.com", phoneNumber: "+919876543210", display: "okay" },
    nested: [{ authorization: "Bearer downstream-secret", amount: 480 }],
  };
  const output = redactSensitive(input);
  assert.deepEqual(output, {
    access_token: "[REDACTED]",
    profile: { email: "[REDACTED]", phoneNumber: "[REDACTED]", display: "okay" },
    nested: [{ authorization: "[REDACTED]", amount: 480 }],
  });
  assert.equal(input.access_token, "downstream-secret");
});
test("redaction strips known secrets and bearer/JWT fragments from messages and errors", () => {
  const secret = "opaque-downstream-credential";
  assert.equal(redactMessage(`failed Bearer ${secret}`, [secret]), "failed Bearer [REDACTED]");
  const output = redactSensitive(new Error(`transport exposed ${secret}`), { secrets: [secret] });
  assert.equal(JSON.stringify(output).includes(secret), false);
});
