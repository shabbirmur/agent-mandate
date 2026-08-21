import type { JsonValue } from "../types.js";

const REDACTED = "[REDACTED]";
const CIRCULAR = "[Circular]";

const SECRET_KEYS = /^(?:authorization|auth|proxy-authorization|cookie|set-cookie|token|access[-_]?token|refresh[-_]?token|id[-_]?token|subject[-_]?token|client[-_]?secret|secret|api[-_]?key|apikey|password|passwd|grant|credential|private[-_]?key|otp|pin)$/i;
const PII_KEYS = /^(?:email|e[-_]?mail|phone|phone[-_]?number|mobile|address|street|postal[-_]?code|postcode|full[-_]?name|first[-_]?name|last[-_]?name|date[-_]?of[-_]?birth|dob|ssn|pan|aadhaar)$/i;

export interface RedactionOptions {
  /** Additional exact secret strings known to the caller. */
  secrets?: readonly string[];
  /** Set false only for an access-controlled diagnostic surface. */
  redactPii?: boolean;
}

/**
 * Produce a recursively redacted, JSON-safe value suitable for results, logs,
 * traces and audit details. The input is never mutated.
 */
export function redactSensitive(value: unknown, options: RedactionOptions = {}): JsonValue {
  const secrets = (options.secrets ?? []).filter((secret) => secret.length > 0);
  return visit(value, new Set<object>(), secrets, options.redactPii !== false);
}

/** Redact token-shaped fragments from an otherwise safe error message. */
export function redactMessage(message: string, secrets: readonly string[] = []): string {
  let result = message;
  for (const secret of secrets) {
    if (secret.length > 0) result = result.split(secret).join(REDACTED);
  }
  return result
    .replace(/\b(Bearer|DPoP)\s+[A-Za-z0-9._~+\/-]+=*/gi, `$1 ${REDACTED}`)
    .replace(/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g, REDACTED)
    .replace(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi, REDACTED)
    .replace(/(?:\+?\d[\s().-]*){10,15}/g, REDACTED);
}

function visit(value: unknown, ancestors: Set<object>, secrets: readonly string[], redactPii: boolean): JsonValue {
  if (value === null || typeof value === "boolean") return value;
  if (typeof value === "string") return redactMessage(value, secrets);
  if (typeof value === "number") return Number.isFinite(value) ? value : String(value);
  if (typeof value === "bigint" || typeof value === "symbol" || typeof value === "function" || value === undefined) {
    return `[${typeof value}]`;
  }

  if (ancestors.has(value)) return CIRCULAR;
  ancestors.add(value);
  try {
    if (value instanceof Error) {
      return {
        name: value.name,
        message: redactMessage(value.message, secrets),
      };
    }

    if (Array.isArray(value)) return value.map((item) => visit(item, ancestors, secrets, redactPii));

    const output: Record<string, JsonValue> = {};
    for (const [key, child] of Object.entries(value)) {
      output[key] = SECRET_KEYS.test(key) || (redactPii && PII_KEYS.test(key))
        ? REDACTED
        : visit(child, ancestors, secrets, redactPii);
    }
    return output;
  } finally {
    ancestors.delete(value);
  }
}

export { REDACTED };
