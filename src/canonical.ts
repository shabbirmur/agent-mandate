import { createHash } from "node:crypto";
import type { JsonValue } from "./types.js";

/**
 * Serialize the pilot JSON profile deterministically.
 *
 * Object keys are recursively sorted and every value must already be valid
 * JSON. In particular, values that JSON.stringify would silently discard or
 * coerce (undefined, functions, sparse array entries and non-finite numbers)
 * are rejected instead.
 */
export function canonicalJson(value: unknown): string {
  return encode(value, new Set<object>(), "$");
}

/** SHA-256 of the canonical UTF-8 representation, encoded as base64url. */
export function canonicalHash(value: unknown): string {
  return createHash("sha256").update(canonicalJson(value), "utf8").digest("base64url");
}

/** Validate and clone a value into the JSON domain. */
export function toJsonValue(value: unknown): JsonValue {
  return JSON.parse(canonicalJson(value)) as JsonValue;
}

function encode(value: unknown, ancestors: Set<object>, path: string): string {
  if (value === null) return "null";

  switch (typeof value) {
    case "string":
    case "boolean":
      return JSON.stringify(value);
    case "number":
      if (!Number.isFinite(value)) throw invalid(path, "numbers must be finite");
      return JSON.stringify(value);
    case "object":
      break;
    default:
      throw invalid(path, `${typeof value} is not JSON`);
  }

  if (ancestors.has(value)) throw invalid(path, "cyclic values are not JSON");
  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      const items: string[] = [];
      for (let index = 0; index < value.length; index += 1) {
        if (!Object.hasOwn(value, index)) throw invalid(`${path}[${index}]`, "sparse arrays are not JSON");
        items.push(encode(value[index], ancestors, `${path}[${index}]`));
      }
      return `[${items.join(",")}]`;
    }

    const prototype = Object.getPrototypeOf(value) as object | null;
    if (prototype !== Object.prototype && prototype !== null) {
      throw invalid(path, "only plain objects are JSON objects");
    }

    const object = value as Record<string, unknown>;
    const ownKeys = Reflect.ownKeys(object);
    if (ownKeys.some((key) => typeof key === "symbol")) throw invalid(path, "symbol keys are not JSON");
    for (const key of ownKeys as string[]) {
      const descriptor = Object.getOwnPropertyDescriptor(object, key);
      if (!descriptor?.enumerable || !("value" in descriptor)) {
        throw invalid(`${path}.${key}`, "only enumerable data properties are JSON");
      }
    }
    const entries = Object.keys(object)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${encode(object[key], ancestors, `${path}.${key}`)}`);
    return `{${entries.join(",")}}`;
  } finally {
    ancestors.delete(value);
  }
}

function invalid(path: string, reason: string): TypeError {
  return new TypeError(`invalid_json at ${path}: ${reason}`);
}
