import { createHash } from "node:crypto";
import { canonicalHash, canonicalJson } from "../canonical.js";
import type { ActionEnvelope } from "../types.js";

export { canonicalJson };

export function sha256Base64Url(value: string | Uint8Array): string {
  return createHash("sha256").update(value).digest("base64url");
}

export function hashActionEnvelope(envelope: ActionEnvelope): string {
  return canonicalHash(envelope);
}
