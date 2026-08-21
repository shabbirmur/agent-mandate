import type { IncomingMessage, ServerResponse } from "node:http";

const MAX_BODY_BYTES = 64 * 1024;

export class HttpError extends Error {
  constructor(readonly status: number, readonly code: string) {
    super(code);
  }
}

export async function readJson<T>(request: IncomingMessage, maximumBytes = MAX_BODY_BYTES): Promise<T> {
  if (!request.headers["content-type"]?.toLowerCase().startsWith("application/json")) {
    throw new HttpError(415, "content_type_required");
  }
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of request) {
    const buffer = Buffer.from(chunk);
    size += buffer.length;
    if (size > maximumBytes) throw new HttpError(413, "request_too_large");
    chunks.push(buffer);
  }
  if (size === 0) throw new HttpError(400, "invalid_request");
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8")) as T;
  } catch {
    throw new HttpError(400, "invalid_request");
  }
}

export function bearer(request: IncomingMessage, headerName = "authorization"): string {
  const raw = request.headers[headerName];
  const value = Array.isArray(raw) ? raw[0] : raw;
  if (!value?.startsWith("Bearer ") || value.length === "Bearer ".length) throw new HttpError(401, "invalid_token");
  return value.slice("Bearer ".length);
}

export function requestUrl(request: IncomingMessage): URL {
  return new URL(request.url ?? "/", "http://gateway.local");
}

export function sendJson(response: ServerResponse, status: number, value: unknown): void {
  response.writeHead(status, {
    "content-type": "application/json",
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
  });
  response.end(JSON.stringify(value));
}
