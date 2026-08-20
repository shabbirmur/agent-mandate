import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { MandateBroker } from "./broker.js";
import type { ActionRequest, MandateRequest } from "./types.js";

const broker = new MandateBroker();
const port = Number(process.env.PORT ?? 8787);

createServer(async (req, res) => {
  try {
    if (req.method === "GET" && req.url === "/healthz") return json(res, 200, { ok: true });
    if (req.method === "POST" && req.url === "/v1/mandates") {
      const mandate = broker.issue(await body<MandateRequest>(req));
      return json(res, 201, { ...mandate, grant: MandateBroker.bearer(mandate), secret: undefined });
    }
    if (req.method === "POST" && req.url === "/v1/authorize") {
      const decision = broker.authorize(await body<ActionRequest>(req));
      return json(res, decision.allowed ? 200 : 403, decision);
    }
    const revoke = req.method === "POST" && req.url?.match(/^\/v1\/mandates\/([^/]+)\/revoke$/);
    if (revoke) {
      const revoked = broker.revoke(revoke[1]!);
      return json(res, revoked ? 200 : 404, { revoked });
    }
    if (req.method === "GET" && req.url === "/v1/audit") return json(res, 200, { events: broker.audit() });
    return json(res, 404, { error: "not_found" });
  } catch (error) {
    return json(res, 400, { error: error instanceof Error ? error.message : "bad_request" });
  }
}).listen(port, "127.0.0.1", () => console.log(`agent-mandate listening on http://127.0.0.1:${port}`));

async function body<T>(req: IncomingMessage): Promise<T> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(Buffer.from(chunk));
  return JSON.parse(Buffer.concat(chunks).toString("utf8")) as T;
}

function json(res: ServerResponse, status: number, value: unknown): void {
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify(value));
}
