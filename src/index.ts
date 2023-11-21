import { Hono } from "hono";
import { createMiddleware } from "hono/factory";

type Options = {
  secret: string;
};
export function validateWebhook(options: Options) {
  return createMiddleware(async (c, next) => {
    const encoder = new TextEncoder();
    const algorithm = { name: "HMAC", hash: { name: "SHA-256" } };

    const signature = c.req
      .header("X-Hub-Signature-256")
      ?.replace("sha256=", "");
    const rawBody = await new Response(c.req.raw.body).text();

    if (!signature || !rawBody) {
      return;
    }

    const key = await crypto.subtle.importKey(
      "raw",
      encoder.encode(options.secret),
      algorithm,
      false,
      ["sign", "verify"]
    );

    const sigBytes = Uint8Array.from(
      Array.from(signature.matchAll(/.{1,2}/g)).map((v) => parseInt(v[0], 16))
    );
    const dataBytes = encoder.encode(rawBody);
    const equal = await crypto.subtle.verify(
      algorithm.name,
      key,
      sigBytes,
      dataBytes
    );

    if (!equal) {
      return;
    }

    next();
  });
}

const app = new Hono();

app.get("/", validateWebhook({ secret: "secret" }), (c) => c.text("OK"));

export default app;
