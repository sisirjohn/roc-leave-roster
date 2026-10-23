import { serve } from "https://deno.land/std@0.224.0/http/server.ts";

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, apikey, content-type, x-client-info",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

function json(data: unknown, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      ...cors,
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
    },
  });
}

function b64url(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary)
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

function encode(value: unknown): string {
  return b64url(
    new TextEncoder().encode(JSON.stringify(value)),
  );
}

async function issueToken(role: string, secret: string) {
  const now = Math.floor(Date.now() / 1000);
  const head = encode({ alg: "HS256", typ: "JWT" });
  const body = encode({
    role,
    aud: "roc-board",
    iat: now,
    exp: now + 1800,
  });

  const message = `${head}.${body}`;
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(message),
  );

  return `${message}.${b64url(new Uint8Array(signature))}`;
}

serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: cors });
  }

  if (req.method !== "POST") {
    return json({ error: "Method not allowed" }, 405);
  }

  const viewer = Deno.env.get("ROC_VIEWER_CODE");
  const coordinator = Deno.env.get("ROC_COORDINATOR_CODE");
  const signingKey = Deno.env.get("ROC_SESSION_SIGNING_KEY");

  if (!viewer || !coordinator || !signingKey || signingKey.length < 32) {
    return json({ error: "Server configuration incomplete" }, 503);
  }

  let body: { code?: unknown };

  try {
    body = await req.json();
  } catch {
    return json({ error: "Invalid request" }, 400);
  }

  if (
    typeof body.code !== "string" ||
    body.code.length < 1 ||
    body.code.length > 200
  ) {
    return json({ error: "Invalid access code" }, 400);
  }

  let role: "viewer" | "coordinator";

  if (body.code === coordinator) {
    role = "coordinator";
  } else if (body.code === viewer) {
    role = "viewer";
  } else {
    return json({ error: "Invalid access code" }, 401);
  }

  const token = await issueToken(role, signingKey);

  return json({
    access_token: token,
    token_type: "Bearer",
    expires_in: 1800,
    role,
  });
});
