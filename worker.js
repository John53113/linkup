const COOKIE_NAME = "linkup_session";
const SESSION_SECONDS = 60 * 60 * 24 * 7;
const PBKDF2_ITERATIONS = 310000;

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...extraHeaders }
  });
}
function cookieValue(request, name) {
  const cookie = request.headers.get("Cookie") || "";
  for (const item of cookie.split(";")) {
    const part = item.trim();
    if (part.startsWith(name + "=")) return decodeURIComponent(part.slice(name.length + 1));
  }
  return null;
}
function sessionCookie(value, maxAge = SESSION_SECONDS) {
  return `${COOKIE_NAME}=${encodeURIComponent(value)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
}
function clearSessionCookie() {
  return `${COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
}
function b64url(bytes) {
  let binary = "";
  for (const b of new Uint8Array(bytes)) binary += String.fromCharCode(b);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/g, "");
}
function fromB64url(value) {
  const base = value.replaceAll("-", "+").replaceAll("_", "/");
  const padded = base + "=".repeat((4 - base.length % 4) % 4);
  return Uint8Array.from(atob(padded), c => c.charCodeAt(0));
}
async function hmacKey(env) {
  return crypto.subtle.importKey("raw", new TextEncoder().encode(env.SESSION_SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}
async function signSession(payload, env) {
  const body = b64url(new TextEncoder().encode(JSON.stringify(payload)));
  const sig = await crypto.subtle.sign("HMAC", await hmacKey(env), new TextEncoder().encode(body));
  return body + "." + b64url(sig);
}
async function verifySession(token, env) {
  if (!token || !token.includes(".")) return null;
  const [body, signature] = token.split(".");
  try {
    const ok = await crypto.subtle.verify("HMAC", await hmacKey(env), fromB64url(signature), new TextEncoder().encode(body));
    if (!ok) return null;
    const payload = JSON.parse(new TextDecoder().decode(fromB64url(body)));
    if (!payload.sub || payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch { return null; }
}
async function hashPin(pin, salt) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(pin), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" }, key, 256);
  return b64url(bits);
}
function validUsername(value) {
  return typeof value === "string" && /^[A-Za-z0-9_]{3,24}$/.test(value);
}
function safeUser(row) {
  return {
    id: row.id,
    username: row.username,
    displayName: row.display_name,
    status: row.status || "",
    avatarUrl: row.avatar_url || "",
    createdAt: row.created_at
  };
}
async function requireUser(request, env) {
  const token = cookieValue(request, COOKIE_NAME);
  const session = await verifySession(token, env);
  if (!session) return null;
  return await env.DB.prepare("SELECT id, username, display_name, status, avatar_url, created_at FROM users WHERE id = ?").bind(session.sub).first();
}
function originAllowed(request) {
  const origin = request.headers.get("Origin");
  if (!origin) return true;
  return new URL(request.url).origin === origin;
}
async function tooManyAttempts(env, ip, username) {
  const row = await env.DB.prepare(
    "SELECT COUNT(*) AS n FROM login_attempts WHERE attempted_at > ? AND (ip = ? OR username = ?)"
  ).bind(Date.now() - 15 * 60 * 1000, ip, username.toLowerCase()).first();
  return (row?.n || 0) >= 10;
}
async function recordAttempt(env, ip, username, success) {
  await env.DB.prepare("INSERT INTO login_attempts (ip, username, success, attempted_at) VALUES (?, ?, ?, ?)")
    .bind(ip, username.toLowerCase(), success ? 1 : 0, Date.now()).run();
  // Opportunistic cleanup; keeps this table from growing forever.
  await env.DB.prepare("DELETE FROM login_attempts WHERE attempted_at < ?").bind(Date.now() - 7 * 24 * 60 * 60 * 1000).run();
}
async function makeSession(user, env) {
  const now = Math.floor(Date.now() / 1000);
  const token = await signSession({ sub: user.id, iat: now, exp: now + SESSION_SECONDS }, env);
  return sessionCookie(token);
}
async function route(request, env) {
  const url = new URL(request.url);
  if (!url.pathname.startsWith("/api/")) return env.ASSETS.fetch(request);
  if (!originAllowed(request)) return json({ error: "Request origin not allowed." }, 403);
  const path = url.pathname.slice(4);
  if (request.method === "GET" && path === "/health") return json({ ok: true, service: "linkup-api" });

  if (request.method === "POST" && (path === "/register" || path === "/login")) {
    let body;
    try { body = await request.json(); } catch { return json({ error: "Invalid request body." }, 400); }
    const username = typeof body.username === "string" ? body.username.trim() : "";
    const pin = typeof body.pin === "string" ? body.pin : "";
    const displayName = typeof body.displayName === "string" ? body.displayName.trim().slice(0, 40) : "";
    if (!validUsername(username)) return json({ error: "Username must be 3–24 letters, numbers or underscores." }, 400);
    if (!/^[0-9]{4}$/.test(pin)) return json({ error: "PIN must be exactly four digits." }, 400);
    const ip = request.headers.get("CF-Connecting-IP") || "unknown";
    if (await tooManyAttempts(env, ip, username)) return json({ error: "Too many attempts. Please wait 15 minutes and try again." }, 429);

    if (path === "/register") {
      const id = crypto.randomUUID();
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const pinHash = await hashPin(pin, salt);
      const finalDisplayName = (displayName || username).slice(0, 40);
      try {
        await env.DB.prepare(
          "INSERT INTO users (id, username, username_norm, pin_salt, pin_hash, display_name, status, avatar_url, created_at) VALUES (?, ?, ?, ?, ?, ?, '', '', ?)"
        ).bind(id, username, username.toLowerCase(), b64url(salt), pinHash, finalDisplayName, new Date().toISOString()).run();
      } catch (e) {
        if (String(e).includes("UNIQUE") || String(e).includes("unique")) return json({ error: "That username is already taken." }, 409);
        throw e;
      }
      await recordAttempt(env, ip, username, true);
      const user = await env.DB.prepare("SELECT id, username, display_name, status, avatar_url, created_at FROM users WHERE id = ?").bind(id).first();
      return json({ user: safeUser(user) }, 201, { "Set-Cookie": await makeSession(user, env) });
    }

    const row = await env.DB.prepare("SELECT * FROM users WHERE username_norm = ?").bind(username.toLowerCase()).first();
    let success = false;
    if (row) {
      const candidate = await hashPin(pin, fromB64url(row.pin_salt));
      success = candidate === row.pin_hash;
    } else {
      // Burn comparable PBKDF2 work for unknown usernames to reduce username timing leaks.
      await hashPin(pin, crypto.getRandomValues(new Uint8Array(16)));
    }
    await recordAttempt(env, ip, username, success);
    if (!success) return json({ error: "Incorrect username or PIN." }, 401);
    const user = await env.DB.prepare("SELECT id, username, display_name, status, avatar_url, created_at FROM users WHERE id = ?").bind(row.id).first();
    return json({ user: safeUser(user) }, 200, { "Set-Cookie": await makeSession(user, env) });
  }

  if (request.method === "POST" && path === "/logout") {
    return json({ ok: true }, 200, { "Set-Cookie": clearSessionCookie() });
  }

  if (request.method === "GET" && path === "/me") {
    const user = await requireUser(request, env);
    if (!user) return json({ error: "Please sign in." }, 401);
    return json({ user: safeUser(user) });
  }

  if (request.method === "PATCH" && path === "/profile") {
    const user = await requireUser(request, env);
    if (!user) return json({ error: "Please sign in." }, 401);
    let body;
    try { body = await request.json(); } catch { return json({ error: "Invalid request body." }, 400); }
    const displayName = typeof body.displayName === "string" ? body.displayName.trim() : "";
    const status = typeof body.status === "string" ? body.status.trim() : "";
    const avatarUrl = typeof body.avatarUrl === "string" ? body.avatarUrl.trim() : "";
    if (!displayName || displayName.length > 40) return json({ error: "Display name must be 1–40 characters." }, 400);
    if (status.length > 160) return json({ error: "Status must be 160 characters or fewer." }, 400);
    if (avatarUrl && (!avatarUrl.startsWith("https://") || avatarUrl.length > 500)) return json({ error: "Avatar URL must be an HTTPS URL under 500 characters." }, 400);
    await env.DB.prepare("UPDATE users SET display_name = ?, status = ?, avatar_url = ? WHERE id = ?")
      .bind(displayName, status, avatarUrl, user.id).run();
    const updated = await env.DB.prepare("SELECT id, username, display_name, status, avatar_url, created_at FROM users WHERE id = ?").bind(user.id).first();
    return json({ user: safeUser(updated) });
  }

  if (request.method === "POST" && path === "/notifications/subscribe") {
    const user = await requireUser(request, env);
    if (!user) return json({ error: "Please sign in." }, 401);
    let body;
    try { body = await request.json(); } catch { return json({ error: "Invalid request body." }, 400); }
    const sub = body.subscription;
    if (!sub || typeof sub.endpoint !== "string" || !sub.endpoint.startsWith("https://") || !sub.keys?.p256dh || !sub.keys?.auth) {
      return json({ error: "Invalid push subscription." }, 400);
    }
    await env.DB.prepare(
      "INSERT INTO push_subscriptions (id, user_id, endpoint, p256dh, auth, created_at) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(endpoint) DO UPDATE SET user_id = excluded.user_id, p256dh = excluded.p256dh, auth = excluded.auth"
    ).bind(crypto.randomUUID(), user.id, sub.endpoint, sub.keys.p256dh, sub.keys.auth, new Date().toISOString()).run();
    return json({ ok: true, message: "Subscription saved. Configure a push sender to deliver notifications." });
  }

  return json({ error: "Not found." }, 404);
}
export default {
  async fetch(request, env) {
    try { return await route(request, env); }
    catch (error) {
      console.error("Linkup request failed:", error);
      return json({ error: "Server error. Please try again later." }, 500);
    }
  }
};
