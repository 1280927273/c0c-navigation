const DATA_KEY = "navigation:data";
const BACKUP_PREFIX = "navigation:backup:";

const json = (data, status = 200, headers = {}) => new Response(JSON.stringify(data), {
  status,
  headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...headers },
});

const b64url = (bytes) => btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

async function sign(value, secret) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return b64url(new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(value))));
}

async function createToken(secret) {
  const payload = b64url(new TextEncoder().encode(JSON.stringify({ exp: Date.now() + 12 * 60 * 60 * 1000 })));
  return `${payload}.${await sign(payload, secret)}`;
}

async function authorized(request, env) {
  const token = (request.headers.get("authorization") || "").replace(/^Bearer\s+/i, "");
  const [payload, signature] = token.split(".");
  if (!payload || !signature || !env.SESSION_SECRET) return false;
  if ((await sign(payload, env.SESSION_SECRET)) !== signature) return false;
  try {
    const decoded = JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(payload.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0))));
    return decoded.exp > Date.now();
  } catch { return false; }
}

function validData(value) {
  if (!value || typeof value !== "object" || !Array.isArray(value.categories)) return false;
  return value.categories.every(c => c && typeof c.id === "string" && typeof c.name === "string" && Array.isArray(c.links));
}

async function backup(env, data) {
  const key = `${BACKUP_PREFIX}${new Date().toISOString()}`;
  await env.NAV_DATA.put(key, JSON.stringify(data));
  const list = await env.NAV_DATA.list({ prefix: BACKUP_PREFIX });
  const stale = list.keys.sort((a, b) => b.name.localeCompare(a.name)).slice(10);
  await Promise.all(stale.map(item => env.NAV_DATA.delete(item.name)));
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (!url.pathname.startsWith("/api/")) return env.ASSETS.fetch(request);

    if (url.pathname === "/api/data" && request.method === "GET") {
      const raw = await env.NAV_DATA.get(DATA_KEY);
      return json(raw ? JSON.parse(raw) : null);
    }

    if (url.pathname === "/api/login" && request.method === "POST") {
      if (!env.ADMIN_PASSWORD || !env.SESSION_SECRET) return json({ error: "服务端尚未配置管理密钥" }, 503);
      const body = await request.json().catch(() => ({}));
      if (body.password !== env.ADMIN_PASSWORD) return json({ error: "密码错误" }, 403);
      return json({ token: await createToken(env.SESSION_SECRET) });
    }

    if (url.pathname === "/api/data" && request.method === "PUT") {
      if (!await authorized(request, env)) return json({ error: "登录已失效" }, 401);
      const body = await request.json().catch(() => null);
      if (!validData(body)) return json({ error: "数据格式无效" }, 400);
      const previous = await env.NAV_DATA.get(DATA_KEY, "json");
      if (previous) await backup(env, previous);
      body.updatedAt = new Date().toISOString();
      await env.NAV_DATA.put(DATA_KEY, JSON.stringify(body));
      return json({ ok: true, updatedAt: body.updatedAt });
    }

    if (url.pathname === "/api/session" && request.method === "GET") return json({ valid: await authorized(request, env) });
    return json({ error: "Not found" }, 404);
  },
};
