const DATA_KEY = "navigation:data";
const BACKUP_PREFIX = "navigation:backup:";
const LOGIN_PREFIX = "navigation:login:";
const MAX_LOGIN_FAILURES = 5;
const SESSION_COOKIE = "nav_session";
const SECURITY_HEADERS = {
  "content-security-policy": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: https:; connect-src 'self' https://v1.hitokoto.cn; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
  "referrer-policy": "strict-origin-when-cross-origin",
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
  "permissions-policy": "camera=(), microphone=(), geolocation=()",
};

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

function constantTimeEqual(left, right) {
  const a = new TextEncoder().encode(String(left));
  const b = new TextEncoder().encode(String(right));
  let mismatch = a.length ^ b.length;
  for (let i = 0; i < Math.max(a.length, b.length); i++) mismatch |= (a[i] || 0) ^ (b[i] || 0);
  return mismatch === 0;
}

function cookie(request, name) {
  const item = (request.headers.get("cookie") || "").split(/;\s*/).find(value => value.startsWith(`${name}=`));
  return item ? decodeURIComponent(item.slice(name.length + 1)) : "";
}

async function authorized(request, env) {
  const token = cookie(request, SESSION_COOKIE) || (request.headers.get("authorization") || "").replace(/^Bearer\s+/i, "");
  const [payload, signature] = token.split(".");
  if (!payload || !signature || !env.SESSION_SECRET) return false;
  if (!constantTimeEqual(await sign(payload, env.SESSION_SECRET), signature)) return false;
  try {
    const decoded = JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(payload.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0))));
    return decoded.exp > Date.now();
  } catch { return false; }
}

function validData(value) {
  const text = (input, max, required = true) => typeof input === "string" && input.length <= max && (!required || input.trim().length > 0);
  const webUrl = (input, optional = false) => {
    if (optional && (input === undefined || input === "")) return true;
    if (!text(input, 2048)) return false;
    try { return ["http:", "https:"].includes(new URL(input).protocol); } catch { return false; }
  };
  const validLink = link => link && typeof link === "object" && text(link.name, 40) && webUrl(link.url) && text(link.description || "", 100, false) && webUrl(link.icon, true);
  const validEngine = engine => engine && typeof engine === "object" && text(engine.name, 20) && webUrl(engine.url) && text(engine.placeholder || "", 40, false) && webUrl(engine.icon, true);
  if (!value || typeof value !== "object" || !Array.isArray(value.categories) || value.categories.length > 100) return false;
  if (!Array.isArray(value.engines) || value.engines.length < 1 || value.engines.length > 50 || !value.engines.every(validEngine)) return false;
  return value.categories.every(category => category && text(category.id, 80) && text(category.name, 20) && Array.isArray(category.links) && category.links.length <= 500 && category.links.every(validLink));
}

async function loginState(request, env) {
  const ip = request.headers.get("cf-connecting-ip") || "local";
  const key = `${LOGIN_PREFIX}${ip}`;
  return { key, failures: Number(await env.NAV_DATA.get(key)) || 0 };
}

function secure(response) {
  const secured = new Response(response.body, response);
  for (const [name, value] of Object.entries(SECURITY_HEADERS)) secured.headers.set(name, value);
  return secured;
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
    if (url.protocol === "http:" && url.hostname === "c.c0c.cc") {
      url.protocol = "https:";
      return Response.redirect(url, 308);
    }
    if (!url.pathname.startsWith("/api/")) return secure(await env.ASSETS.fetch(request));

    if (url.pathname === "/api/data" && request.method === "GET") {
      const raw = await env.NAV_DATA.get(DATA_KEY);
      return json(raw ? JSON.parse(raw) : null);
    }

    if (url.pathname === "/api/login" && request.method === "POST") {
      if (!env.ADMIN_PASSWORD || !env.SESSION_SECRET) return json({ error: "服务端尚未配置管理密钥" }, 503);
      const state = await loginState(request, env);
      if (state.failures >= MAX_LOGIN_FAILURES) return json({ error: "尝试次数过多，请 10 分钟后再试" }, 429, { "retry-after": "600" });
      const body = await request.json().catch(() => ({}));
      if (!constantTimeEqual(body.password || "", env.ADMIN_PASSWORD)) {
        await env.NAV_DATA.put(state.key, String(state.failures + 1), { expirationTtl: 600 });
        return json({ error: `密码错误，还可尝试 ${MAX_LOGIN_FAILURES-state.failures-1} 次` }, 403);
      }
      await env.NAV_DATA.delete(state.key);
      const token = await createToken(env.SESSION_SECRET);
      const secureCookie = url.protocol === "https:" ? "; Secure" : "";
      return json({ ok: true }, 200, { "set-cookie": `${SESSION_COOKIE}=${encodeURIComponent(token)}; HttpOnly${secureCookie}; SameSite=Strict; Path=/; Max-Age=43200` });
    }

    if (url.pathname === "/api/logout" && request.method === "POST") {
      const secureCookie = url.protocol === "https:" ? "; Secure" : "";
      return json({ ok: true }, 200, { "set-cookie": `${SESSION_COOKIE}=; HttpOnly${secureCookie}; SameSite=Strict; Path=/; Max-Age=0` });
    }

    if (url.pathname === "/api/data" && request.method === "PUT") {
      if (!await authorized(request, env)) return json({ error: "登录已失效" }, 401);
      const body = await request.json().catch(() => null);
      if (!validData(body)) return json({ error: "数据格式无效" }, 400);
      if (JSON.stringify(body).length > 500_000) return json({ error: "数据量超过限制" }, 413);
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
