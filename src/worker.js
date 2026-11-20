// forms-worker: Netlify Forms, rebuilt on Cloudflare Workers + D1 (+ Workers KV for file uploads, Turnstile for spam).
//
// A page keeps a plain HTML form pointed at POST /f/<site> (or loads GET /forms.js for forms that submit by fetch("/")).
// This Worker checks the page's host, drops honeypot posts, limits bursts, stores each submission in D1 and sends the visitor
// on to the thank-you page. Uploaded files (allowlisted types, 10 MB per submission) are held in KV until a poller moves them
// on and deletes them. Notifications come from a small poller you run that reads unnotified rows from D1 (see README).
// A lead is stored first; files and Turnstile are add-ons that can fail without losing it.
//
// Configuration (wrangler.toml [vars], none of it secret): ALLOWED_HOSTS (required), HASH_SALT, RATE_MAX.
// Optional bindings: UPLOADS (KV namespace) turns file storage on. Optional secret: TURNSTILE_SECRET turns Turnstile checks on.
import FORMS_JS from "./forms.js";

const MAX_BODY = 64 * 1024;
const MAX_MULTIPART = 30 * 1024 * 1024; // hard cap for a multipart post (files over MAX_FILES_TOTAL are noted, not stored)
const MAX_FILES_TOTAL = 10 * 1024 * 1024;
const MAX_FIELDS = 60;
const MAX_VALUE = 5000;
const UPLOAD_TTL = 14 * 24 * 3600; // a file nobody collected expires from KV after 14 days
const CONTROL = new Set(["form-name", "_hp", "_next", "bot-field", "_files", "cf-turnstile-response"]);
const SITE_RX = /^\/f\/([a-z0-9](?:[a-z0-9-]{0,98}[a-z0-9])?)\/?$/;
const FILE_EXT = new Set(["pdf", "png", "jpg", "jpeg", "gif", "webp", "heic", "heif", "bmp", "tif", "tiff", "doc", "docx", "xls",
  "xlsx", "ppt", "pptx", "odt", "ods", "rtf", "txt", "csv"]);
// spam column: 0 = ok, 1 = honeypot (silent, never emailed), 2 = Turnstile token missing or failed (stored and emailed, flagged)

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (url.pathname === "/health") return text("ok", 200);
    if (url.pathname === "/forms.js" && (req.method === "GET" || req.method === "HEAD")) {
      return new Response(req.method === "HEAD" ? null : FORMS_JS, { status: 200, headers: {
        "content-type": "application/javascript; charset=utf-8", "cache-control": "public, max-age=300",
        "access-control-allow-origin": "*", "x-content-type-options": "nosniff" } });
    }
    const m = url.pathname.match(SITE_RX);
    if (!m) return text("Not found", 404);
    const site = m[1];
    const hosts = env.ALLOWED_HOSTS || "";
    const from = sourceUrl(req);
    const ok = from && hostAllowed(from.hostname, hosts);
    const fail = (body, status, extra) => withCors(text(body, status, extra), ok ? from.origin : null);
    if (req.method === "OPTIONS") return withCors(new Response(null, { status: 204 }), ok ? from.origin : null);
    if (req.method !== "POST") return text("Method not allowed", 405, { allow: "POST, OPTIONS" });
    if (!ok) return text("Forbidden: this form only accepts posts from allowed pages.", 403);

    const ctRaw = req.headers.get("content-type") || ""; // the multipart boundary is case-sensitive, so parse with this one
    const ct = ctRaw.toLowerCase();
    const multipart = ct.includes("multipart/form-data");
    const limit = multipart ? MAX_MULTIPART : MAX_BODY;
    if (Number(req.headers.get("content-length") || 0) > limit) return fail("Too large", 413);
    const raw = await req.arrayBuffer();
    if (raw.byteLength > limit) return fail("Too large", 413);
    let fields, files = [];
    try {
      fields = await parseBody(raw, ct, files, ctRaw);
    } catch (e) {
      return fail("Unsupported form encoding", 415);
    }
    if (!fields) return fail("Unsupported form encoding", 415);

    const form = clip(fields["form-name"] || "form", 100);
    const hpName = clip(fields["_hp"] || "bot-field", 100);
    let spam = (fields[hpName] || "").trim() !== "" || (fields["bot-field"] || "").trim() !== "" ? 1 : 0;
    const next = safeNext(fields["_next"], hosts);
    const data = {};
    let n = 0;
    for (const [k, v] of Object.entries(fields)) {
      if (CONTROL.has(k) || k === hpName) continue;
      if (++n > MAX_FIELDS) break;
      data[clip(k, 100)] = clip(v, MAX_VALUE);
    }
    if (!spam && Object.keys(data).length === 0 && files.length === 0) return fail("Empty form", 400);

    const ip = req.headers.get("cf-connecting-ip") || "";
    const ipHash = await sha256(ip + "|" + (env.HASH_SALT || "forms"));
    const rateMax = Number(env.RATE_MAX) || 8; // per visitor, per site, per 10 minutes
    const recent = await env.DB.prepare(
      "SELECT count(*) AS n FROM submissions WHERE ip_hash = ?1 AND site = ?2 AND created_at > datetime('now', '-10 minutes')"
    ).bind(ipHash, site).first();
    if (recent && recent.n >= rateMax) return fail("Too many submissions; please try again in a few minutes.", 429);

    if (!spam && env.TURNSTILE_SECRET) {
      // A missing or failed token never drops a lead: the row is stored flagged (spam = 2) and the poller emails it as unverified.
      if (!(await turnstileOk(env.TURNSTILE_SECRET, fields["cf-turnstile-response"], ip))) spam = 2;
    }

    const ref = refererUrl(req);
    const pageUrl = ref && hostAllowed(ref.hostname, hosts) ? ref : from;
    const page = clip(pageUrl.origin + pageUrl.pathname, 500);
    const ua = clip(req.headers.get("user-agent") || "", 300);
    const r = await env.DB.prepare(
      "INSERT INTO submissions (site, form, page, data, ip_hash, ua, spam) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"
    ).bind(site, form, page, JSON.stringify(data), ipHash, ua, spam).run();
    const id = r && r.meta ? r.meta.last_row_id : null;

    if (id && files.length && spam !== 1) await storeFiles(env, id, files, data).catch(() => {}); // the lead is already stored

    const wantsJson = (req.headers.get("accept") || "").includes("application/json") || ct.includes("application/json");
    if (wantsJson) return withCors(json({ ok: true, id }), from.origin);
    if (next) return new Response(null, { status: 303, headers: { location: next } });
    return thanks(pageUrl);
  },
};

// Files are kept in KV under "<row id>-<n>" with the allowlist and 10 MB per submission; the row's data gets "_files"
// (field, name, size, type, and either key or skipped with the reason). Any failure leaves the lead and notes the file as skipped.
async function storeFiles(env, id, files, data) {
  const meta = [];
  let total = 0;
  let i = 0;
  for (const { field, file } of files.slice(0, 10)) {
    const ext = (file.name.split(".").pop() || "").toLowerCase();
    const m = { field: clip(field, 100), name: clip(file.name, 200), size: file.size, type: clip(file.type, 100) };
    if (!FILE_EXT.has(ext)) m.skipped = "file type not allowed";
    else if (total + file.size > MAX_FILES_TOTAL) m.skipped = "over 10 MB for this submission";
    else if (!env.UPLOADS) m.skipped = "file storage is not configured";
    else {
      const key = id + "-" + ++i;
      try {
        await env.UPLOADS.put(key, await file.arrayBuffer(), { expirationTtl: UPLOAD_TTL, metadata: { name: m.name, type: m.type, size: m.size } });
        m.key = key;
        total += file.size;
      } catch (e) {
        m.skipped = "file storage refused the upload";
      }
    }
    meta.push(m);
  }
  if (meta.length) {
    data._files = meta;
    await env.DB.prepare("UPDATE submissions SET data = ?1 WHERE id = ?2").bind(JSON.stringify(data), id).run();
  }
}

async function turnstileOk(secret, token, ip) {
  if (!token || typeof token !== "string" || token.length > 2048) return false;
  try {
    const body = new URLSearchParams({ secret, response: token });
    if (ip) body.set("remoteip", ip);
    const r = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", { method: "POST", body });
    const d = await r.json();
    return d && d.success === true;
  } catch (e) {
    return false;
  }
}

async function parseBody(raw, ct, files, ctRaw) {
  const out = {};
  if (ct.includes("application/x-www-form-urlencoded")) {
    for (const [k, v] of new URLSearchParams(new TextDecoder().decode(raw))) add(out, k, v);
    return out;
  }
  if (ct.includes("multipart/form-data")) {
    const fd = await new Response(raw, { headers: { "content-type": ctRaw } }).formData();
    for (const [k, v] of fd) {
      if (typeof v === "string") add(out, k, v);
      else if (v && v.size > 0 && v.name) files.push({ field: k, file: v });
    }
    return out;
  }
  if (ct.includes("application/json")) {
    const body = JSON.parse(new TextDecoder().decode(raw));
    if (!body || typeof body !== "object" || Array.isArray(body)) return null;
    for (const [k, v] of Object.entries(body)) add(out, k, typeof v === "string" ? v : JSON.stringify(v));
    return out;
  }
  return null;
}

function add(out, k, v) {
  out[k] = k in out ? out[k] + ", " + v : v; // checkbox groups arrive as repeated keys
}

function sourceUrl(req) {
  for (const h of ["origin", "referer"]) {
    const v = req.headers.get(h);
    if (!v || v === "null") continue;
    try {
      const u = new URL(v);
      if (u.protocol === "https:") return u;
    } catch (e) {}
  }
  return null;
}

function refererUrl(req) {
  try {
    const u = new URL(req.headers.get("referer") || "");
    return u.protocol === "https:" ? u : null;
  } catch (e) {
    return null;
  }
}

export function hostAllowed(host, list) {
  host = String(host || "").toLowerCase();
  for (const raw of String(list).split(",")) {
    const p = raw.trim().toLowerCase();
    if (!p) continue;
    if (p.startsWith("*.") ? host.endsWith(p.slice(1)) && host.length > p.length - 1 : host === p) return true;
  }
  return false;
}

function safeNext(v, list) {
  if (!v) return null;
  try {
    const u = new URL(v);
    return u.protocol === "https:" && hostAllowed(u.hostname, list) ? u.toString() : null;
  } catch (e) {
    return null;
  }
}

function clip(v, n) {
  v = String(v == null ? "" : v);
  return v.length > n ? v.slice(0, n) : v;
}

async function sha256(s) {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return [...new Uint8Array(d)].slice(0, 16).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function text(body, status, headers = {}) {
  return new Response(body, { status, headers: { "content-type": "text/plain; charset=utf-8", ...headers } });
}

function json(obj) {
  return new Response(JSON.stringify(obj), { status: 200, headers: { "content-type": "application/json" } });
}

function withCors(res, origin) {
  if (!origin) return res;
  const h = new Headers(res.headers);
  h.set("access-control-allow-origin", origin);
  h.set("access-control-allow-methods", "POST, OPTIONS");
  h.set("access-control-allow-headers", "content-type, accept");
  h.set("vary", "origin");
  return new Response(res.body, { status: res.status, headers: h });
}

function thanks(from) {
  const back = from.origin + from.pathname;
  const esc = back.replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;");
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex"><title>Thank you</title>
<style>body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;display:grid;place-items:center;min-height:100vh;margin:0;background:#f7f7f5;color:#111}
main{max-width:30rem;padding:2rem;text-align:center}h1{font-size:1.6rem;margin:0 0 .5rem}a{color:#111}</style></head>
<body><main><h1>Thank you</h1><p>Your message was sent. We'll be in touch soon.</p><p><a href="${esc}">Back to the page</a></p></main></body></html>`;
  return new Response(html, { status: 200, headers: { "content-type": "text/html; charset=utf-8", "x-robots-tag": "noindex" } });
}
