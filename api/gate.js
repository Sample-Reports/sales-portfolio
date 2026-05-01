// api/gate.js — sales portfolio gate.
// Verifies iv_session JWT cookie. Sales scope is enforced later (phase 3);
// for now this re-uses the existing gateway allowlist.

export const config = { runtime: 'edge' };

const PORTAL_BASE = 'https://portal.infovisionsocial.com';

function readCookie(req, name) {
  const header = req.headers.get('cookie') || '';
  for (const part of header.split(';')) {
    const [k, ...v] = part.trim().split('=');
    if (k === name) return decodeURIComponent(v.join('='));
  }
  return null;
}
function b64uToBytes(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  const bin = atob(str);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function b64uToString(s) { return new TextDecoder().decode(b64uToBytes(s)); }

async function verifyHS256(token, secret) {
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [h, p, s] = parts;
  let header;
  try { header = JSON.parse(b64uToString(h)); } catch { return null; }
  if (header.alg !== 'HS256') return null;
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false, ['verify']
  );
  const signed = new TextEncoder().encode(`${h}.${p}`);
  const sig = b64uToBytes(s);
  if (!await crypto.subtle.verify('HMAC', key, sig, signed)) return null;
  let payload;
  try { payload = JSON.parse(b64uToString(p)); } catch { return null; }
  if (payload.exp && Math.floor(Date.now() / 1000) >= payload.exp) return null;
  return payload;
}

export default async function handler(req) {
  const url = new URL(req.url);
  const token = readCookie(req, 'iv_session');
  let authed = false;
  if (token) {
    try {
      const payload = await verifyHS256(token, process.env.JWT_SECRET);
      if (payload && payload.purpose === 'session') authed = true;
    } catch { authed = false; }
  }
  if (!authed) return Response.redirect(PORTAL_BASE + '/', 302);

  const idx = new URL('/_index.html', url.origin);
  const res = await fetch(idx.toString());
  if (!res.ok) return new Response('home not found', { status: 404 });
  const html = await res.text();
  return new Response(html, {
    status: 200,
    headers: {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'private, no-store',
    },
  });
}
