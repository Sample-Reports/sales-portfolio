// api/gate.js — DEBUG VERSION. Returns JSON diagnostics instead of 302.
// REMOVE BEFORE PRODUCTION USE — accessible without auth.

export const config = { runtime: 'edge' };

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

export default async function handler(req) {
  const out = {};
  out.now_unix = Math.floor(Date.now() / 1000);
  out.has_jwt_secret_env = !!process.env.JWT_SECRET;
  out.jwt_secret_length = (process.env.JWT_SECRET || '').length;
  out.jwt_secret_first8 = (process.env.JWT_SECRET || '').slice(0, 8);
  out.jwt_secret_last8  = (process.env.JWT_SECRET || '').slice(-8);

  const cookieHeader = req.headers.get('cookie') || '';
  out.cookie_header_length = cookieHeader.length;
  out.cookie_names = cookieHeader.split(';').map(c => c.trim().split('=')[0]).filter(Boolean);

  const token = readCookie(req, 'session');
  out.has_session_cookie = !!token;
  if (!token) {
    return new Response(JSON.stringify(out, null, 2), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  }

  out.session_token_length = token.length;
  out.session_first16 = token.slice(0, 16);
  out.session_dot_count = (token.match(/\./g) || []).length;

  const parts = token.split('.');
  if (parts.length !== 3) {
    out.error = 'token_not_3_parts';
    return new Response(JSON.stringify(out, null, 2), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  }
  const [h, p, sig] = parts;

  let header;
  try { header = JSON.parse(b64uToString(h)); }
  catch (e) {
    out.error = 'header_parse_failed';
    out.error_msg = String(e);
    return new Response(JSON.stringify(out, null, 2), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  }
  out.jwt_header = header;

  let payload;
  try { payload = JSON.parse(b64uToString(p)); }
  catch (e) {
    out.error = 'payload_parse_failed';
    return new Response(JSON.stringify(out, null, 2), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  }
  out.jwt_payload_keys = Object.keys(payload);
  out.jwt_payload_kind = payload.kind;
  out.jwt_payload_exp = payload.exp;
  out.jwt_payload_email = payload.email ? payload.email.replace(/(.{3}).+(@.+)/, '$1***$2') : null;
  out.exp_in_future = payload.exp ? (payload.exp > out.now_unix) : null;

  // Try sig verification
  try {
    const key = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(process.env.JWT_SECRET),
      { name: 'HMAC', hash: 'SHA-256' },
      false, ['verify']
    );
    const signed = new TextEncoder().encode(`${h}.${p}`);
    const sigBytes = b64uToBytes(sig);
    const verified = await crypto.subtle.verify('HMAC', key, sigBytes, signed);
    out.signature_verified = verified;
  } catch (e) {
    out.signature_verified = false;
    out.signature_error = String(e);
  }

  out.would_authed = (
    out.signature_verified &&
    payload.kind === 'session' &&
    (!payload.exp || payload.exp > out.now_unix)
  );

  return new Response(JSON.stringify(out, null, 2), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  });
}
