// ============================================================
// The Small Willy Club — shared helpers
// Passphrase hashing (PBKDF2) + signed session cookies (HMAC)
// ============================================================

const ITERATIONS = 10000; // PBKDF2-SHA256 iterations (kept modest for Workers CPU limits)
const SESSION_DAYS = 180; // members stay signed in for ~6 months
export const COOKIE_NAME = 'swc_session';

const enc = new TextEncoder();

export function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

export function bytesToHex(buf) {
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
}

// --- Passphrases -------------------------------------------------

export async function hashPassphrase(passphrase, saltHex) {
  const salt = saltHex ? hexToBytes(saltHex) : crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey(
    'raw', enc.encode(passphrase.normalize('NFKC')), 'PBKDF2', false, ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: ITERATIONS },
    keyMaterial, 256
  );
  return `${bytesToHex(salt)}:${bytesToHex(bits)}`;
}

export async function verifyPassphrase(passphrase, stored) {
  if (!stored || !stored.includes(':')) return false;
  const [saltHex, hashHex] = stored.split(':');
  const candidate = await hashPassphrase(passphrase, saltHex);
  const a = enc.encode(candidate.split(':')[1]);
  const b = enc.encode(hashHex);
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

// --- Session cookies ---------------------------------------------

async function hmac(secret, message) {
  const key = await crypto.subtle.importKey(
    'raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(message));
  return bytesToHex(sig);
}

export async function createSessionCookie(memberId, secret) {
  const exp = Date.now() + SESSION_DAYS * 24 * 60 * 60 * 1000;
  const payload = `${memberId}.${exp}`;
  const sig = await hmac(secret, payload);
  const value = `${payload}.${sig}`;
  const maxAge = SESSION_DAYS * 24 * 60 * 60;
  return `${COOKIE_NAME}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
}

export function clearSessionCookie() {
  return `${COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
}

export async function getSessionMemberId(request, secret) {
  const cookies = request.headers.get('Cookie') || '';
  const match = cookies.match(new RegExp(`(?:^|;\\s*)${COOKIE_NAME}=([^;]+)`));
  if (!match) return null;
  const parts = match[1].split('.');
  if (parts.length !== 3) return null;
  const [id, exp, sig] = parts;
  if (Number(exp) < Date.now()) return null;
  const expected = await hmac(secret, `${id}.${exp}`);
  if (sig !== expected) return null;
  return Number(id);
}

// --- Small response helpers --------------------------------------

export function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...headers },
  });
}
