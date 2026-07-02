// POST /api/login  { member: "ben", passphrase: "..." }
import { verifyPassphrase, createSessionCookie, json } from '../_lib.js';

export async function onRequestPost({ request, env }) {
  let body;
  try { body = await request.json(); } catch { return json({ error: 'Malformed request.' }, 400); }

  const slug = String(body.member || '').toLowerCase().trim();
  const passphrase = String(body.passphrase || '');

  if (!slug || !passphrase) {
    return json({ error: 'A name and a passphrase are required. The Committee insists.' }, 400);
  }

  const member = await env.DB
    .prepare('SELECT id, slug, name, passphrase_hash FROM members WHERE slug = ?')
    .bind(slug).first();

  const ok = member && await verifyPassphrase(passphrase, member.passphrase_hash);
  if (!ok) {
    return json({ error: 'Incorrect. The Committee has made a note.' }, 401);
  }

  return json(
    { ok: true, name: member.name },
    200,
    { 'Set-Cookie': await createSessionCookie(member.id, env.SESSION_SECRET) }
  );
}
