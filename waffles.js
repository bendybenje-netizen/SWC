// POST /api/change-passphrase  { current: "...", next: "..." }
import { verifyPassphrase, hashPassphrase, json } from '../_lib.js';

export async function onRequestPost({ request, env, data }) {
  let body;
  try { body = await request.json(); } catch { return json({ error: 'Malformed request.' }, 400); }

  const current = String(body.current || '');
  const next = String(body.next || '');

  if (next.length < 8) {
    return json({ error: 'New passphrase must be at least 8 characters. Standards, please.' }, 400);
  }

  const member = await env.DB
    .prepare('SELECT id, passphrase_hash FROM members WHERE id = ?')
    .bind(data.memberId).first();

  if (!member || !(await verifyPassphrase(current, member.passphrase_hash))) {
    return json({ error: 'Current passphrase incorrect. The Committee raises an eyebrow.' }, 401);
  }

  const newHash = await hashPassphrase(next);
  await env.DB.prepare('UPDATE members SET passphrase_hash = ? WHERE id = ?')
    .bind(newHash, member.id).run();

  return json({ ok: true, message: 'Passphrase changed. Guard it with your life.' });
}
