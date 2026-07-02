// POST /api/reset-passphrase  (admin only)
//   { member_slug: "barney", new_passphrase: "twelve-percent-again" }
// For when a member forgets their passphrase and confesses to the Committee.
import { hashPassphrase, json } from '../_lib.js';

export async function onRequestPost({ request, env, data }) {
  const me = await env.DB.prepare('SELECT is_admin FROM members WHERE id = ?')
    .bind(data.memberId).first();
  if (!me || !me.is_admin) {
    return json({ error: 'Only the Committee may perform the Rite of Reset.' }, 403);
  }

  let body;
  try { body = await request.json(); } catch { return json({ error: 'Malformed request.' }, 400); }

  const slug = String(body.member_slug || '').toLowerCase();
  const newPassphrase = String(body.new_passphrase || '');
  if (newPassphrase.length < 8) {
    return json({ error: 'Passphrase must be at least 8 characters.' }, 400);
  }

  const member = await env.DB.prepare('SELECT id, name FROM members WHERE slug = ?')
    .bind(slug).first();
  if (!member) return json({ error: 'No such member.' }, 404);

  const hash = await hashPassphrase(newPassphrase);
  await env.DB.prepare('UPDATE members SET passphrase_hash = ? WHERE id = ?')
    .bind(hash, member.id).run();

  return json({ ok: true, message: `${member.name}'s passphrase has been reset. Inform them solemnly.` });
}
