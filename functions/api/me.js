// GET /api/me — who am I? (session already verified by middleware)
import { json } from '../_lib.js';

export async function onRequestGet({ env, data }) {
  const me = await env.DB.prepare(
    `SELECT id, slug, name, role, membership_number, member_since, is_admin
     FROM members WHERE id = ?`
  ).bind(data.memberId).first();

  if (!me) return json({ error: 'Member not found. Deeply irregular.' }, 404);

  const lastWaffle = await env.DB.prepare(
    `SELECT waffled_on, duration_seconds FROM waffles
     WHERE member_id = ? ORDER BY waffled_on DESC LIMIT 1`
  ).bind(me.id).first();

  return json({
    id: me.id,
    slug: me.slug,
    name: me.name,
    role: me.role,
    membership_number: me.membership_number,
    member_since: me.member_since,
    is_admin: !!me.is_admin,
    last_waffle: lastWaffle || null,
  });
}
