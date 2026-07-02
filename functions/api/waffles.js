// GET  /api/waffles — the full Ledger (all members' standing + Register of Rambles)
// POST /api/waffles — record a waffle (admin only)
//        { member_slug: "greg", date: "2026-07-01", duration_minutes: 4, note: "..." }
import { json } from '../_lib.js';

const RAMBLE_THRESHOLD_SECONDS = 5 * 60; // Bylaw 3.3

export async function onRequestGet({ env }) {
  const { results: members } = await env.DB.prepare(
    `SELECT m.id, m.slug, m.name,
            (SELECT waffled_on FROM waffles w WHERE w.member_id = m.id
             ORDER BY waffled_on DESC LIMIT 1) AS last_waffle,
            (SELECT duration_seconds FROM waffles w WHERE w.member_id = m.id
             ORDER BY waffled_on DESC LIMIT 1) AS last_duration,
            (SELECT COUNT(*) FROM waffles w WHERE w.member_id = m.id) AS total_waffles
     FROM members m ORDER BY m.sort_order`
  ).all();

  const { results: rambles } = await env.DB.prepare(
    `SELECT m.name, w.waffled_on, w.duration_seconds, w.note
     FROM waffles w JOIN members m ON m.id = w.member_id
     WHERE w.duration_seconds > ?
     ORDER BY w.waffled_on DESC LIMIT 20`
  ).bind(RAMBLE_THRESHOLD_SECONDS).all();

  return json({ members, rambles });
}

export async function onRequestPost({ request, env, data }) {
  const me = await env.DB.prepare('SELECT is_admin FROM members WHERE id = ?')
    .bind(data.memberId).first();
  if (!me || !me.is_admin) {
    return json({ error: 'Only the Committee may write to the Ledger.' }, 403);
  }

  let body;
  try { body = await request.json(); } catch { return json({ error: 'Malformed request.' }, 400); }

  const member = await env.DB.prepare('SELECT id FROM members WHERE slug = ?')
    .bind(String(body.member_slug || '').toLowerCase()).first();
  if (!member) return json({ error: 'No such member. The Club is full, remember.' }, 404);

  const date = String(body.date || '').match(/^\d{4}-\d{2}-\d{2}$/)
    ? body.date : new Date().toISOString().slice(0, 10);
  const durationSeconds = Math.max(0, Math.round(Number(body.duration_minutes || 0) * 60));
  const note = String(body.note || '').slice(0, 300);

  await env.DB.prepare(
    'INSERT INTO waffles (member_id, waffled_on, duration_seconds, note) VALUES (?, ?, ?, ?)'
  ).bind(member.id, date, durationSeconds, note).run();

  const classification = durationSeconds > RAMBLE_THRESHOLD_SECONDS ? 'Ramble' : 'Waffle';
  return json({ ok: true, classification });
}
