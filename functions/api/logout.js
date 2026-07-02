// POST /api/logout — clears the session cookie
import { clearSessionCookie, json } from '../_lib.js';

export async function onRequestPost() {
  return json({ ok: true }, 200, { 'Set-Cookie': clearSessionCookie() });
}
