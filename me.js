// ============================================================
// Gatekeeper. Runs before EVERY request to the site.
// No valid session cookie → you only ever see the login page.
// ============================================================

import { getSessionMemberId, json } from './_lib.js';

// The only things visible to the un-anointed:
const PUBLIC_PATHS = new Set([
  '/login.html',
  '/api/login',
  '/frontimage.png',
  '/favicon.ico',
]);

export async function onRequest(context) {
  const { request, env, next, data } = context;
  const url = new URL(request.url);

  if (PUBLIC_PATHS.has(url.pathname)) return next();

  const memberId = await getSessionMemberId(request, env.SESSION_SECRET);

  if (!memberId) {
    if (url.pathname.startsWith('/api/')) {
      return json({ error: 'The Committee does not recognise you.' }, 401);
    }
    return Response.redirect(new URL('/login.html', url.origin).toString(), 302);
  }

  data.memberId = memberId; // hand the identity to whichever function runs next
  return next();
}
