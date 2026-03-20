// YAMADA LAB ANP Portal – Service Worker
// Auth: Cloudflare Access (Google Workspace SSO)

self.addEventListener('install',  () => self.skipWaiting());
self.addEventListener('activate', e  => e.waitUntil(clients.claim()));

self.addEventListener('fetch', event => {
  const path = new URL(event.request.url).pathname.replace(/\/$/, '') || '/';

  // ログアウト: CF Access のログアウトエンドポイントへ
  if (path === '/auth/logout') {
    event.respondWith(Response.redirect('/cdn-cgi/access/logout', 302));
    return;
  }

  // 認証ステータス: CF Access の get-identity エンドポイントに問い合わせ
  if (path === '/auth/status') {
    event.respondWith(handleAuthStatus());
    return;
  }
});

async function handleAuthStatus() {
  try {
    const res = await fetch('/cdn-cgi/access/get-identity', { credentials: 'same-origin' });
    if (res.ok) {
      const data = await res.json();
      return new Response(
        JSON.stringify({ authenticated: true, email: data.email || '' }),
        { headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } }
      );
    }
  } catch {}
  return new Response(
    JSON.stringify({ authenticated: false }),
    { headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } }
  );
}
