// YAMADA LAB ANP Portal – Service Worker
// Auth: GitHub Enterprise Cloud OAuth SSO

const PROTECTED_PATHS = [
  '/dashboard', '/analytics', '/radius', '/radius-udp',
  '/certificates', '/logs', '/issue',
];
const TOKEN_PROXY = 'https://github-oauth-proxy.masaki-yamada.workers.dev';
const GHE_API     = 'https://yamada-lab-llc.ghe.com/api/v3';
const ORG_NAME    = 'yamada-lab-llc';
const SESSION_TTL = 8 * 60 * 60 * 1000; // 8h

// ── Lifecycle ────────────────────────────────────────────────────────────────
self.addEventListener('install',  () => self.skipWaiting());
self.addEventListener('activate', e  => e.waitUntil(clients.claim()));

// ── Fetch interception ───────────────────────────────────────────────────────
self.addEventListener('fetch', event => {
  const url  = new URL(event.request.url);
  const path = url.pathname.replace(/\/$/, '') || '/';

  // OAuth callback: 認可コードをトークンに交換してセッション保存
  if (path === '/auth/callback' && url.searchParams.has('code')) {
    event.respondWith(handleOAuthCallback(url));
    return;
  }

  // Logout: セッションをクリアして /login/ へ
  if (path === '/auth/logout') {
    event.respondWith(handleLogout());
    return;
  }

  // Auth status JSON API（ページ側から呼び出し）
  if (path === '/auth/status') {
    event.respondWith(handleAuthStatus());
    return;
  }

  // 保護ルートのガード
  const isProtected = PROTECTED_PATHS.some(p => path === p || path.startsWith(p + '/'));
  if (isProtected && event.request.mode === 'navigate') {
    event.respondWith(guardedFetch(event.request, url));
    return;
  }
});

// ── OAuth callback handler ────────────────────────────────────────────────────
async function handleOAuthCallback(url) {
  const code  = url.searchParams.get('code');
  const error = url.searchParams.get('error');
  if (error) return Response.redirect('/login/?error=' + encodeURIComponent(error), 302);
  try {
    // 1. Cloudflare Worker でコード→アクセストークン交換
    const tokenRes = await fetch(TOKEN_PROXY, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code }),
    });
    if (!tokenRes.ok) throw new Error('token_exchange_failed');
    const { access_token } = await tokenRes.json();
    if (!access_token) throw new Error('no_access_token');

    // 2. ユーザー情報を取得
    const userRes = await fetch(GHE_API + '/user', {
      headers: { Authorization: 'token ' + access_token, Accept: 'application/vnd.github+json' },
    });
    if (!userRes.ok) throw new Error('user_fetch_failed');
    const user = await userRes.json();

    // 3. 組織メンバーシップを確認
    const memberRes = await fetch(GHE_API + '/orgs/' + ORG_NAME + '/members/' + user.login, {
      headers: { Authorization: 'token ' + access_token, Accept: 'application/vnd.github+json' },
    });
    if (memberRes.status !== 204) throw new Error('not_org_member');

    // 4. セッション保存してダッシュボードへ
    const email = user.email || user.login + '@yamada-lab.co.jp';
    await storeSession({ email, login: user.login, expiry: Date.now() + SESSION_TTL });
    return Response.redirect('/dashboard/', 302);
  } catch (e) {
    return Response.redirect('/login/?error=' + encodeURIComponent(e.message), 302);
  }
}

// ── Auth guard ────────────────────────────────────────────────────────────────
async function guardedFetch(request, url) {
  const session = await getSession();
  if (!session) {
    return Response.redirect('/login/?next=' + encodeURIComponent(url.pathname), 302);
  }
  return fetch(request);
}

async function handleLogout() {
  await clearSession();
  return Response.redirect('/login/', 302);
}

async function handleAuthStatus() {
  const s = await getSession();
  const body = s
    ? JSON.stringify({ authenticated: true,  email: s.email })
    : JSON.stringify({ authenticated: false });
  return new Response(body, {
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
  });
}

// ── SW message handler（ページからのセッション保存）────────────────────────
self.addEventListener('message', async event => {
  if (event.data?.type === 'SET_SESSION') {
    await storeSession(event.data.session);
    event.ports[0]?.postMessage({ ok: true });
  }
});

// ── IndexedDB ────────────────────────────────────────────────────────────────
function openDB() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open('anp-auth', 2);
    req.onupgradeneeded = e => {
      const db = e.target.result;
      if (!db.objectStoreNames.contains('session')) db.createObjectStore('session', { keyPath: 'id' });
    };
    req.onsuccess = e => resolve(e.target.result);
    req.onerror   = e => reject(e.target.error);
  });
}

async function storeSession(data) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction('session', 'readwrite');
    tx.objectStore('session').put({ id: 'current', ...data });
    tx.oncomplete = resolve;
    tx.onerror    = e => reject(e.target.error);
  });
}

async function getSession() {
  try {
    const db = await openDB();
    return new Promise(resolve => {
      const req = db.transaction('session', 'readonly').objectStore('session').get('current');
      req.onsuccess = e => {
        const s = e.target.result;
        resolve(s && s.expiry > Date.now() ? s : null);
      };
      req.onerror = () => resolve(null);
    });
  } catch { return null; }
}

async function clearSession() {
  try {
    const db = await openDB();
    return new Promise(resolve => {
      const tx = db.transaction('session', 'readwrite');
      tx.objectStore('session').delete('current');
      tx.oncomplete = resolve;
    });
  } catch {}
}
