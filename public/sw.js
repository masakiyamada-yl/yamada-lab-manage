// YAMADA LAB ANP Portal – Service Worker
// Auth: GitHub Enterprise Cloud Pages (Internal visibility)
// GitHub 層で認証済みの場合のみページが配信されるため、
// SW はセッション管理とルートガードのみ担当する。

const PROTECTED_PATHS = [
  '/dashboard', '/analytics', '/radius', '/radius-udp',
  '/certificates', '/logs', '/issue',
];

// ── Lifecycle ────────────────────────────────────────────────────────────────
self.addEventListener('install',  () => self.skipWaiting());
self.addEventListener('activate', e  => e.waitUntil(clients.claim()));

// ── Fetch interception ───────────────────────────────────────────────────────
self.addEventListener('fetch', event => {
  const url  = new URL(event.request.url);
  const path = url.pathname.replace(/\/$/, '') || '/';

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

  // 保護ルートのガード（GitHub Pages Internal が一次防衛線）
  const isProtected = PROTECTED_PATHS.some(p => path === p || path.startsWith(p + '/'));
  if (isProtected && event.request.mode === 'navigate') {
    event.respondWith(guardedFetch(event.request, url));
    return;
  }
});

// ── Auth guard ────────────────────────────────────────────────────────────────
async function guardedFetch(request, url) {
  const session = await getSession();
  if (!session) {
    // GitHub Pages Internal で認証済みなら /login/ にリダイレクトして再確認
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
