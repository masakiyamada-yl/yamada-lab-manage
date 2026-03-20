// YAMADA LAB ANP Portal – Service Worker
// Auth: Cloudflare Access JWT (Google Workspace SSO)

const PROTECTED_PATHS = [
  '/dashboard', '/analytics', '/radius', '/radius-udp',
  '/certificates', '/logs', '/issue',
];
const SESSION_TTL = 8 * 60 * 60 * 1000; // 8h

self.addEventListener('install',  () => self.skipWaiting());
self.addEventListener('activate', e  => e.waitUntil(clients.claim()));

self.addEventListener('fetch', event => {
  const url  = new URL(event.request.url);
  const path = url.pathname.replace(/\/$/, '') || '/';

  if (path === '/auth/logout') { event.respondWith(handleLogout()); return; }
  if (path === '/auth/status') { event.respondWith(handleAuthStatus()); return; }

  const isProtected = PROTECTED_PATHS.some(p => path === p || path.startsWith(p + '/'));
  if (isProtected && event.request.mode === 'navigate') {
    event.respondWith(guardedFetch(event.request, url));
  }
});

// ── Auth guard ────────────────────────────────────────────────────────────────
async function guardedFetch(request, url) {
  // Cloudflare Access JWT からセッションを同期
  await syncSessionFromCF(request);

  const session = await getSession();
  if (!session) {
    return Response.redirect('/login/?next=' + encodeURIComponent(url.pathname), 302);
  }
  return fetch(request);
}

// CF_Authorization クッキー（Cloudflare Access JWT）を読んでセッション作成
async function syncSessionFromCF(request) {
  const existing = await getSession();
  if (existing) return;

  const cookieHeader = request.headers.get('Cookie') || '';
  const cfToken = extractCookie(cookieHeader, 'CF_Authorization');
  if (!cfToken) return;

  try {
    const payload = decodeJWTPayload(cfToken);
    if (!payload.email) return;
    if (payload.exp && payload.exp * 1000 < Date.now()) return;

    await storeSession({
      email:  payload.email,
      login:  payload.email.split('@')[0],
      expiry: payload.exp ? payload.exp * 1000 : Date.now() + SESSION_TTL,
    });
  } catch { /* JWT decode failure – skip */ }
}

function extractCookie(cookieStr, name) {
  const m = cookieStr.match(new RegExp('(?:^|;\\s*)' + name + '=([^;]+)'));
  return m ? decodeURIComponent(m[1]) : null;
}

function decodeJWTPayload(token) {
  const b64 = token.split('.')[1];
  if (!b64) throw new Error('invalid_jwt');
  return JSON.parse(atob(b64.replace(/-/g, '+').replace(/_/g, '/')));
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
