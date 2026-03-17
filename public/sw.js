// YAMADA LAB ANP Portal – Service Worker
// Auth: GitHub Enterprise Cloud OAuth (GHEC SSO → Google Workspace SAML)
//
// Setup required:
//   1. Create a GitHub OAuth App in yamada-lab-llc.ghe.com
//      - Homepage URL : https://manage.yamada-lab.co.jp
//      - Callback URL : https://manage.yamada-lab.co.jp/auth/callback/
//   2. Deploy the Cloudflare Worker (cloudflare-worker.js) and set TOKEN_PROXY_URL below.
//   3. Set GITHUB_CLIENT_ID below.

const GITHUB_ENTERPRISE_HOST = 'https://yamada-lab-llc.ghe.com';
const GITHUB_CLIENT_ID       = 'REPLACE_WITH_OAUTH_APP_CLIENT_ID'; // ← GitHub OAuth App の Client ID
const TOKEN_PROXY_URL        = 'REPLACE_WITH_CLOUDFLARE_WORKER_URL'; // ← Cloudflare Worker URL
const GITHUB_API_BASE        = 'https://api.github.com';
const ENTERPRISE_ORG         = 'yamada-lab-llc'; // GitHub Enterprise org slug

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

  // OAuth callback (GET with ?code=)
  if (path === '/auth/callback' && url.searchParams.has('code')) {
    event.respondWith(handleOAuthCallback(url));
    return;
  }

  // Logout
  if (path === '/auth/logout') {
    event.respondWith(handleLogout());
    return;
  }

  // Auth status JSON API
  if (path === '/auth/status') {
    event.respondWith(handleAuthStatus());
    return;
  }

  // Guard protected routes
  const isProtected = PROTECTED_PATHS.some(p => path === p || path.startsWith(p + '/'));
  if (isProtected && event.request.mode === 'navigate') {
    event.respondWith(guardedFetch(event.request, url));
    return;
  }
});

// ── OAuth callback ────────────────────────────────────────────────────────────
async function handleOAuthCallback(url) {
  const code  = url.searchParams.get('code');
  const state = url.searchParams.get('state');

  if (!code) return Response.redirect('/login/?error=no_code', 302);

  // Verify state (CSRF protection)
  const savedState = await getState();
  if (!savedState || savedState !== state) {
    return Response.redirect('/login/?error=state_mismatch', 302);
  }
  await clearState();

  try {
    // Exchange code for access token via Cloudflare Worker proxy
    const tokenRes = await fetch(TOKEN_PROXY_URL, {
      method : 'POST',
      headers: { 'Content-Type': 'application/json' },
      body   : JSON.stringify({ code }),
    });

    if (!tokenRes.ok) {
      console.error('[SW] Token proxy error:', await tokenRes.text());
      return Response.redirect('/login/?error=token_exchange_failed', 302);
    }

    const { access_token, error } = await tokenRes.json();
    if (error || !access_token) {
      return Response.redirect('/login/?error=' + encodeURIComponent(error || 'no_token'), 302);
    }

    // Fetch user info from GitHub API
    const userRes = await fetch(`${GITHUB_API_BASE}/user`, {
      headers: {
        Authorization: `Bearer ${access_token}`,
        Accept: 'application/vnd.github+json',
      },
    });

    if (!userRes.ok) {
      return Response.redirect('/login/?error=user_fetch_failed', 302);
    }

    const user = await userRes.json();

    // Verify enterprise membership
    const memberRes = await fetch(
      `${GITHUB_API_BASE}/orgs/${ENTERPRISE_ORG}/members/${user.login}`,
      {
        headers: {
          Authorization: `Bearer ${access_token}`,
          Accept: 'application/vnd.github+json',
        },
      }
    );
    // 204 = member, 404 = not a member
    if (memberRes.status === 404) {
      return Response.redirect('/login/?error=not_org_member', 302);
    }

    const email   = user.email || `${user.login}@yamada-lab.co.jp`;
    const expiry  = Date.now() + 8 * 3_600_000; // 8-hour session
    await storeSession({ email, login: user.login, avatar: user.avatar_url, expiry });

    return Response.redirect('/dashboard/', 302);

  } catch (err) {
    console.error('[SW] OAuth callback error:', err);
    return Response.redirect('/login/?error=exception', 302);
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
    ? JSON.stringify({ authenticated: true, email: s.email, login: s.login, avatar: s.avatar })
    : JSON.stringify({ authenticated: false });
  return new Response(body, {
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
  });
}

// ── IndexedDB ────────────────────────────────────────────────────────────────
function openDB() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open('anp-auth', 2);
    req.onupgradeneeded = e => {
      const db = e.target.result;
      if (!db.objectStoreNames.contains('session')) db.createObjectStore('session',  { keyPath: 'id' });
      if (!db.objectStoreNames.contains('state'))   db.createObjectStore('state',    { keyPath: 'id' });
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

// State for CSRF protection
async function saveState(state) {
  try {
    const db = await openDB();
    return new Promise(resolve => {
      const tx = db.transaction('state', 'readwrite');
      tx.objectStore('state').put({ id: 'oauth', value: state, ts: Date.now() });
      tx.oncomplete = resolve;
    });
  } catch {}
}

async function getState() {
  try {
    const db = await openDB();
    return new Promise(resolve => {
      const req = db.transaction('state', 'readonly').objectStore('state').get('oauth');
      req.onsuccess = e => resolve(e.target.result?.value ?? null);
      req.onerror   = () => resolve(null);
    });
  } catch { return null; }
}

async function clearState() {
  try {
    const db = await openDB();
    return new Promise(resolve => {
      const tx = db.transaction('state', 'readwrite');
      tx.objectStore('state').delete('oauth');
      tx.oncomplete = resolve;
    });
  } catch {}
}

// Called from login page to save state before redirect
self.addEventListener('message', async event => {
  if (event.data?.type === 'SAVE_STATE') {
    await saveState(event.data.state);
    event.ports[0]?.postMessage({ ok: true });
  }
});
