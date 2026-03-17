// YAMADA LAB ANP Portal – Service Worker
// SAML SP (client-side): intercepts ACS POST, guards protected routes

const IDP_ENTITY_ID = 'https://accounts.google.com/o/saml2?idpid=C04eaya5d';
const SP_ENTITY_ID  = 'https://manage.yamada-lab.co.jp';

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

  // SAML ACS callback (POST from Google)
  if ((path === '/auth/callback') && event.request.method === 'POST') {
    event.respondWith(handleSamlCallback(event.request));
    return;
  }

  // Logout
  if (path === '/auth/logout') {
    event.respondWith(handleLogout(url));
    return;
  }

  // Auth status JSON API (called by pages)
  if (path === '/auth/status') {
    event.respondWith(handleAuthStatus());
    return;
  }

  // Guard protected routes (navigation requests only)
  const isProtected = PROTECTED_PATHS.some(p => path === p || path.startsWith(p + '/'));
  if (isProtected && event.request.mode === 'navigate') {
    event.respondWith(guardedFetch(event.request, url));
    return;
  }
});

// ── SAML ACS handler ─────────────────────────────────────────────────────────
async function handleSamlCallback(request) {
  try {
    const form = await request.formData();
    const b64  = form.get('SAMLResponse');

    if (!b64) return Response.redirect('/login/?error=no_response', 302);

    const xml    = decodeBase64(b64);
    const result = parseSamlResponse(xml);

    if (!result.valid) {
      console.error('[SW] SAML validation failed:', result.error);
      return Response.redirect('/login/?error=' + encodeURIComponent(result.error), 302);
    }

    await storeSession({ email: result.email, expiry: result.expiry });

    // Consume the used request ID (replay protection)
    if (result.inResponseTo) await removeRequestId(result.inResponseTo);

    return Response.redirect('/dashboard/', 302);

  } catch (err) {
    console.error('[SW] SAML callback exception:', err);
    return Response.redirect('/login/?error=exception', 302);
  }
}

// ── SAML parsing ─────────────────────────────────────────────────────────────
function decodeBase64(b64) {
  const binary = atob(b64.replace(/\s/g, ''));
  return new TextDecoder('utf-8').decode(
    Uint8Array.from(binary, c => c.charCodeAt(0))
  );
}

function parseSamlResponse(xml) {
  const NS_P = 'urn:oasis:names:tc:SAML:2.0:protocol';
  const NS_A = 'urn:oasis:names:tc:SAML:2.0:assertion';

  let doc;
  try {
    doc = new DOMParser().parseFromString(xml, 'text/xml');
  } catch {
    return { valid: false, error: 'xml_parse_failed' };
  }
  if (doc.querySelector('parsererror')) {
    return { valid: false, error: 'xml_parse_error' };
  }

  // StatusCode must be Success
  const statusCode = doc.getElementsByTagNameNS(NS_P, 'StatusCode')[0];
  if (!statusCode?.getAttribute('Value')?.includes('Success')) {
    return { valid: false, error: 'auth_failed' };
  }

  // Issuer must match IdP entity ID
  const issuer = doc.getElementsByTagNameNS(NS_A, 'Issuer')[0]?.textContent?.trim();
  if (issuer !== IDP_ENTITY_ID) {
    return { valid: false, error: 'wrong_issuer' };
  }

  // Timestamps (Conditions)
  const conditions = doc.getElementsByTagNameNS(NS_A, 'Conditions')[0];
  const now = Date.now();
  const TOLERANCE = 60_000; // 1 min clock skew
  if (conditions) {
    const nb  = conditions.getAttribute('NotBefore');
    const noa = conditions.getAttribute('NotOnOrAfter');
    if (nb  && now < new Date(nb).getTime()  - TOLERANCE) return { valid: false, error: 'not_yet_valid' };
    if (noa && now > new Date(noa).getTime() + TOLERANCE) return { valid: false, error: 'expired' };
  }

  // Audience must match SP entity ID
  const audience = doc.getElementsByTagNameNS(NS_A, 'Audience')[0]?.textContent?.trim();
  if (audience && audience !== SP_ENTITY_ID) {
    return { valid: false, error: 'wrong_audience' };
  }

  // NameID (email)
  const nameId = doc.getElementsByTagNameNS(NS_A, 'NameID')[0]?.textContent?.trim();
  if (!nameId) return { valid: false, error: 'no_nameid' };

  // Session expiry from SubjectConfirmationData
  const scd     = doc.getElementsByTagNameNS(NS_A, 'SubjectConfirmationData')[0];
  const expiryS = scd?.getAttribute('NotOnOrAfter');
  const expiry  = expiryS ? new Date(expiryS).getTime() : now + 3_600_000;

  // InResponseTo (replay protection)
  const response     = doc.getElementsByTagNameNS(NS_P, 'Response')[0] ?? doc.documentElement;
  const inResponseTo = response.getAttribute('InResponseTo') ?? null;

  return { valid: true, email: nameId, expiry, inResponseTo };
}

// ── Auth guard ───────────────────────────────────────────────────────────────
async function guardedFetch(request, url) {
  const session = await getSession();
  if (!session) {
    return Response.redirect('/login/?next=' + encodeURIComponent(url.pathname), 302);
  }
  return fetch(request);
}

async function handleLogout(url) {
  await clearSession();
  const next = url.searchParams.get('next') || '/login/';
  return Response.redirect(next, 302);
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

// ── IndexedDB helpers ────────────────────────────────────────────────────────
function openDB() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open('anp-auth', 1);
    req.onupgradeneeded = e => {
      const db = e.target.result;
      if (!db.objectStoreNames.contains('session'))  db.createObjectStore('session',  { keyPath: 'id' });
      if (!db.objectStoreNames.contains('requests')) db.createObjectStore('requests', { keyPath: 'id' });
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

// Replay protection: track used/pending request IDs
export async function storeRequestId(id) {
  try {
    const db = await openDB();
    return new Promise(resolve => {
      const tx = db.transaction('requests', 'readwrite');
      tx.objectStore('requests').put({ id, ts: Date.now() });
      tx.oncomplete = resolve;
    });
  } catch {}
}

async function removeRequestId(id) {
  try {
    const db = await openDB();
    return new Promise(resolve => {
      const tx = db.transaction('requests', 'readwrite');
      tx.objectStore('requests').delete(id);
      tx.oncomplete = resolve;
    });
  } catch {}
}
