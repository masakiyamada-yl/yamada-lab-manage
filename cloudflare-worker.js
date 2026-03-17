/**
 * Cloudflare Worker – GitHub Enterprise OAuth Token Exchange Proxy
 * Deploy at: https://dash.cloudflare.com → Workers & Pages → Create Worker
 *
 * Environment variables to set in Worker Settings → Variables:
 *   GITHUB_CLIENT_ID     : GitHub OAuth App の Client ID
 *   GITHUB_CLIENT_SECRET : GitHub OAuth App の Client Secret
 *
 * GitHub Enterprise OAuth token endpoint:
 *   https://yamada-lab-llc.ghe.com/login/oauth/access_token
 */

const GITHUB_ENTERPRISE_HOST = 'https://yamada-lab-llc.ghe.com';
const ALLOWED_ORIGIN         = 'https://manage.yamada-lab.co.jp';

export default {
  async fetch(request, env) {
    // CORS preflight
    if (request.method === 'OPTIONS') {
      return corsResponse(null, 204);
    }

    // Only POST /token is supported
    if (request.method !== 'POST') {
      return corsResponse(JSON.stringify({ error: 'method_not_allowed' }), 405);
    }

    // Origin check
    const origin = request.headers.get('Origin') || '';
    if (origin !== ALLOWED_ORIGIN) {
      return corsResponse(JSON.stringify({ error: 'forbidden' }), 403);
    }

    let code;
    try {
      const body = await request.json();
      code = body.code;
    } catch {
      return corsResponse(JSON.stringify({ error: 'invalid_request' }), 400);
    }

    if (!code) {
      return corsResponse(JSON.stringify({ error: 'missing_code' }), 400);
    }

    // Exchange code for access token with GitHub Enterprise
    const tokenRes = await fetch(`${GITHUB_ENTERPRISE_HOST}/login/oauth/access_token`, {
      method : 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept'      : 'application/json',
      },
      body: JSON.stringify({
        client_id    : env.GITHUB_CLIENT_ID,
        client_secret: env.GITHUB_CLIENT_SECRET,
        code,
      }),
    });

    if (!tokenRes.ok) {
      return corsResponse(JSON.stringify({ error: 'github_error', status: tokenRes.status }), 502);
    }

    const tokenData = await tokenRes.json();

    if (tokenData.error) {
      return corsResponse(JSON.stringify({ error: tokenData.error }), 400);
    }

    // Return only the access_token (do not expose client_secret)
    return corsResponse(JSON.stringify({ access_token: tokenData.access_token }), 200);
  },
};

function corsResponse(body, status) {
  return new Response(body, {
    status,
    headers: {
      'Access-Control-Allow-Origin' : ALLOWED_ORIGIN,
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
      'Content-Type'                : 'application/json',
      'Cache-Control'               : 'no-store',
    },
  });
}
