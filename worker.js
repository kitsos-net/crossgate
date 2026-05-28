/**
 * ─────────────────────────────────────────────────────────────────────────────
 * Kitsos Cross-Device Auth Worker
 * OIDC proxy for QR-code / cross-device login
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * Required environment variables:
 *   WORKER_BASE_URL          e.g. https://device.kitsos.net
 *   UPSTREAM_ISSUER          e.g. https://kitsos.eu.auth0.com
 *   UPSTREAM_CLIENT_ID       Worker's client_id at the upstream OIDC provider
 *   UPSTREAM_CLIENT_SECRET   (set as secret — never in plaintext)
 *   LOGOUT_URL               Where Device 2's "Abmelden" button redirects
 *
 * Optional environment variables:
 *   UPSTREAM_AUTH_ENDPOINT   Override upstream /authorize URL
 *   UPSTREAM_TOKEN_ENDPOINT  Override upstream /token URL
 *                            (defaults: {ISSUER}/authorize and {ISSUER}/oauth/token)
 *
 * KV Namespace binding: SESSIONS
 *
 * ─── Flow ────────────────────────────────────────────────────────────────────
 *
 *  Device 1 (browser, wants to log in):
 *    → Redirected to GET /authorize?response_type=code&redirect_uri=...&state=...
 *    → Sees QR code + user code; page polls /poll every 2 s
 *
 *  Device 2 (phone, scans QR / enters code):
 *    → GET /activate?code=XXXX-XXXX  (or POST / with code in form)
 *    → Redirected to upstream OIDC for login
 *    → Upstream calls GET /callback
 *    → Worker exchanges upstream code for tokens, stores them
 *    → Device 2 sees success page with logout button
 *
 *  Device 1 (poll resolves):
 *    → JavaScript redirects to redirect_uri?code=<relay_code>&state=...
 *    → App calls POST /token to exchange relay_code for upstream tokens
 *
 * ─── RFC 8628 (Device Authorization Grant) ───────────────────────────────────
 *
 *  POST /device_authorization  →  returns device_code, user_code, verification_uri
 *  POST /token with grant_type=urn:ietf:params:oauth:grant-type:device_code
 *             →  returns tokens once Device 2 has authenticated
 */

// ─── Constants ────────────────────────────────────────────────────────────────
const SESSION_TTL = 600;  // 10 minutes (seconds)
const RELAY_TTL   = 120;  // 2 minutes for one-time relay code
const RL_MAX      = 5;    // max code-entry attempts per IP per minute
const CDN1 = 'https://cdn.kitsos.net';
const CDN2 = 'https://cdn2.kitsos.net';

// ─── Utilities ────────────────────────────────────────────────────────────────
const b64u = buf =>
  btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

const digest = str =>
  crypto.subtle.digest('SHA-256', new TextEncoder().encode(str)).then(b64u);

const genPKCE = async () => {
  const v = b64u(crypto.getRandomValues(new Uint8Array(32)));
  return { v, c: await digest(v) };
};

const uid = () => crypto.randomUUID();

const genUserCode = () => {
  // Unambiguous chars: no 0/O, 1/I
  const ch = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const p  = n => [...Array(n)].map(() => ch[Math.floor(Math.random() * ch.length)]).join('');
  return `${p(4)}-${p(4)}`;
};

const esc  = s => String(s)
  .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');

const jRes = (d, s = 200) => new Response(JSON.stringify(d), {
  status: s,
  headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }
});

const hRes = (b, s = 200) => new Response(b, {
  status: s,
  headers: { 'Content-Type': 'text/html;charset=utf-8', 'Cache-Control': 'no-store' }
});

const oErr = (e, d, s = 400) => jRes({ error: e, error_description: d }, s);

// ─── JWT re-signing ───────────────────────────────────────────────────────────
const b64uDec = s => {
  const pad = s.length % 4 ? '='.repeat(4 - s.length % 4) : '';
  return atob(s.replace(/-/g, '+').replace(/_/g, '/') + pad);
};

async function reSignIdToken(idToken, newIss, newAud, env) {
  if (!env.SIGNING_PRIVATE_KEY || !idToken) return idToken;
  try {
    const parts = idToken.split('.');
    if (parts.length !== 3) return idToken;
    const payload = JSON.parse(b64uDec(parts[1]));
    payload.iss = newIss;
    if (newAud) payload.aud = newAud;
    const header  = { alg: 'RS256', typ: 'JWT', kid: env.SIGNING_KEY_ID ?? 'crossgate-1' };
    const hdr     = b64u(new TextEncoder().encode(JSON.stringify(header)));
    const pld     = b64u(new TextEncoder().encode(JSON.stringify(payload)));
    const input   = `${hdr}.${pld}`;
    const privKey = await crypto.subtle.importKey(
      'jwk', JSON.parse(env.SIGNING_PRIVATE_KEY),
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign']
    );
    const sig = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', privKey, new TextEncoder().encode(input));
    return `${input}.${b64u(sig)}`;
  } catch (e) {
    console.error('reSignIdToken failed:', e);
    return idToken;
  }
}

// ─── GET /jwks ────────────────────────────────────────────────────────────────
function onJwks(env) {
  if (!env.SIGNING_PUBLIC_KEY) return jRes({ keys: [] });
  try {
    const key = JSON.parse(env.SIGNING_PUBLIC_KEY);
    return jRes({ keys: [{ ...key, use: 'sig', alg: 'RS256', kid: env.SIGNING_KEY_ID ?? 'crossgate-1' }] });
  } catch { return jRes({ keys: [] }); }
}

// ─── Rate limiting ────────────────────────────────────────────────────────────
async function rlOK(ip, env) {
  const k = `rl:${ip}`;
  const n = parseInt(await env.SESSIONS.get(k) ?? '0', 10);
  if (n >= RL_MAX) return false;
  await env.SESSIONS.put(k, String(n + 1), { expirationTtl: 60 });
  return true;
}

// ─── Session helpers ──────────────────────────────────────────────────────────
const getS = (dc, env) => env.SESSIONS.get(`d:${dc}`, 'json');

const saveS = (s, env) => env.SESSIONS.put(`d:${s.device_code}`, JSON.stringify(s), {
  expirationTtl: Math.max(1, Math.floor((s.created_at + SESSION_TTL * 1000 - Date.now()) / 1000))
});

async function getSbyUC(raw, env) {
  const norm = raw.replace(/[^A-Za-z0-9]/g, '').toUpperCase();
  const dc   = await env.SESSIONS.get(`uc:${norm}`);
  return dc ? getS(dc, env) : null;
}

async function createSession(env, overrides = {}) {
  const dc   = uid();
  const uc   = genUserCode();
  const us   = uid();
  const norm = uc.replace('-', '');

  const sess = {
    device_code: dc, user_code: uc, upstream_state: us, status: 'pending',
    downstream_redirect_uri: '', downstream_state: '', downstream_client_id: null,
    downstream_code_challenge: null, downstream_code_challenge_method: null,
    downstream_scope: 'openid profile email',
    pkce_v: null, relay_code: null, tokens: null, created_at: Date.now(),
    ...overrides,
  };

  await env.SESSIONS.put(`d:${dc}`,    JSON.stringify(sess), { expirationTtl: SESSION_TTL });
  await env.SESSIONS.put(`uc:${norm}`, dc,                   { expirationTtl: SESSION_TTL });
  await env.SESSIONS.put(`us:${us}`,   dc,                   { expirationTtl: SESSION_TTL });

  return sess;
}

// ─── OIDC Discovery ───────────────────────────────────────────────────────────
function onDiscover(env) {
  const b = env.WORKER_BASE_URL;
  return jRes({
    issuer:                               b,
    authorization_endpoint:               `${b}/authorize`,
    token_endpoint:                       `${b}/token`,
    end_session_endpoint:                 `${b}/logout`,
    device_authorization_endpoint:        `${b}/device_authorization`,
    jwks_uri:                             `${b}/jwks`,
    response_types_supported:             ['code'],
    grant_types_supported:                ['authorization_code', 'urn:ietf:params:oauth:grant-type:device_code'],
    code_challenge_methods_supported:     ['S256'],
    subject_types_supported:              ['public'],
    id_token_signing_alg_values_supported:['RS256'],
  });
}

// ─── GET /logout — RP-initiated logout ───────────────────────────────────────
function onLogout(url, env) {
  const postLogoutUri = url.searchParams.get('post_logout_redirect_uri');
  const logoutBase    = env.LOGOUT_URL ?? `${env.UPSTREAM_ISSUER}/oidc/logout`;
  const target        = new URL(logoutBase);
  if (postLogoutUri) target.searchParams.set('returnTo', postLogoutUri);
  return Response.redirect(target.toString(), 302);
}

// ─── GET /authorize — Device 1 entry ─────────────────────────────────────────
async function onAuthorize(url, env) {
  const p = url.searchParams;
  if (p.get('response_type') !== 'code')
    return oErr('unsupported_response_type', 'Only code is supported');
  const ru = p.get('redirect_uri');
  if (!ru) return oErr('invalid_request', 'redirect_uri required');

  const sess = await createSession(env, {
    downstream_redirect_uri:          ru,
    downstream_state:                 p.get('state') ?? '',
    downstream_client_id:             p.get('client_id') ?? null,
    downstream_code_challenge:        p.get('code_challenge') ?? null,
    downstream_code_challenge_method: p.get('code_challenge_method') ?? null,
    downstream_scope:                 p.get('scope') ?? 'openid profile email',
  });

  const vurl = `${env.WORKER_BASE_URL}/activate?code=${encodeURIComponent(sess.user_code)}`;
  return hRes(renderQRPage(sess.device_code, sess.user_code, vurl, env));
}

// ─── POST /device_authorization — RFC 8628 ────────────────────────────────────
async function onDeviceAuthorize(req, env) {
  const p    = new URLSearchParams(await req.text());
  const sess = await createSession(env, {
    downstream_scope: p.get('scope') ?? 'openid profile email',
  });

  return jRes({
    device_code:              sess.device_code,
    user_code:                sess.user_code,
    verification_uri:         `${env.WORKER_BASE_URL}/`,
    verification_uri_complete:`${env.WORKER_BASE_URL}/activate?code=${encodeURIComponent(sess.user_code)}`,
    expires_in:               SESSION_TTL,
    interval:                 5,
  });
}

// ─── Activate (QR scan or code entry) ────────────────────────────────────────
async function onActivate(url, env) {
  return doActivate(url.searchParams.get('code') ?? '', env);
}

async function onCodePost(req, env) {
  const ip   = req.headers.get('CF-Connecting-IP') ?? 'unknown';
  if (!await rlOK(ip, env))
    return hRes(renderEntry('', 'Zu viele Versuche. Bitte warte eine Minute.'));
  const fd   = await req.formData();
  const code = fd.get('code')?.toString().trim() ?? '';
  if (!code) return hRes(renderEntry('', 'Bitte einen Code eingeben.'));
  return doActivate(code, env);
}

async function doActivate(raw, env) {
  const sess = await getSbyUC(raw, env);
  if (!sess)                     return hRes(renderError('Code ungültig oder abgelaufen.'));
  if (sess.status !== 'pending') return hRes(renderError('Dieser Code wurde bereits verwendet oder ist abgelaufen.'));

  const { v, c } = await genPKCE();
  sess.pkce_v = v;
  await saveS(sess, env);

  const authEP = env.UPSTREAM_AUTH_ENDPOINT ?? `${env.UPSTREAM_ISSUER}/authorize`;
  const u      = new URL(authEP);
  u.searchParams.set('client_id',             env.UPSTREAM_CLIENT_ID);
  u.searchParams.set('redirect_uri',          `${env.WORKER_BASE_URL}/callback`);
  u.searchParams.set('response_type',         'code');
  u.searchParams.set('scope',                 sess.downstream_scope);
  u.searchParams.set('state',                 sess.upstream_state);
  u.searchParams.set('code_challenge',        c);
  u.searchParams.set('code_challenge_method', 'S256');

  return Response.redirect(u.toString(), 302);
}

// ─── GET /callback — upstream returns after Device 2 auth ────────────────────
async function onCallback(url, env) {
  const err = url.searchParams.get('error');
  if (err) return hRes(renderError(
    `Anmeldung fehlgeschlagen: ${url.searchParams.get('error_description') ?? err}`));

  const code  = url.searchParams.get('code');
  const state = url.searchParams.get('state');
  const dc    = await env.SESSIONS.get(`us:${state}`);
  if (!dc)    return hRes(renderError('Session nicht gefunden.'));

  const sess = await getS(dc, env);
  if (!sess || sess.status !== 'pending') return hRes(renderError('Session ungültig oder abgelaufen.'));

  // Exchange code for tokens at upstream
  const tokenEP = env.UPSTREAM_TOKEN_ENDPOINT ?? `${env.UPSTREAM_ISSUER}/oauth/token`;
  const tr = await fetch(tokenEP, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type:    'authorization_code',
      client_id:     env.UPSTREAM_CLIENT_ID,
      client_secret: env.UPSTREAM_CLIENT_SECRET,
      code,
      redirect_uri:  `${env.WORKER_BASE_URL}/callback`,
      code_verifier: sess.pkce_v ?? '',
    }),
  });

  if (!tr.ok) {
    console.error('Token exchange failed:', await tr.text());
    return hRes(renderError('Token-Austausch fehlgeschlagen. Bitte erneut versuchen.'));
  }

  const tokens    = await tr.json();
  const relay     = uid();
  sess.status     = 'authenticated';
  sess.tokens     = tokens;
  sess.relay_code = relay;
  await saveS(sess, env);
  await env.SESSIONS.put(`relay:${relay}`, dc, { expirationTtl: RELAY_TTL });

  return hRes(renderDevice2Success(env));
}

// ─── POST /token — Device 1 exchanges relay_code (or RFC 8628 device poll) ───
async function onToken(req, env) {
  if (!req.headers.get('Content-Type')?.includes('urlencoded'))
    return oErr('invalid_request', 'Content-Type must be application/x-www-form-urlencoded');

  const p          = new URLSearchParams(await req.text());
  const grant_type = p.get('grant_type');

  // ── RFC 8628: device_code polling ────────────────────────────────────────
  if (grant_type === 'urn:ietf:params:oauth:grant-type:device_code') {
    const dc = p.get('device_code');
    if (!dc) return oErr('invalid_request', 'device_code required');
    const sess = await getS(dc, env);
    if (!sess)                       return oErr('expired_token',          'Session expired',         400);
    if (sess.status === 'pending')   return oErr('authorization_pending',  'Authorization pending',   400);
    if (sess.status !== 'authenticated') return oErr('access_denied',      'Access denied',           400);
    // Return tokens directly for RFC 8628 flow
    const { access_token, id_token: raw8628, token_type, expires_in, refresh_token } = sess.tokens;
    const id_token8628 = await reSignIdToken(raw8628, env.WORKER_BASE_URL, sess.downstream_client_id, env);
    return jRes({ access_token, id_token: id_token8628, token_type: token_type ?? 'Bearer', expires_in,
      ...(refresh_token ? { refresh_token } : {}) });
  }

  // ── Standard authorization_code exchange (OIDC redirect flow) ────────────
  if (grant_type !== 'authorization_code')
    return oErr('unsupported_grant_type', 'Unsupported grant type');

  const code = p.get('code');
  if (!code) return oErr('invalid_request', 'code required');

  const dc = await env.SESSIONS.get(`relay:${code}`);
  if (!dc)  return oErr('invalid_grant', 'Invalid or expired code', 400);

  const sess = await getS(dc, env);
  if (!sess || sess.status !== 'authenticated' || sess.relay_code !== code)
    return oErr('invalid_grant', 'Invalid grant', 400);

  // Validate redirect_uri if provided
  const ru = p.get('redirect_uri');
  if (ru && ru !== sess.downstream_redirect_uri)
    return oErr('invalid_grant', 'redirect_uri mismatch', 400);

  // Verify PKCE (if Device 1 used it)
  if (sess.downstream_code_challenge) {
    const cv = p.get('code_verifier');
    if (!cv) return oErr('invalid_request', 'code_verifier required');
    if (await digest(cv) !== sess.downstream_code_challenge)
      return oErr('invalid_grant', 'PKCE verification failed', 400);
  }

  // Invalidate relay code (one-time use)
  await env.SESSIONS.delete(`relay:${code}`);

  const { access_token, id_token: rawIdToken, token_type, expires_in, refresh_token } = sess.tokens;
  const id_token = await reSignIdToken(rawIdToken, env.WORKER_BASE_URL, sess.downstream_client_id, env);
  return jRes({ access_token, id_token, token_type: token_type ?? 'Bearer', expires_in,
    ...(refresh_token ? { refresh_token } : {}) });
}

// ─── GET /poll — Device 1 checks for auth completion ─────────────────────────
async function onPoll(url, env) {
  const dc = url.searchParams.get('device_code');
  if (!dc) return jRes({ status: 'error', message: 'device_code required' }, 400);

  const s = await getS(dc, env);
  if (!s)  return jRes({ status: 'expired' });

  if (s.status === 'authenticated')
    return jRes({ status: 'authenticated', relay_code: s.relay_code,
      redirect_uri: s.downstream_redirect_uri, state: s.downstream_state });

  return jRes({ status: 'pending',
    remaining_ms: Math.max(0, s.created_at + SESSION_TTL * 1000 - Date.now()) });
}

// ─── HTML templates ───────────────────────────────────────────────────────────

const CSS = `
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#f0f0f7;--card:#ffffff;--t:#18182e;--ts:#5c5c7a;--tm:#9494b4;
  --bd:#e0e0ef;--ac:#4f46e5;--ach:#4338ca;--ok:#10b981;--er:#ef4444;
  --sh:0 8px 48px rgba(60,40,120,.10),0 1.5px 4px rgba(60,40,120,.06)
}
@media(prefers-color-scheme:dark){:root{
  --bg:#0c0c1a;--card:#131326;--t:#e6e6f8;--ts:#7a7a9e;--tm:#4a4a6a;
  --bd:#20203e;--ac:#7c73fa;--ach:#6d63f5;--sh:0 8px 48px rgba(0,0,0,.55),0 1.5px 4px rgba(0,0,0,.3)
}}
body{background:var(--bg);color:var(--t);min-height:100vh;display:flex;align-items:center;
  justify-content:center;padding:1.5rem;font-size:15px;line-height:1.6;
  font-family:system-ui,sans-serif;-webkit-font-smoothing:antialiased}
.card{background:var(--card);border:1px solid var(--bd);border-radius:28px;
  box-shadow:var(--sh);padding:2.75rem 2.25rem;max-width:400px;width:100%;
  display:flex;flex-direction:column;align-items:center;text-align:center;gap:.8rem}
.logo{height:34px;width:auto;margin-bottom:.15rem}
.logo-d{display:none}
@media(prefers-color-scheme:dark){.logo-l{display:none}.logo-d{display:block}}
h1{font-size:1.2rem;font-weight:700;letter-spacing:-.01em}
.sub{color:var(--ts);font-size:.875rem;line-height:1.55}
.rule{width:100%;height:1px;background:var(--bd);margin:.1rem 0}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:.4rem;
  padding:.7rem 1.5rem;border-radius:12px;font-size:.9rem;font-weight:600;cursor:pointer;
  border:none;width:100%;text-decoration:none;font-family:inherit;
  transition:background .15s,opacity .15s,transform .1s;letter-spacing:-.01em}
.btn:active{transform:scale(.97)}
.bp{background:var(--ac);color:#fff}.bp:hover{background:var(--ach)}
.bg_{background:transparent;color:var(--ts);border:1px solid var(--bd)}.bg_:hover{background:var(--bd)}
.emsg{color:var(--er);font-size:.8rem;padding:.55rem .85rem;
  background:rgba(239,68,68,.09);border-radius:10px;width:100%}
input[type=text]{width:100%;padding:.8rem 1rem;border:2px solid var(--bd);
  border-radius:12px;background:var(--bg);color:var(--t);font-size:1.25rem;
  text-align:center;letter-spacing:.15em;outline:none;
  transition:border-color .15s,box-shadow .15s;font-family:inherit}
input[type=text]:focus{border-color:var(--ac);box-shadow:0 0 0 3px rgba(79,70,229,.15)}
input::placeholder{color:var(--tm);letter-spacing:0;font-size:1rem}
.qr-box{background:#fff;border-radius:16px;padding:14px;
  border:1px solid rgba(0,0,0,.07);display:inline-block}
@keyframes spin{to{transform:rotate(360deg)}}
@keyframes fadein{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}
.fadein{animation:fadein .35s ease both}
`;

// CDN loader: logos with onerror fallback, font via FontFace API
const cdnScript = `(()=>{
  const C1='${CDN1}',C2='${CDN2}';
  // Logos: try CDN1, onerror → CDN2
  document.querySelectorAll('.logo-l').forEach(e=>{
    e.src=C1+'/logos/k.png';e.onerror=()=>e.src=C2+'/logos/k.png'});
  document.querySelectorAll('.logo-d').forEach(e=>{
    e.src=C1+'/logos/k-dark.png';e.onerror=()=>e.src=C2+'/logos/k-dark.png'});
  // Font: try CDN1, fallback CDN2
  const lf=cdn=>new FontFace('KD','url("'+cdn+'/fonts/kitsos-default/default_advanced.ttf")').load();
  lf(C1).then(f=>{document.fonts.add(f);document.body.style.fontFamily="'KD',system-ui,sans-serif"})
    .catch(()=>lf(C2).then(f=>{document.fonts.add(f);document.body.style.fontFamily="'KD',system-ui,sans-serif"}).catch(()=>{}));
})();`;

function page(title, body, extraScript = '') {
  return `<!doctype html><html lang=de>
<head>
<meta charset=UTF-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>${esc(title)} – Kitsos</title>
<style>${CSS}</style>
</head>
<body>
<div class=card>
  <img class="logo logo-l" src="" alt=Kitsos>
  <img class="logo logo-d" src="" alt=Kitsos>
  ${body}
</div>
<script>
${cdnScript}
${extraScript}
</script>
</body></html>`;
}

// ── QR Code page (Device 1) ───────────────────────────────────────────────────
function renderQRPage(dc, uc, vurl, env) {
  const body = `
<h1>Mit anderem Gerät anmelden</h1>
<p class=sub>Scanne den QR-Code mit dem Gerät,<br>auf dem du dich anmelden möchtest.</p>

<div id=pv class=fadein style="display:flex;flex-direction:column;align-items:center;gap:.8rem;width:100%">

  <div class=qr-box>
    <canvas id=qrc></canvas>
    <p id=qrfb style="display:none;padding:1.25rem 1rem;font-size:.8rem;color:#555;max-width:160px">
      QR-Code konnte nicht geladen werden
    </p>
  </div>

  <p style="font-size:.75rem;color:var(--tm);margin-top:-.1rem">
    oder gib diesen Code auf<br>
    <strong style="color:var(--ts)">${esc(env.WORKER_BASE_URL)}</strong> ein
  </p>

  <div style="font-size:1.9rem;font-weight:800;letter-spacing:.2em;color:var(--ac);
              font-variant-numeric:tabular-nums">${esc(uc)}</div>

  <div class=rule></div>

  <div style="display:flex;align-items:center;gap:.5rem;color:var(--ts);font-size:.875rem">
    <div id=sp style="width:14px;height:14px;border:2px solid var(--bd);
      border-top-color:var(--ac);border-radius:50%;animation:spin 1s linear infinite;flex-shrink:0"></div>
    Warte auf Anmeldung …
  </div>

  <div id=cd style="font-size:.78rem;color:var(--tm)">
    Gültig für <b id=ti>10:00</b>
  </div>

</div>

<div id=sv class=fadein style="display:none;flex-direction:column;align-items:center;gap:.8rem;width:100%">
  <div style="width:64px;height:64px;background:var(--ok);border-radius:50%;
              display:flex;align-items:center;justify-content:center;margin-top:.25rem">
    <svg width=30 height=30 viewBox="0 0 24 24" fill=none stroke=white
         stroke-width=2.5 stroke-linecap=round stroke-linejoin=round>
      <polyline points="20 6 9 17 4 12"/>
    </svg>
  </div>
  <h1>Erfolgreich angemeldet!</h1>
  <p class=sub>Du wirst gleich weitergeleitet …</p>
</div>
`;

  const script = `
const DC=${JSON.stringify(dc)};
const VURL=${JSON.stringify(vurl)};
const EXP=Date.now()+${SESSION_TTL * 1000};

// ── QR Code ──────────────────────────────────────────────────────────────────
(s=>{
  s.src='https://cdn.jsdelivr.net/npm/qrcode@1.5.3/build/qrcode.min.js';
  s.onload=()=>QRCode.toCanvas(document.getElementById('qrc'),VURL,{
    width:190,margin:1,color:{dark:'#18182e',light:'#ffffff'}
  });
  s.onerror=()=>{
    document.getElementById('qrc').style.display='none';
    document.getElementById('qrfb').style.display='block';
  };
  document.head.appendChild(s);
})(document.createElement('script'));

// ── Countdown ─────────────────────────────────────────────────────────────────
const ti=document.getElementById('ti'), cd=document.getElementById('cd');
const ct=setInterval(()=>{
  const ms=Math.max(0,EXP-Date.now()),m=Math.floor(ms/6e4),s=Math.floor(ms%6e4/1e3);
  ti.textContent=m+':'+(s<10?'0':'')+s;
  if(ms<6e4) cd.style.color='var(--er)';
  else if(ms<18e4) cd.style.color='#f59e0b';
  if(ms<=0){
    clearInterval(ct);clearInterval(pi);
    document.getElementById('pv').innerHTML=
      '<p style="color:var(--ts);padding:.75rem">Code abgelaufen.</p>'+
      '<button onclick="location.reload()" class="btn bg_" style="margin-top:.25rem">↻ Neu laden</button>';
  }
},1000);

// ── Poll ──────────────────────────────────────────────────────────────────────
const pi=setInterval(async()=>{
  try{
    const d=await fetch('/poll?device_code='+DC).then(r=>r.json());
    if(d.status==='authenticated'){
      clearInterval(pi);clearInterval(ct);
      document.getElementById('pv').style.opacity='0';
      document.getElementById('pv').style.transition='opacity .25s';
      setTimeout(()=>{
        document.getElementById('pv').style.display='none';
        const sv=document.getElementById('sv');
        sv.style.display='flex';
      },250);
      setTimeout(()=>{
        const u=new URL(d.redirect_uri||location.href);
        u.searchParams.set('code',d.relay_code);
        if(d.state)u.searchParams.set('state',d.state);
        location.href=u.toString();
      },1600);
    }else if(d.status==='expired'){clearInterval(pi);clearInterval(ct)}
  }catch(e){console.warn('poll error',e)}
},2000);
`;

  return page('Mit anderem Gerät anmelden', body, script);
}

// ── Code entry page (Device 2, GET /) ────────────────────────────────────────
function renderEntry(prefill = '', err = null) {
  const body = `
<h1>Code eingeben</h1>
<p class=sub>Gib den Code ein, der auf dem<br>anderen Gerät angezeigt wird.</p>
${err ? `<div class=emsg>${esc(err)}</div>` : ''}
<form method=POST action=/ style="display:flex;flex-direction:column;gap:.75rem;width:100%;margin-top:.15rem">
  <input type=text name=code placeholder="XXXX-XXXX"
    value="${esc(prefill)}" maxlength=9
    autocomplete=off autocapitalize=characters spellcheck=false autofocus
    oninput="const v=this.value.replace(/[^A-Z0-9]/gi,'').toUpperCase().slice(0,8);this.value=v.length>4?v.slice(0,4)+'-'+v.slice(4):v">
  <button type=submit class="btn bp">Weiter →</button>
</form>
`;
  return page('Code eingeben', body);
}

// ── Device 2 success page ─────────────────────────────────────────────────────
function renderDevice2Success(env) {
  const body = `
<div class=fadein style="display:flex;flex-direction:column;align-items:center;gap:.8rem;width:100%">
  <div style="width:68px;height:68px;background:var(--ok);border-radius:50%;
              display:flex;align-items:center;justify-content:center;margin-top:.25rem">
    <svg width=32 height=32 viewBox="0 0 24 24" fill=none stroke=white
         stroke-width=2.5 stroke-linecap=round stroke-linejoin=round>
      <polyline points="20 6 9 17 4 12"/>
    </svg>
  </div>
  <h1>Anmeldung erfolgreich!</h1>
  <p class=sub>Das andere Gerät wurde angemeldet.<br>Du kannst dieses Fenster jetzt schließen.</p>
  <div class=rule></div>
  <a href="${esc(env.LOGOUT_URL ?? '/')}" class="btn bg_">Abmelden</a>
</div>
`;
  return page('Anmeldung erfolgreich', body);
}

// ── Error page ────────────────────────────────────────────────────────────────
function renderError(msg) {
  const body = `
<div class=fadein style="display:flex;flex-direction:column;align-items:center;gap:.8rem;width:100%">
  <div style="width:60px;height:60px;background:rgba(239,68,68,.1);border-radius:50%;
              display:flex;align-items:center;justify-content:center;margin-top:.25rem">
    <svg width=28 height=28 viewBox="0 0 24 24" fill=none stroke=var(--er)
         stroke-width=2 stroke-linecap=round stroke-linejoin=round>
      <circle cx=12 cy=12 r=10/><line x1=12 y1=8 x2=12 y2=12/>
      <line x1=12 y1=16 x2=12.01 y2=16/>
    </svg>
  </div>
  <h1>Etwas ist schiefgelaufen</h1>
  <p class=sub>${esc(msg)}</p>
  <div class=rule></div>
  <a href=/ class="btn bg_">← Zurück</a>
</div>
`;
  return page('Fehler', body);
}

// ─── Main Router ──────────────────────────────────────────────────────────────
export default {
  async fetch(request, env) {
    const url    = new URL(request.url);
    const path   = url.pathname;
    const method = request.method;

    try {
      // OIDC discovery + JWKS
      if (path === '/.well-known/openid-configuration' && method === 'GET') return onDiscover(env);
      if (path === '/jwks'                             && method === 'GET')  return onJwks(env);

      // Device 1: start cross-device flow
      if (path === '/authorize'            && method === 'GET')  return onAuthorize(url, env);

      // RFC 8628: Device Authorization Grant
      if (path === '/device_authorization' && method === 'POST') return onDeviceAuthorize(request, env);

      // Device 2: scan QR code link
      if (path === '/activate'             && method === 'GET')  return onActivate(url, env);

      // Upstream OIDC callback (after Device 2 authenticates)
      if (path === '/callback'             && method === 'GET')  return onCallback(url, env);

      // Token exchange (Device 1 relay_code → tokens, or RFC 8628 poll)
      if (path === '/token'                && method === 'POST') return onToken(request, env);

      // Device 1 status polling
      if (path === '/poll'                 && method === 'GET')  return onPoll(url, env);

      // RP-initiated logout
      if (path === '/logout'               && method === 'GET')  return onLogout(url, env);

      // Device 2: manual code entry page
      if (path === '/'                     && method === 'GET')
        return hRes(renderEntry(url.searchParams.get('code') ?? ''));

      // Device 2: submit code
      if (path === '/'                     && method === 'POST') return onCodePost(request, env);

      return new Response('Not Found', { status: 404 });
    } catch (e) {
      console.error('Worker error:', e);
      return new Response('Internal Server Error', { status: 500 });
    }
  }
};
