# crossgate

A Cloudflare Worker that enables cross-device OIDC login via QR code.
Acts as an OIDC proxy: Device 1 shows a QR code and waits; Device 2 scans it,
authenticates at the upstream OIDC provider, and the session is securely relayed back.

![Cloudflare Workers](https://img.shields.io/badge/Cloudflare-Workers-F38020?logo=cloudflare&logoColor=white)
![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)

## How it works

```
Device 1 (browser) → /authorize        → shows QR code + user code
Device 2 (phone)   → scans QR          → authenticates at upstream OIDC
Upstream           → /callback          → tokens stored in KV
Device 1           → polls /poll        → redirected with relay code → exchanges for tokens
```

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/.well-known/openid-configuration` | OIDC Discovery |
| `GET` | `/authorize` | Device 1 entry – shows QR page |
| `GET` | `/activate?code=XXXX-XXXX` | Device 2 scans QR link |
| `GET` | `/callback` | Upstream OIDC callback |
| `POST` | `/token` | Exchange relay_code for tokens (+ RFC 8628 poll) |
| `GET` | `/poll?device_code=...` | Device 1 status poll (every 2 s) |
| `GET` | `/` | Manual code entry for Device 2 |
| `POST` | `/device_authorization` | RFC 8628 Device Authorization Grant |

## Environment variables

| Variable | Required | Description |
|----------|----------|-------------|
| `WORKER_BASE_URL` | required | e.g. `https://crossgate.kitsos.net` |
| `UPSTREAM_ISSUER` | required | Base URL of upstream OIDC provider |
| `UPSTREAM_CLIENT_ID` | required (secret) | Worker's client_id |
| `UPSTREAM_CLIENT_SECRET` | required (secret) | Worker's client_secret |
| `LOGOUT_URL` | required (secret) | URL for Device 2's logout button |
| `UPSTREAM_AUTH_ENDPOINT` | optional | Override upstream `/authorize` |
| `UPSTREAM_TOKEN_ENDPOINT` | optional | Override upstream `/token` |

## Setup

**Prerequisites:** Cloudflare account, Wrangler CLI, upstream OIDC provider

1. **Clone the repo**
   ```sh
   git clone https://github.com/kitsos-net/crossgate.git
   cd crossgate
   ```

2. **Create KV namespace**
   ```sh
   wrangler kv:namespace create SESSIONS
   ```
   Update the `id` in `wrangler.toml` with the returned namespace ID.

3. **Set secrets**
   ```sh
   wrangler secret put UPSTREAM_CLIENT_ID
   wrangler secret put UPSTREAM_CLIENT_SECRET
   wrangler secret put LOGOUT_URL
   ```

4. **Configure upstream OIDC client**
   - Allowed Callback URLs: `https://crossgate.kitsos.net/callback`
   - Grant Types: Authorization Code + PKCE

5. **Configure Device 1's app to use crossgate as its OIDC provider**
   - Authorization Endpoint: `https://crossgate.kitsos.net/authorize`
   - Token Endpoint: `https://crossgate.kitsos.net/token`
   - JWKS URI: `{UPSTREAM_ISSUER}/.well-known/jwks.json`
     _(id_tokens are issued by upstream and verified against upstream JWKS)_

6. **Deploy**
   ```sh
   wrangler deploy
   ```

## Local development

```sh
cp .dev.vars.example .dev.vars
# fill in real values
wrangler dev
```

## License

[MIT](LICENSE)
