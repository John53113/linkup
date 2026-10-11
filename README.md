# Linkup starter

A starter Progressive Web App with:
- username + four-digit PIN registration/login
- Cloudflare Worker API with PBKDF2 PIN hashing and signed HttpOnly sessions
- Cloudflare D1 profile storage
- editable display name, status and avatar URL
- in-app notification list and browser notification permission
- service-worker shell/offline fallback and push event handler
- starter video-call, walkie-talkie and chat screens

## Important limitations

The video call, walkie-talkie and chat screens are UI prototypes; they do not yet send live media or cross-device messages. The push subscription endpoint stores a browser subscription, but server-side Web Push delivery still needs VAPID keys and a sender implementation. Browser notifications require permission and are subject to browser/device rules.

Four-digit PINs are low-entropy credentials. The API throttles attempts, but before a public launch add stronger abuse controls (e.g. Cloudflare Turnstile, per-IP/user rate limiting using a dedicated rate-limit service, monitoring, and account recovery). Do not reuse an important PIN. There is no email-based recovery.

## Files

- `public/index.html` — app UI and client-side interactions
- `public/manifest.webmanifest` — installable PWA metadata
- `public/sw.js` — service worker, offline shell and push event display
- `public/icon.svg` — app icon
- `worker.js` — Cloudflare Worker API
- `schema.sql` — D1 schema
- `wrangler.toml` — deployment configuration

## Setup

1. Create a GitHub repository and upload these files preserving the `public/` folder.
2. In Cloudflare, create a D1 database named `linkup-db`.
3. Run `schema.sql` against that database (Cloudflare dashboard SQL console or Wrangler).
4. Copy the D1 database ID into `wrangler.toml` in place of `REPLACE_WITH_YOUR_D1_DATABASE_ID`.
5. Install Wrangler locally if deploying from your computer, then run:
   ```sh
   npm install -D wrangler
   npx wrangler d1 execute linkup-db --remote --file=./schema.sql
   npx wrangler secret put SESSION_SECRET
   ```
   For `SESSION_SECRET`, use a long random secret (at least 32 random bytes). Do not put it in GitHub or in client-side code.
6. Deploy with:
   ```sh
   npx wrangler deploy
   ```
7. Connect the GitHub repository to Cloudflare Workers Builds if you want deployments on every push. Make sure it uses this `wrangler.toml`.

For local development, create the D1 database binding and run `npx wrangler dev`. Use HTTPS in production; the session cookie is Secure.

## Security notes

- Usernames are case-insensitive for sign-in.
- PINs are salted and hashed with PBKDF2-SHA-256 (310,000 iterations), never stored as plain text.
- Sessions are HMAC-signed and sent in Secure, HttpOnly, SameSite=Lax cookies.
- The Worker only accepts same-origin API requests.
- Add a proper production rate-limit/abuse protection layer before public launch.
