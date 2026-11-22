# CrossPlay Auth V1 — new product workspace

This is a new product baseline. It does **not** modify or reuse the Huangguo Short Drama IPA.

## Project layout

- `server/`: FastAPI authorization API and SQLite persistence
- `apps/admin/`: Expo / React Native iOS administrator app
- `apps/user/`: Expo / React Native iOS controlled-user app
- `docker-compose.yml`: single-host API deployment

## Product rules

1. Administrator and controlled-user accounts have separate role-scoped login endpoints.
2. Controlled users self-register; the administrator never needs their password.
3. The administrator manages sources, video records, user accounts, and grants.
4. A controlled user's catalog and search return only currently authorized videos.
5. A playback ticket is issued only after a fresh server-side authorization check.
6. Revoking or expiring a grant removes the video from the catalog and blocks subsequent ticket and media requests.
7. The media gateway proxies standard HTTPS HLS and MP4 resources without returning upstream source URLs to the apps. It checks authorization for each media request, rewrites HLS segment/key/playlist references back through the gateway, and rechecks an open media stream at short intervals.
8. Grant issuance and revocation are written to an administrator-only audit log; duplicate active grants and past expiry timestamps are rejected.

## Local API setup

```bash
cd server
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python -m uvicorn app.main:app --reload
```

The first administrator is created from `ADMIN_USERNAME` and `ADMIN_PASSWORD` on first startup. Local default values in `.env.example` are for development only. The API docs are at `http://127.0.0.1:8000/docs`.

## Server deployment with Docker

1. Copy `server/.env.example` to `server/.env`.
2. Set a unique `ADMIN_PASSWORD` and a random `TOKEN_SECRET` of at least 32 bytes.
3. Run `docker compose up -d --build` from the project root.
4. Put the API behind HTTPS (reverse proxy / managed TLS) before connecting real iPhones.

Production startup deliberately refuses the sample admin password or sample token secret.

## iOS app setup

For each app folder:

```bash
npm install
npx expo start
```

On a physical phone, enter the reachable HTTPS API address on the login screen. `127.0.0.1` means the phone itself, not your server.

To create signed iOS builds, configure EAS Build and your Apple Developer signing credentials:

```bash
npm install -g eas-cli
eas login
eas build --platform ios --profile preview
```

The two apps have different bundle identifiers. An installable IPA requires an Apple signing setup; this repository alone is not a signed IPA.

## Source and playback integration

The source form stores a source endpoint and source kind. A video record stores a provider-specific `playback_ref` (a relative path under the source endpoint or an absolute HTTPS URL). The initial gateway supports ordinary HTTPS HLS (`.m3u8`) and MP4 resources. It rewrites HLS playlist, segment, subtitle, and AES-128 key references through the authorization gateway. Non-public hosts, non-HTTPS URLs, non-standard ports, and DRM-protected HLS methods are rejected.

Before production use, the media gateway still needs provider-specific validation and load testing. In particular:

- Resolve `playback_ref` on the server, never return the upstream URL to the app.
- Proxy HLS master/media playlists, segments, subtitles, and encryption keys through the authorization gateway.
- Rewrite every playlist URI to the protected gateway.
- Check grant status on each media request (or an equivalently short revocation interval).
- Handle upstream authentication only with credentials the operator is authorized to use.
- Respect provider terms, access controls, and DRM. This project does not bypass DRM, login walls, subscriptions, or other restrictions.

If a provider uses a custom API, signed cookies, unusual redirects, DRM, or a non-standard playlist format, a dedicated adapter may still be required. The gateway is not a DRM bypass and will not access content without valid upstream authorization.

## Current verification

The API test suite currently passes 8 tests covering admin login, user registration/login, role separation, source/video creation, authorized catalog filtering, expiry, duplicate grants, audit logging, ticket issuance, HLS playlist rewriting, SSRF host rejection, and revocation denial. The app source and Expo configuration are present, but a full native iOS compile, physical-device playback test, production deployment, and signed IPA generation have not yet been performed.
