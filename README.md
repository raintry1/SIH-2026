# SIH 2026 — Gmail Client

A full-stack, secure web application that lets users **sign in with Google**, **read their Gmail inbox** with a clean, Gmail-like UI, and **scan email links for phishing** in one click.

Built for **Smart India Hackathon 2026**.

- **Frontend** (`web/`): React 18 + Vite + Material-UI + Tailwind CSS — hosted on **Vercel**
- **Backend** (`api/`): Node.js + Express + Firebase Admin SDK + Google APIs — hosted on **Render**
- **Authentication**: Firebase Auth (Google Sign-In) + Google Identity Services
- **Email access**: Gmail API (`users.messages.list` + `users.messages.get`) with **read-only** permission
- **Phishing protection**: per-link verdicts (Safe / Suspicious / Malicious / Unknown) against the **Hybrid Analysis** threat-intelligence API

---

## Live URLs

| Service | URL |
|---------|-----|
| Frontend (Vercel) | `https://sih-2026-iota-rouge.vercel.app` |
| Backend (Render) | `https://sih-2026-backend-re9s.onrender.com` |
| Backend health check | `https://sih-2026-backend-re9s.onrender.com/health` |
| Source code | `https://github.com/raintry1/SIH-2026` |

---

## Project Structure

```
SIH-2026/
├── web/                      # Frontend  (deployed on Vercel)
│   ├── src/
│   │   ├── config/firebase.js          # Firebase app initialization
│   │   ├── auth/authService.js         # Google token <-> Firebase sign-in, token storage
│   │   ├── api/gmailApi.js             # Axios client + auth headers
│   │   ├── components/
│   │   │   ├── Login.jsx               # Google sign-in button
│   │   │   ├── GmailConnector.jsx      # Re-connect Gmail when token is missing
│   │   │   ├── Layout.jsx              # App bar + user avatar
│   │   │   ├── EmailList.jsx           # Scrollable inbox, 30s polling
│   │   │   ├── EmailListItem.jsx       # Sender / subject / date / snippet
│   │   │   └── EmailDetail.jsx         # Full email + phishing scan results
│   │   ├── pages/Dashboard.jsx         # Master-detail layout
│   │   └── utils/format.js             # Date helpers
│   ├── .env.example / .env.production
│   └── package.json
├── api/                       # Backend  (deployed on Render)
│   ├── src/
│   │   ├── server.js                  # Express app, CORS, routes
│   │   ├── firebase.js                # Firebase Admin SDK init (service account)
│   │   ├── middleware/auth.js         # Firebase JWT verification
│   │   ├── routes/gmail.js            # /api/emails endpoints
│   │   ├── routes/security.js         # POST /api/security/check
│   │   ├── services/gmail.js          # Gmail API calls + body parsing
│   │   └── services/phishing.js       # Phishing link scanner (Hybrid Analysis)
│   └── package.json
├── package.json               # Root package (Render start command)
└── README.md
```

---

## How Authentication & Security Work

### 1. The sign-in flow (frontend)

1. User clicks **"Sign in with Google"**.
2. Google Identity Services (`@react-oauth/google` `useGoogleLogin`) opens Google's popup requesting read-only Gmail access: `email profile openid https://www.googleapis.com/auth/gmail.readonly`
3. Google returns an **access_token** (for the Gmail API) to the browser.
4. The **same token** is used to sign into **Firebase** via `GoogleAuthProvider.credential(null, accessToken)`.
5. The Gmail `access_token` is stored in `sessionStorage` only (never `localStorage`, never on the server).

### 2. Every backend request is authenticated

Every frontend API call (added automatically by the `gmailApi.js` Axios interceptor) carries two credentials:

```
Authorization: Bearer <Firebase ID token>    <- proves WHO you are
x-gmail-token: <Gmail OAuth access token>    <- grants access to YOUR Gmail
```

Backend flow for each request:

```
Request → /api/*
   -> middleware/auth.js verifies the Firebase ID token
      (crypto signature + expiry + audience) with Firebase Admin SDK
   -> invalid/missing/expired  =>  401 Unauthorized
   -> valid => route uses x-gmail-token to call the Gmail API as that user
```

### 3. Why endpoints are safe (no leaks)

| Threat | How it is prevented |
|--------|---------------------|
| Calling `/api/emails` without logging in | Missing Firebase token → **401** |
| Forged / expired token | `admin.auth().verifyIdToken()` rejects invalid signatures & expired JWTs → **401** |
| Reading someone else's mail | Every Gmail call uses `userId: 'me'` with **your** `x-gmail-token`. There is no way to pass another user's mailbox. |
| Stealing the service-account private key | Exists **only as an env var on Render**, never in the repo, never in the client. |
| Gmail token theft | Lives in `sessionStorage`, dies on tab close / logout, sent over HTTPS only. |
| CORS abuse from other websites | `CORS_ORIGINS` allowlist — only Vercel + localhost origins are accepted. |
| HTML email attacks (XSS) | All HTML bodies sanitized with **DOMPurify** before rendering. |
| Secrets in git | `.env` and `serviceAccountKey.json` are gitignored. Committed `.env.production` holds only public Firebase config + OAuth Client ID. |

> The Firebase **web config** (`apiKey`, `projectId`, etc.) and Google **OAuth Client ID** are designed to be public in a web app — they identify your app, they are not secrets. The only true secret is the service-account private key, which never leaves Render.

### gmail.readonly principle

- Scope is only **`https://www.googleapis.com/auth/gmail.readonly`** → the app can only **READ** emails, never send/modify/delete.
- Each user only ever sees their own inbox.
- The token is short-lived and cleared on logout.

---

## API Endpoints

Base URL: `https://sih-2026-backend-re9s.onrender.com`

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/health` | none | Health check |
| `GET` | `/api/emails?pageToken=&maxResults=` | Firebase token + Gmail token | List inbox (sender, subject, date, snippet, unread) with pagination |
| `GET` | `/api/emails/:id` | Firebase token + Gmail token | Full message with decoded HTML + plain body |
| `POST` | `/api/security/check` | Firebase token + Gmail token | Scan all links in an email for phishing → per-link + summary verdicts |

Headers required on `/api/*`:

```
Authorization: Bearer <firebase-id-token>
x-gmail-token: <google-gmail-oauth-access-token>
```

Example:

```bash
curl -X GET "https://sih-2026-backend-re9s.onrender.com/api/emails?maxResults=5" \
  -H "Authorization: Bearer <FIREBASE_TOKEN>" \
  -H "x-gmail-token: <GMAIL_TOKEN>"
```

---

## Phishing Link Scanner

Every opened email gets a **Scan for phishing** action (bell/shield icon in the toolbar of `EmailDetail.jsx`).

### How a link is checked (`api/src/services/phishing.js`)

Each URL found in the email body goes through a **3-layer pipeline** — fronted by an in-memory cache so repeated scans are instant:

1. **Free DB lookup** — `hash-for-url` → `search/hash` against Hybrid Analysis's public threat-intel database. Aggregates only **recent** (≤ 2 years) `SUCCESS` reports and uses a dominance rule (`malicious >= safe`, etc.) so legitimate domains like google.com never false-positive on old/one-off reports.
2. **Exact-URL search** — `POST /search/terms?url=<full url>` returns the exact submission record (`verdict`, `av_detect`, `analysis_start_time`). Free, **not** rate-limited, and it resolves malicious URLs even when the per-domain quick-scan quota is exhausted.
3. **On-demand quick scan** — `POST /quick-scan/url` + polling until the sandbox report finishes. Verdicts come from the aggregate of scanner signals: any `malicious` ⇒ **Malicious**; suspicious/unsure signals ≥ clean signals ⇒ **Suspicious**; otherwise clean ⇒ **Safe**.

### Verdicts

| Verdict | Meaning | UI |
|---------|---------|-----|
| `safe` | No threat found (DB match or clean scan) | Green chip |
| `suspicious` | Sandbox signals lean malicious | Yellow/amber chip |
| `malicious` | Confirmed malware/phishing report | Red chip + **"Click blocked"** card |
| `unknown` | Could not verify (no DB record & scan timed out) | Grey chip + "open with caution" banner |

- Gmail/Google **infrastructure URLs** (signature images on `googleusercontent.com`, `gmail.com`, etc.) are auto-skipped — they are always safe and never shown as links to verify.
- Per-URL checks run with **concurrency 4** and short timeouts, so a full email scan typically finishes in ~2s.
- The email summary banner reflects the worst verdict found (never claims "safe" while any link is unverified).

### Example response

```json
{
  "links": [
    {
      "url": "https://something-for-you-check.netlify.app/?id=7202927639",
      "hostname": "something-for-you-check.netlify.app",
      "verdict": "malicious",
      "source": "db",
      "threatScore": 85,
      "label": "Malicious"
    },
    { "url": "https://www.google.com/", "verdict": "safe", "source": "db", "threatScore": 0, "label": "No specific threat" }
  ],
  "summary": {
    "verdict": "malicious",
    "count": 2,
    "highestSeverity": "malicious",
    "counts": { "malicious": 1, "safe": 1 }
  }
}
```

---

## Tech Stack

**Frontend** (`web/`): `react` `react-dom` `react-router-dom` `firebase` `@react-oauth/google` `axios` `@mui/material` `@emotion/*` `dompurify` `vite` `tailwindcss`

**Backend** (`api/`): `express` `firebase-admin` `googleapis` `cors` `dotenv` `tldts`

**Threat intelligence**: [Hybrid Analysis (Falcon Sandbox)](https://www.hybrid-analysis.com) public API v2 — free tier. Requires an API key (create at hybrid-analysis.com → *My account → API*).

---

## Local Development

Requirements: **Node.js 18+** and **npm**.

### 1. Backend

```bash
cd api
npm install
cp .env.example .env          # fill in values
# place your Firebase service-account key here (never commit it):
#   api/serviceAccountKey.json
# phishing works out of the box once HYBRIDANALYSIS_API_KEY is set in .env
npm run dev                   # -> http://localhost:3001
```

### 2. Frontend

```bash
cd web
npm install
cp .env.example .env          # fill in values
npm run dev                   # -> http://localhost:5173
```

> The Vite dev server proxies `/api/*` → `http://localhost:3001`, so no CORS issues locally.

### 3. Test

1. Sign in with Google.
2. Your inbox loads in the left panel (refreshes every 30s).
3. Click any email → full message opens on the right (Gmail-style master-detail).
4. Click **Scan for phishing** → per-link verdicts + a summary banner appear in ~2s.

---

## Deployment

### Render (backend) — deployed

- Web Service linked to GitHub repo, branch `main`.
- Build: `npm install` · Start: `npm start` (root `package.json` runs `node api/src/server.js`).
- Render assigns `PORT` automatically; the server respects it.
- Env vars on Render: `FIREBASE_SERVICE_ACCOUNT`, `CORS_ORIGINS`, `GOOGLE_CLIENT_ID`, `HYBRIDANALYSIS_API_KEY`.

### Vercel (frontend) — deployed

- Project `sih-2026`, Root Directory `web`.
- Build: `npm run build` · Output: `dist`.
- Env vars: `VITE_FIREBASE_*`, `VITE_GMAIL_CLIENT_ID`, `VITE_API_URL` (→ Render URL).

---

## Remaining Setup (Google OAuth origins)

Login is currently blocked with `Error 400: origin_mismatch` because the live origin `https://sih-2026-iota-rouge.vercel.app` is not registered on the OAuth client.

1. Google Cloud Console → **APIs & Services → Credentials**.
2. Open OAuth client `476115290827-snmunld87gppmff222ui13qnb5bvnffc.apps.googleusercontent.com`.
3. **Authorized JavaScript origins** → add `https://sih-2026-iota-rouge.vercel.app` (keep `http://localhost:5173`).
4. **Authorized redirect URIs** → add `https://sih-2026-iota-rouge.vercel.app`.
5. **Save** — propagation takes 1–5 minutes.

Optional (OAuth consent screen): add team test users while in "Testing" mode; request verification before public launch.

---

## Real-time Updates

The inbox polls every 30 seconds (`EmailList.jsx`), so new mail appears without a page refresh. No webhooks/Pub-Sub required.

---

## Known Limitations

- Read-only by design — no compose/send/archive/delete.
- Attachments are parsed in the raw message but not rendered as downloadable files.
- On hard refresh the sessionStorage Gmail token is gone → app shows **"Connect Gmail"** to re-grant (Firebase session persists; one click reconnects).
- Hybrid Analysis quick scans are limited per domain (~2/hour); the free DB-layer lookups avoid this for already-analyzed URLs, but a **never-before-seen** URL may occasionally report `unknown` when the scan quota is hit.
- Free-tier Render/Vercel cold-start after ~15 min idle: the first load of each deploy after inactivity can take ~30s.

---

## Scripts

| Command | Directory | Purpose |
|---------|-----------|---------|
| `npm run dev` | `web/` | Vite dev server (5173) |
| `npm run build` | `web/` | Production build to `dist/` |
| `npm run dev` | `api/` | API dev server with reload (3001) |
| `npm start` | root / `api/` | Start API server |