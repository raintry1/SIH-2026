# SIH 2026 — Gmail Client

A full-stack, secure web application that lets users **sign in with Google** and **read their Gmail inbox** with a clean, Gmail-like UI.

Built for **Smart India Hackathon 2026**.

- **Frontend** (`web/`): React 18 + Vite + Material-UI + Tailwind CSS — hosted on **Vercel**
- **Backend** (`api/`): Node.js + Express + Firebase Admin SDK + Google APIs — hosted on **Render**
- **Authentication**: Firebase Auth (Google Sign-In) + Google Identity Services
- **Email access**: Gmail API (`users.messages.list` + `users.messages.get`) with **read-only** permission

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
│   │   │   └── EmailDetail.jsx         # Full email (HTML rendered, sanitized)
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
│   │   └── services/gmail.js          # Gmail API calls + body parsing
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

## Tech Stack

**Frontend** (`web/`): `react` `react-dom` `react-router-dom` `firebase` `@react-oauth/google` `axios` `@mui/material` `@emotion/*` `dompurify` `vite` `tailwindcss`

**Backend** (`api/`): `express` `firebase-admin` `googleapis` `cors` `dotenv`

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

---

## Deployment

### Render (backend) — deployed

- Web Service linked to GitHub repo, branch `main`.
- Build: `npm install` · Start: `npm start` (root `package.json` runs `node api/src/server.js`).
- Render assigns `PORT` automatically; the server respects it.
- Env vars on Render: `FIREBASE_SERVICE_ACCOUNT`, `CORS_ORIGINS`, `GOOGLE_CLIENT_ID`.

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

---

## Scripts

| Command | Directory | Purpose |
|---------|-----------|---------|
| `npm run dev` | `web/` | Vite dev server (5173) |
| `npm run build` | `web/` | Production build to `dist/` |
| `npm run dev` | `api/` | API dev server with reload (3001) |
| `npm start` | root / `api/` | Start API server |