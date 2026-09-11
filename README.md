# Gmail Client — SIH 2026

A full-stack Gmail web client with Firebase Authentication (Google Sign-In) and Gmail API integration.

- **Frontend** (`web/`): React + Vite + Material-UI + Tailwind, hosted on **Vercel**
- **Backend** (`api/`): Node.js + Express + Firebase Admin + Google APIs, hosted on **Render**

---

## Architecture

```
Browser (Google Identity Services)
   │  Google Sign-In with gmail.readonly scope
   ▼
web/  ── Firebase Auth (user identity) ──►  Firebase Admin (verify token)
   │
   └── calls api/ with: Bearer <Firebase ID token>  +  x-gmail-token <Gmail OAuth token>
       ▼
api/  ── verifies Firebase token ──►  calls Gmail API using user's token
```

- **Login**: `@react-oauth/google` gets a Google ID token **and** a Gmail-scoped OAuth access token. The ID token is exchanged into Firebase; the Gmail token is kept in `sessionStorage` only.
- **Security**: every backend Gmail call requires a verified Firebase ID token. The Gmail OAuth token is passed per-request and never stored on the server.
- **Real-time**: the frontend polls the email list every 30 seconds for new mail.

---

## Prerequisites

1. Node.js 18+
2. A Google Cloud project with:
   - **Gmail API** enabled
   - An **OAuth 2.0 Client ID** of type **Web application** with `https://www.googleapis.com/auth/gmail.readonly` scope
   - Authorized **JavaScript origins** and **redirect URIs** set to your Vercel URL + `http://localhost:5173`
3. A **Firebase** project with Google Sign-In enabled.

---

## Setup

### 1. Frontend (`web/`)

```bash
cd web
cp .env.example .env    # fill in values
npm install
npm run dev             # http://localhost:5173
```

`.env` values:

| Variable | Description |
|----------|-------------|
| `VITE_FIREBASE_*` | Your Firebase web app config (from Firebase Console) |
| `VITE_GMAIL_CLIENT_ID` | Your Google OAuth Web Client ID |
| `VITE_API_URL` | Backend URL (Vite proxies `/api` → `http://localhost:3001` in dev) |

### 2. Backend (`api/`)

```bash
cd api
cp .env.example .env
# Place your Firebase service account key here (from Firebase Console → Project settings → Service accounts → Generate new private key)
# Name it: serviceAccountKey.json
npm install
npm run dev            # http://localhost:3001
```

`.env` values:

| Variable | Description |
|----------|-------------|
| `PORT` | Server port (default 3001) |
| `FIREBASE_SERVICE_ACCOUNT_PATH` | Path to `serviceAccountKey.json` (local) |
| `FIREBASE_SERVICE_ACCOUNT` | Full service-account JSON string (preferred on Render) |
| `CORS_ORIGINS` | Comma-separated allowed origins |
| `GOOGLE_CLIENT_ID` | Your Google OAuth Web Client ID |

### 3. Firebase Console steps

1. **Add a web app** to your Firebase project → copy the config into `web/.env`.
2. **Authentication → Sign-in method → Enable Google**.
3. **Project settings → Service accounts → Generate new private key** → save as `api/serviceAccountKey.json` (⚠️ never commit this file).
4. In **Google Cloud Console → OAuth consent screen**: add test users and the `gmail.readonly` scope; publish if you want it available to everyone.

---

## Deployment

### Frontend → Vercel

1. Push the repo to GitHub (private is fine).
2. Import the repo in Vercel; set **Root Directory** to `web`.
3. Add all `VITE_*` environment variables (Vite exposes only those prefixed with `VITE_`).
4. Deploy. Add your production URL to the OAuth client's authorized JS origins/redirect URIs.

### Backend → Render

1. Create a **Web Service** in Render linked to the same repo; set **Root Directory** to `api`.
2. Build command: `npm install`
3. Start command: `npm start`
4. Add env vars: `PORT`, `CORS_ORIGINS` (your Vercel URL), and `FIREBASE_SERVICE_ACCOUNT` (full JSON string).
5. In the Firebase **Web App** settings, add your Render URL to the authorized domains if needed.

---

## API Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/health` | none | Health check |
| `GET` | `/api/emails` | Firebase token | List emails (query: `pageToken`, `maxResults`) |
| `GET` | `/api/emails/:id` | Firebase token | Full message with decoded body |

All `/api/*` routes require header `Authorization: Bearer <firebase-id-token>`. The Gmail call additionally uses header `x-gmail-token: <oauth-access-token>` (sent automatically by the frontend).

---

## Security Notes

- `.env` files and `serviceAccountKey.json` are gitignored — never commit them.
- HTML email bodies are sanitized on the client with `DOMPurify` before rendering.
- The Gmail OAuth token is only kept in `sessionStorage` and cleared on logout.