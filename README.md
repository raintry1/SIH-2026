# SIH 2026 — Gmail Security Client

A full-stack, secure web application that lets users **sign in with Google**, **read their Gmail inbox** with a clean, Gmail-like UI, and **scan email links + attachments for phishing/malware** in one click.

Built for **Smart India Hackathon 2026**.

- **Frontend** (`web/`): React 18 + Vite + Material-UI + Tailwind CSS — hosted on **Vercel**
- **Backend** (`api/`): Node.js + Express + Firebase Admin SDK + Google APIs — hosted on **Render**
- **Authentication**: Firebase Auth (Google Sign-In) + Google Identity Services
- **Email access**: Gmail API (`users.messages.list` + `users.messages.get`) with **read-only** permission
- **Phishing protection**: per-link verdicts (Safe / Suspicious / Malicious / Unknown) via **Hybrid Analysis** threat-intel + local structural heuristics + per-domain **domain intelligence** (WHOIS / DNS / IP Geo / SSL / Threat-list / Reverse-IP)
- **File protection**: email attachment scanning via SHA-256 hash DB lookup + risky-extension heuristics (high-risk, macro-enabled, archive)

---

## Problem & How We Solved It

| Problem | Symptom | Solution |
|---------|---------|----------|
| **URL shorteners hid the real target** | Two tinyurl/bit.ly links both got cached under the shortener host → one "unknown" verdict poisoned the other; never saw the resolved destination | Resolve shorteners (24 services) to the **real URL** before scanning; cache keyed on the resolved target so each link is judged independently (`resolveShortener` in `domainIntel.js`) |
| **Hybrid Analysis API is slow** | Hard-coded 8s timeouts aborted every lookup → **every link returned `unknown`** | Timeouts raised to 25s; the 3 sources (DB hash, exact-URL search, quick-scan) still run in **parallel** and the first conclusive answer wins |
| **Recency window was too tight** | HA DB reports from 2023 fell outside the 2-year filter in 2026 → known domains had no usable reports | **Dual-window aggregation**: trust the fresh 2-year window first, fall back to a 5-year window only when no recent data exists (and only if not contradicted by clean reports, so paypal/google never false-positive) |
| **HA quick-scan intermittently fails** | Sandbox returned `400 domain does not exist` even for paypal.com (server-side outage) → all links unknown | Added a **structural heuristic fallback**: raw-IP host + non-standard port + phishing paths (`ReportViewer.aspx`, `webscr`, `login.php`, …) → suspicious/malicious with **zero external API calls** |
| **Phishing sites hide on free hosting / subdomains** | Bare `something.netlify.app` pages carry no warning for users | Per-flagged-link **domain intelligence card**: hosting-platform detection, subdomain/base split, SSL issuer, IP geo-location, proxy/Tor flags, threat-list status |
| **Old/noisy reports on legit domains** | google.com had old (2020-21) malicious flags → risk of false positive | Flags are trusted only when they **dominate a clean window**; mixed evidence returns `unknown` (never a false "malicious") |

**Result:** a phishing link scanned through the app today is flagged `Malicious` even during a HA outage — detection no longer depends on a single flaky API.

---

## Live URLs

| Service | URL |
|---------|-----|
| Frontend (Vercel) | `https://sih-2026-iota-rouge.vercel.app` |
| Frontend (custom domain) | `https://www.sih26106.duckdns.org` |
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
│   │   │   └── EmailDetail.jsx         # Full email + scan results + domain-intel card
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
│   │   ├── services/gmail.js          # Gmail API calls + body parsing + attachment extraction
│   │   ├── services/phishing.js       # Phishing link scanner (HA + shortener + heuristics)
│   │   ├── services/domainIntel.js    # Domain intelligence (6 parallel lookups) + shortener resolution
│   │   └── services/filecheck.js      # Attachment file scanner (HA DB hash + extension heuristics)
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
| `POST` | `/api/security/check` | Firebase token + Gmail token | Scan all links + attachments in an email → per-link, per-attachment, + combined summary verdicts |

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

Each URL found in the email body goes through this pipeline — fronted by an in-memory cache so repeated scans are instant:

1. **Shortener resolution** (`domainIntel.js`) — tinyURL / bit.ly / t.co / 24+ services are resolved to the **real destination URL** first. Cache keys are based on the resolved target, so two different short links pointing at different pages are never cross-contaminated.

2. **Free DB lookup** — `hash-for-url` → `search/hash` against Hybrid Analysis's public threat-intel DB. Uses a **dual recency window**: reports from the fresh 2-year window are trusted first; a 5-year window is only consulted when no recent data exists — and only accepted when **not contradicted by clean reports**, so legit brands stay clean and old one-off flags never cause false positives.

3. **Exact-URL search** — `POST /search/terms?url=<full url>` returns the exact submission record (`verdict`, `av_detect`, `analysis_start_time`). Free and not rate-limited; resolves malicious URLs even when the per-domain quick-scan quota is exhausted.

4. **On-demand quick scan** — `POST /quick-scan/url` + polling until the sandbox report finishes. Any `malicious` scanner ⇒ **Malicious**; suspicious/unsure ≥ clean ⇒ **Suspicious**; otherwise clean ⇒ **Safe**. Runs in parallel with the DB lookups behind a 3s grace window so quota is never spent on already-known URLs.

5. **Structural heuristic fallback** — when all external providers stay silent (brand-new IP-hosted pages, or while HA quick-scan is down), the URL is scored locally: raw-IP host, non-standard port, opaque percent-encoding, and phishing path fragments (`ReportViewer.aspx`, `webscr`, `login.php`, `update-account`, …). High scores ⇒ suspicious/malicious with **no external API dependency**.

### Domain Intelligence (`api/src/services/domainIntel.js`)

Links flagged **malicious / suspicious** are enriched with a 6-lookup intelligence bundle (fetched **once per real domain**, cached 2h):

- **WHOIS** — registrar, age, creation/expiry (who-dat + RDAP fallback)
- **DNS records** — via `networkcalc.com`
- **IP geolocation** — country, ISP, proxy/VPN/Tor flags via `ipwho.is`
- **SSL certificate** — issuer, validity via `crt.sh` (+ `issued.live` fallback)
- **Threat-list membership** — PhishDestroy blocklist
- **Reverse IP** — co-hosted domains via `hackertarget.com`

Plus `tldts`-based parsing: registrable domain vs subdomain split (handles `co.uk`, `netlify.app`, …), **free-hosting/profile-host detection** (~30 platforms), tiny-TLD awareness, and a `resolveShortener()` export reused by `phishing.js`. The UI renders it as an expandable `DomainIntelCard` with chips (hosting platform, uncommon TLD, shortener warning, blocked page).

## Email Attachment File Protection

Every scanned email also has its attachments checked via `POST /api/security/check`.

### How an attachment is checked (`api/src/services/filecheck.js`)

1. **Gmail API fetch** — `extractAttachments()` walks the MIME multipart tree and collects every attachment (`filename`, `mimeType`, `size`, `attachmentId`). Raw bytes are retrieved via `getAttachmentBytes()`.

2. **SHA-256 hash** — the attachment content is hashed locally and looked up against Hybrid Analysis's `search/hash` endpoint (free, no quota). A `SUCCESS` state report with a clear `verdict` is used; unmapped verdicts (e.g., "no verdict") are discarded, and a null is returned to fall through to heuristics.

3. **Risky-extension heuristic** — if the file hash returns no usable DB record, the file extension is matched against curated risk lists:
   - **High risk**: `.exe`, `.dll`, `.bat`, `.ps1`, `.js`, `.vbs`, `.scr`, `.com`, `.pif`
   - **Macro-enabled documents**: `.docm`, `.xlsm`, `.pptm`, `.dotm`, `.xltm`
   - **Archives** (may contain hidden executables): `.zip`, `.rar`, `.7z`

4. **Final verdict** — if the DB reports malicious/suspicious, that verdict is used. Otherwise, high-risk or macro-enabled extensions map to `suspicious`; archive extensions map to `suspicious` with an "Archive may contain hidden files" note; anything else (`.pdf`, `.docx`, `.png`) is `safe`. Unknown and oversized files (>25MB) return `unknown`.

5. **Concurrency-limited** — checks run up to 4 in parallel; max 10 attachments per email are scanned.

### Example combined response

```json
{
  "links": [
    { "url": "https://something-for-you-check.netlify.app/?id=7202927639", "verdict": "malicious", "source": "db" },
    { "url": "https://www.google.com/", "verdict": "safe", "source": "db" }
  ],
  "attachments": [
    {
      "filename": "emotet.bin",
      "mimeType": "application/octet-stream",
      "size": 683008,
      "verdict": "malicious",
      "source": "db",
      "sha256": "106fb5f7a2b5d0e0af8609949ef3754335baa684057902a2bf928681045c436a"
    },
    {
      "filename": "invoice.pdf",
      "mimeType": "application/pdf",
      "size": 45120,
      "verdict": "safe",
      "source": "heuristic",
      "sha256": "a3f2b1c..."
    }
  ],
  "summary": {
    "verdict": "malicious",
    "count": 3,
    "highestSeverity": "malicious",
    "counts": { "malicious": 2, "safe": 1, "suspicious": 0, "unknown": 0 }
  }
}
```

### Verdicts

| Verdict | Meaning | UI |
|---------|---------|-----|
| `safe` | No threat found (DB match or clean scan) | Green chip |
| `suspicious` | Sandbox signals lean malicious | Yellow/amber chip |
| `malicious` | Confirmed malware/phishing report | Red chip + **"Click blocked"** card |
| `unknown` | Could not verify (no DB record & scan timed out) | Grey chip + "open with caution" banner |

- Gmail/Google **infrastructure URLs** (signature images on `googleusercontent.com`, `gmail.com`, etc.) are auto-skipped — they are always safe and never shown as links to verify.
- Per-URL checks run with **concurrency 4**; the parallel sources mean a known URL resolves in ~2-3s, while a brand-new URL needing a sandbox detonation can take up to ~90s.
- The email summary banner reflects the worst verdict found across both links **and** attachments (never claims "safe" while any item is unverified or malicious).

### Example response

```json
{
  "links": [
    {
      "url": "https://tinyurl.com/24q3yj6y",
      "shortener": { "service": "TinyURL", "host": "tinyurl.com", "resolvedUrl": "http://39.49.165.114:83/ReportViewer.aspx?bdl=…", "finalHost": "39.49.165.114" },
      "targetUrl": "http://39.49.165.114:83/ReportViewer.aspx?bdl=…",
      "verdict": "malicious",
      "source": "heuristic",
      "threatScore": 85,
      "label": "Malicious",
      "domainIntel": { "domain": "39.49.165.114", "hosting": { "platform": null, "isTinyTld": false }, "shortener": { … }, "whois": { … }, "geo": { … } }
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

**Backend** (`api/`): `express` `firebase-admin` `googleapis` `cors` `dotenv` `tldts` `node:crypto` (sha256)

**Threat intelligence**:
- [Hybrid Analysis (Falcon Sandbox)](https://www.hybrid-analysis.com) public API v2 — free tier. Requires an API key (create at hybrid-analysis.com → *My account → API*).
- **Domain intelligence** (all free, no auth): WHOIS (`who-dat.as93.net` + RDAP fallback), DNS (`networkcalc.com`), IP geo (`ipwho.is`), SSL (`crt.sh` + `issued.live`), threat-list (PhishDestroy `api.destroy.tools`), reverse-IP (`api.hackertarget.com`).

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
4. Click **Scan for phishing** → per-link verdicts + an expandable domain-intel card on flagged links + a summary banner appear.

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

## Google OAuth Setup

The live origins are registered on the OAuth client, so login works out of the box on Vercel + localhost. If you fork the project to a new domain, re-run this:

1. Google Cloud Console → **APIs & Services → Credentials**.
2. Open the OAuth client (`476115290827-snmunld87gppmff222ui13qnb5bvnffc.apps.googleusercontent.com`).
3. **Authorized JavaScript origins** → add your live origin (e.g. `https://sih-2026-iota-rouge.vercel.app`, keep `http://localhost:5173`).
4. **Authorized redirect URIs** → add the same origins.
5. **Save** — propagation takes 1–5 minutes.

OAuth consent screen is in "Testing" mode — only listed **test users** can sign in; request verification before public launch.

---

## Real-time Updates

The inbox polls every 30 seconds (`EmailList.jsx`), so new mail appears without a page refresh. No webhooks/Pub-Sub required.

---

## Known Limitations

- Read-only by design — no compose/send/archive/delete.
- On hard refresh the sessionStorage Gmail token is gone → app shows **"Connect Gmail"** to re-grant (Firebase session persists; one click reconnects).
- Hybrid Analysis quick scans are limited per domain (~2/hour); the free DB-layer lookups avoid this for already-analyzed URLs, and the structural heuristic catches common phishing patterns (raw-IP + port) — but an exotic brand-new URL can still report `unknown` when quota is exhausted and HA quick-scan is unavailable.
- Domain intelligence calls the free APIs (`whois`, `ipwhois`, `crt.sh`, …) which can occasionally time out; graceful degradation keeps the scan itself working.
- Attachment file protection uses DB hash lookup + extension heuristics. Malware never submitted to HA with a non-risky extension will not be flagged.
- Gmail blocks known malware attachments from being sent — password-protected zips can bypass Gmail but are flagged as "suspicious (archive)" rather than the exact malware hash.
- Free-tier Render/Vercel cold-start after ~15 min idle: the first load of each deploy after inactivity can take ~30s.

---

## Scripts

| Command | Directory | Purpose |
|---------|-----------|---------|
| `npm run dev` | `web/` | Vite dev server (5173) |
| `npm run build` | `web/` | Production build to `dist/` |
| `npm run dev` | `api/` | API dev server with reload (3001) |
| `npm start` | root / `api/` | Start API server |