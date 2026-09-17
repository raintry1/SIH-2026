import { Router } from 'express'
import { google } from 'googleapis'
import { verifyFirebaseToken } from '../middleware/auth.js'
import { listEmails, getEmail } from '../services/gmail.js'

const router = Router()

// All Gmail routes require a verified Firebase token
router.use(verifyFirebaseToken)

const GMAIL_READONLY = 'https://www.googleapis.com/auth/gmail.readonly'

// Check what scopes Google actually granted for this access token. Catches the
// classic "new user allows consent but still gets denied" case: when the OAuth
// app is in Testing mode, gmail.readonly is a restricted scope only issued to
// test users, so the token exists but is missing the scope.
async function requireGmailScope(accessToken) {
  if (!accessToken) return
  try {
    const auth = new google.auth.OAuth2()
    auth.setCredentials({ access_token: accessToken })
    const info = (await auth.getTokenInfo(accessToken)).scopes || []
    if (!info.some((s) => s.includes('gmail.readonly'))) {
      const err = new Error(
        'The Gmail token is missing the gmail.readonly scope. Fix: in Google Cloud Console > OAuth consent screen, publish the app (or add this user as a test user), because gmail.readonly is a restricted scope.'
      )
      err.status = 403
      err.scopeMissing = true
      throw err
    }
  } catch (err) {
    if (err.scopeMissing) throw err
    // tokeninfo outage / network hiccup: don't block, let the Gmail call decide
  }
}

// GET /api/emails?pageToken=...&maxResults=...
router.get('/emails', async (req, res) => {
  try {
    const accessToken = req.headers['x-gmail-token']
    await requireGmailScope(accessToken)
    const pageToken = req.query.pageToken
    const maxResults = Math.min(parseInt(req.query.maxResults) || 50, 100)
    const result = await listEmails(accessToken, { pageToken, maxResults })
    res.json(result)
  } catch (err) {
    console.error('listEmails error:', err.message)
    const status = err.status || (err.response?.status) || 500
    if (err.scopeMissing) {
      return res.status(403).json({ error: err.message, scopeMissing: true })
    }
    if (status === 401 || status === 403) {
      return res.status(401).json({ error: 'Gmail access denied. Please sign in again.' })
    }
    res.status(status).json({ error: err.message || 'Failed to fetch emails' })
  }
})

// GET /api/emails/:id
router.get('/emails/:id', async (req, res) => {
  try {
    const accessToken = req.headers['x-gmail-token']
    await requireGmailScope(accessToken)
    const email = await getEmail(accessToken, req.params.id)
    res.json(email)
  } catch (err) {
    console.error('getEmail error:', err.message)
    const status = err.status || (err.response?.status) || 500
    if (err.scopeMissing) {
      return res.status(403).json({ error: err.message, scopeMissing: true })
    }
    if (status === 401 || status === 403) {
      return res.status(401).json({ error: 'Gmail access denied. Please sign in again.' })
    }
    res.status(status).json({ error: err.message || 'Failed to fetch email' })
  }
})

export default router