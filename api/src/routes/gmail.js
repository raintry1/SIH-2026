import { Router } from 'express'
import { verifyFirebaseToken } from '../middleware/auth.js'
import { listEmails, getEmail } from '../services/gmail.js'

const router = Router()

// All Gmail routes require a verified Firebase token
router.use(verifyFirebaseToken)

// GET /api/emails?pageToken=...&maxResults=...
router.get('/emails', async (req, res) => {
  try {
    const accessToken = req.headers['x-gmail-token']
    const pageToken = req.query.pageToken
    const maxResults = Math.min(parseInt(req.query.maxResults) || 50, 100)
    const result = await listEmails(accessToken, { pageToken, maxResults })
    res.json(result)
  } catch (err) {
    console.error('listEmails error:', err.message)
    const status = err.status || (err.response?.status) || 500
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
    const email = await getEmail(accessToken, req.params.id)
    res.json(email)
  } catch (err) {
    console.error('getEmail error:', err.message)
    const status = err.status || (err.response?.status) || 500
    if (status === 401 || status === 403) {
      return res.status(401).json({ error: 'Gmail access denied. Please sign in again.' })
    }
    res.status(status).json({ error: err.message || 'Failed to fetch email' })
  }
})

export default router