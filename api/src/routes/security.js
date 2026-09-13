import { Router } from 'express'
import { verifyFirebaseToken } from '../middleware/auth.js'
import { getEmail } from '../services/gmail.js'
import { checkEmailLinks } from '../services/phishing.js'

const router = Router()

// All security routes require a verified Firebase token
router.use(verifyFirebaseToken)

// POST /api/security/check { emailId }
// Fetches the email, extracts links, and returns per-link + summary verdicts.
router.post('/check', async (req, res) => {
  try {
    const { emailId } = req.body || {}
    if (!emailId) {
      return res.status(400).json({ error: 'emailId is required' })
    }

    const accessToken = req.headers['x-gmail-token']
    const email = await getEmail(accessToken, emailId)
    const bodyHtml = email?.bodyHtml || ''
    const result = await checkEmailLinks(bodyHtml)
    res.json(result)
  } catch (err) {
    console.error('security check error:', err.message)
    const status = err.status || (err.response?.status) || 500
    if (status === 401 || status === 403) {
      return res.status(401).json({ error: 'Gmail access denied. Please sign in again.' })
    }
    res.status(status).json({ error: err.message || 'Failed to check security' })
  }
})

export default router