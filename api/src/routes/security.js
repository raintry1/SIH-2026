import { Router } from 'express'
import { verifyFirebaseToken } from '../middleware/auth.js'
import { getEmail, getAttachmentBytes } from '../services/gmail.js'
import { checkEmailLinks } from '../services/phishing.js'
import { checkEmailAttachments } from '../services/filecheck.js'
import { buildEmailIntel } from '../services/emailIntel.js'

const router = Router()

// All security routes require a verified Firebase token
router.use(verifyFirebaseToken)

const SEVERITY_RANK = { safe: 0, unknown: 1, suspicious: 2, malicious: 3 }

// Merge link + attachment severity into one overall summary. The worst element
// decides (malicious > suspicious > unknown > safe), so the banner never
// claims "safe" while an unverified link or file is present.
function combineSummaries(linkSummary, fileSummary) {
  const pieces = ['links', 'files']
  const verdicts = [linkSummary?.verdict, fileSummary?.verdict]
  let highest = 'safe'
  for (const v of verdicts) {
    if (v && (SEVERITY_RANK[v] ?? 0) > (SEVERITY_RANK[highest] ?? 0)) highest = v
  }
  const counts = { links: {}, files: {} }
  for (const pc of pieces) {
    const which = pc === 'links' ? linkSummary : fileSummary
    for (const [k, v] of Object.entries(which?.counts || {})) {
      counts[pc][k] = v
    }
  }
  const merged = {}
  for (const [k, v] of Object.entries(counts.links)) merged[k] = (merged[k] || 0) + v
  for (const [k, v] of Object.entries(counts.files)) merged[k] = (merged[k] || 0) + v
  return {
    verdict: highest,
    highestSeverity: highest,
    count: (linkSummary?.count || 0) + (fileSummary?.count || 0),
    counts: merged,
    linkCount: linkSummary?.count || 0,
    fileCount: fileSummary?.count || 0,
  }
}

// POST /api/security/check { emailId }
// Fetches the email, extracts links AND attachments, and returns per-link +
// per-file verdicts plus a combined summary.
router.post('/check', async (req, res) => {
  try {
    const { emailId } = req.body || {}
    if (!emailId) {
      return res.status(400).json({ error: 'emailId is required' })
    }

    const accessToken = req.headers['x-gmail-token']
    const email = await getEmail(accessToken, emailId)
    const bodyHtml = email?.bodyHtml || ''
    const attachments = email?.attachments || []
    const headers = email?.headers || []

    // Links and attachments are scanned in PARALLEL - worst case time drops
    // from links+files to max(links, files).
    const [linkResult, fileResult] = await Promise.all([
      checkEmailLinks(bodyHtml),
      checkEmailAttachments(attachments, (file) =>
        getAttachmentBytes(accessToken, emailId, file.attachmentId)
      ),
    ])

    const combined = combineSummaries(linkResult.summary, fileResult.summary)
    const hasPhishing =
      combined.highestSeverity === 'malicious' ||
      combined.highestSeverity === 'suspicious'

    // Email sender OSINT: only computed for emails flagged as suspicious or
    // malicious to avoid wasting free API quota on safe emails.
    const emailIntel = hasPhishing ? await buildEmailIntel(headers).catch(() => null) : null

    res.json({
      links: linkResult.links,
      attachments: fileResult.attachments,
      summary: combined,
      ...(emailIntel ? { emailIntel } : {}),
    })
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