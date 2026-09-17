import axios from 'axios'
import { getFirebaseToken, getGmailToken, clearTokens } from '../auth/authService'

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:3001'

const api = axios.create({
  baseURL: API_URL,
})

// Attach Firebase ID token (authorization) + Gmail access token (for Gmail API) on every request
api.interceptors.request.use(async (config) => {
  const firebaseToken = await getFirebaseToken()
  const gmailToken = getGmailToken()
  if (firebaseToken) config.headers.Authorization = `Bearer ${firebaseToken}`
  if (gmailToken) config.headers['x-gmail-token'] = gmailToken
  return config
})

// When the backend rejects the Gmail token (expired, revoked, or scope missing),
// drop it so the UI falls back to the "Connect Gmail" screen instead of looping.
api.interceptors.response.use(
  (res) => res,
  (err) => {
    const status = err?.response?.status
    const data = err?.response?.data || {}
    const error = typeof data === 'string' ? data : data.error || ''
    const gmailDenied = error.includes('Gmail access denied') || error.includes('Missing Gmail access token')
    // Missing restricted scope: keep the token but let the UI show the fix hint.
    if (status === 403 && data.scopeMissing && getGmailToken()) {
      window.dispatchEvent(new CustomEvent('gmail-scope-missing', { detail: error }))
      return Promise.reject(err)
    }
    if ((status === 401 || status === 403) && gmailDenied && getGmailToken()) {
      clearTokens()
      if (typeof window !== 'undefined') window.dispatchEvent(new CustomEvent('gmail-token-deleted'))
    }
    return Promise.reject(err)
  }
)

export async function fetchEmails(pageToken) {
  const params = {}
  if (pageToken) params.pageToken = pageToken
  const { data } = await api.get('/api/emails', { params })
  return data
}

export async function fetchEmailDetail(id) {
  const { data } = await api.get(`/api/emails/${id}`)
  return data
}

export async function checkEmailLinks(emailId) {
  const { data } = await api.post('/api/security/check', { emailId })
  return data
}

export default api