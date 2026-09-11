import axios from 'axios'
import { getFirebaseToken, getGmailToken } from '../auth/authService'

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

export default api