import express from 'express'
import cors from 'cors'
import dotenv from 'dotenv'
dotenv.config()

import admin from './firebase.js'
import gmailRouter from './routes/gmail.js'
import securityRouter from './routes/security.js'

const app = express()
const PORT = process.env.PORT || 3001

// CORS
const allowedOrigins = (process.env.CORS_ORIGINS || 'http://localhost:5173')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean)

app.use(
  cors({
    origin(origin, callback) {
      // Allow non-browser clients (curl, health checks) with no origin
      if (!origin) return callback(null, true)
      if (allowedOrigins.includes(origin)) return callback(null, true)
      return callback(new Error(`CORS blocked origin: ${origin}`))
    },
    credentials: true,
  })
)

app.use(express.json())

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', time: new Date().toISOString() })
})

// Gmail API routes
app.use('/api', gmailRouter)

// Security / phishing check routes
app.use('/api/security', securityRouter)

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Not found' })
})

// Error handler
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err.message)
  res.status(500).json({ error: err.message || 'Internal server error' })
})

app.listen(PORT, () => {
  console.log(`API server running on port ${PORT}`)
  console.log(`Firebase app: ${admin.app().options.projectId}`)
})