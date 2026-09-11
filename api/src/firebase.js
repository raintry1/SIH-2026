import dotenv from 'dotenv'
dotenv.config()

import admin from 'firebase-admin'
import fs from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))

function loadServiceAccount() {
  // Option 1: full JSON string provided in env (Render)
  if (process.env.FIREBASE_SERVICE_ACCOUNT) {
    try {
      return JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT)
    } catch (err) {
      console.error('Invalid FIREBASE_SERVICE_ACCOUNT JSON:', err.message)
      process.exit(1)
    }
  }

  // Option 2: path to serviceAccountKey.json (local dev)
  const p = process.env.FIREBASE_SERVICE_ACCOUNT_PATH || './serviceAccountKey.json'
  const absolute = path.isAbsolute(p) ? p : path.resolve(__dirname, '..', p)
  if (fs.existsSync(absolute)) {
    return JSON.parse(fs.readFileSync(absolute, 'utf8'))
  }

  console.error(
    'No Firebase service account found. Set FIREBASE_SERVICE_ACCOUNT or place serviceAccountKey.json in api/.'
  )
  process.exit(1)
}

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert(loadServiceAccount()),
  })
}

export default admin