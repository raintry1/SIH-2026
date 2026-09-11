import admin from '../firebase.js'

// Verifies the Firebase ID token from the Authorization header.
// On success, attaches the verified uid to req.user.
export async function verifyFirebaseToken(req, res, next) {
  const authHeader = req.headers.authorization || ''
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null

  if (!token) {
    return res.status(401).json({ error: 'Missing authorization token' })
  }

  try {
    const decodedToken = await admin.auth().verifyIdToken(token)
    req.user = { uid: decodedToken.uid, email: decodedToken.email }
    next()
  } catch (err) {
    console.error('Token verification failed:', err.message)
    return res.status(401).json({ error: 'Invalid or expired token' })
  }
}