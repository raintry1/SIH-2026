import { getAuth, GoogleAuthProvider, signInWithCredential, onAuthStateChanged, signOut } from 'firebase/auth'
import { app } from '../config/firebase'

export const auth = getAuth(app)
export const googleProvider = new GoogleAuthProvider()
googleProvider.addScope('email')
googleProvider.addScope('profile')
googleProvider.addScope('https://www.googleapis.com/auth/gmail.readonly')

// Sign in to Firebase using the Google access token from @react-oauth/google.
// Firebase accepts a Google OAuth access token as the sign-in credential.
export async function signInWithGoogleAccessToken(accessToken) {
  const firebaseCredential = GoogleAuthProvider.credential(null, accessToken)
  const userCredential = await signInWithCredential(auth, firebaseCredential)
  return userCredential.user
}

// Keep the Gmail OAuth access token (granted by GIS) in sessionStorage
export function storeGmailToken(token) {
  sessionStorage.setItem('gmail_token', token)
}

export function getGmailToken() {
  return sessionStorage.getItem('gmail_token')
}

export function clearTokens() {
  sessionStorage.removeItem('gmail_token')
  sessionStorage.removeItem('firebase_token')
}

// Get a fresh Firebase ID token for authorizing backend calls
export async function getFirebaseToken() {
  const user = auth.currentUser
  if (!user) return null
  return user.getIdToken()
}

// Convenience listener helper
export function onAuthState(callback) {
  return onAuthStateChanged(auth, callback)
}

export function hasGmailToken() {
  return Boolean(getGmailToken())
}

export async function logout() {
  clearTokens()
  await signOut(auth)
}