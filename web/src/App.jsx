import { useState, useEffect } from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import { CircularProgress, Box } from '@mui/material'
import { GoogleOAuthProvider } from '@react-oauth/google'
import Login from './components/Login'
import InstallPopup from './components/InstallPopup'
import Dashboard from './pages/Dashboard'
import { onAuthState } from './auth/authService'

function RequireAuth({ children }) {
  return children
}

export default function App() {
  const [user, setUser] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const unsubscribe = onAuthState((firebaseUser) => {
      setUser(firebaseUser)
      setLoading(false)
    })
    return unsubscribe
  }, [])

  if (loading) {
    return (
      <Box className="min-h-screen aurora-bg flex items-center justify-center">
        <CircularProgress />
      </Box>
    )
  }

  return (
    <GoogleOAuthProvider clientId={import.meta.env.VITE_GMAIL_CLIENT_ID}>
      <InstallPopup />
      <Routes>
        <Route
          path="/"
          element={user ? <Navigate to="/dashboard" replace /> : <Login />}
        />
        <Route
          path="/dashboard"
          element={
            <RequireAuth>
              {user ? <Dashboard user={user} /> : <Navigate to="/" replace />}
            </RequireAuth>
          }
        />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </GoogleOAuthProvider>
  )
}