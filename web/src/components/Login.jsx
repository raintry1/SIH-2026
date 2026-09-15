import { useState } from 'react'
import { useGoogleLogin } from '@react-oauth/google'
import { useNavigate } from 'react-router-dom'
import { Box, Typography, Alert, Button } from '@mui/material'
import { ShieldOutlined } from '@mui/icons-material'
import { signInWithGoogleAccessToken, storeGmailToken } from '../auth/authService'

const GMAIL_SCOPES =
  'email profile openid https://www.googleapis.com/auth/gmail.readonly'

export default function Login() {
  const navigate = useNavigate()
  const [error, setError] = useState(null)

  const login = useGoogleLogin({
    scope: GMAIL_SCOPES,
    onSuccess: async (tokenResponse) => {
      try {
        setError(null)
        if (!tokenResponse.access_token) {
          throw new Error('No access token returned by Google')
        }
        storeGmailToken(tokenResponse.access_token)
        await signInWithGoogleAccessToken(tokenResponse.access_token)
        navigate('/dashboard')
      } catch (err) {
        console.error('Login failed:', err)
        setError(`Sign-in failed: ${err.message}`)
      }
    },
    onError: (err) => {
      console.error('Google sign-in error:', err)
      setError(
        'Google sign-in was cancelled or failed. Make sure the gmail.readonly scope and your email as test user are added in the OAuth consent screen.'
      )
    },
  })

  return (
    <Box className="min-h-screen aurora-bg relative overflow-hidden flex items-center justify-center px-4 py-8">
      {/* Floating glow accents */}
      <Box
        className="pointer-events-none absolute rounded-full hidden sm:block"
        sx={{
          width: 320,
          height: 320,
          top: '-80px',
          left: '10%',
          background: 'radial-gradient(circle, rgba(99,102,241,0.35), transparent 70%)',
          filter: 'blur(40px)',
        }}
      />
      <Box
        className="pointer-events-none absolute rounded-full hidden sm:block"
        sx={{
          width: 380,
          height: 380,
          bottom: '-100px',
          right: '8%',
          background: 'radial-gradient(circle, rgba(192,132,252,0.3), transparent 70%)',
          filter: 'blur(50px)',
        }}
      />

      <Box className="relative w-full max-w-md">
        <Box className="aurora-card rounded-3xl p-6 sm:p-8 shadow-2xl text-center w-full">
          <Box
            className="mx-auto mb-5 flex items-center justify-center rounded-2xl"
            sx={{
              width: 60,
              height: 60,
              background: 'linear-gradient(135deg, #6366f1, #a855f7)',
              boxShadow: '0 8px 30px rgba(129,140,248,0.55)',
            }}
          >
            <ShieldOutlined sx={{ color: '#fff', fontSize: 32 }} />
          </Box>

          <Typography variant="h4" className="font-extrabold mb-2">
            <span className="gradient-text">SecureMail</span>
          </Typography>

          <Typography variant="h6" className="font-bold mb-1.5" sx={{ color: '#f1f5f9' }}>
            Secure your inbox
          </Typography>
          <Typography variant="body2" className="text-slate-400 mb-6">
            Sign in with Google and scan every email's links and attachments for
            phishing and malware — in a single click.
          </Typography>

          {error && (
            <Alert severity="error" className="mb-5" sx={{ borderRadius: 3, textAlign: 'left', fontSize: '0.85rem' }}>
              {error}
            </Alert>
          )}

          <Button
            onClick={() => login()}
            variant="outlined"
            size="large"
            fullWidth
            sx={{
              color: '#e2e8f0',
              borderColor: 'rgba(148,163,184,0.4)',
              bgcolor: 'rgba(255,255,255,0.06)',
              py: 1.6,
              borderRadius: 2.5,
              '&:hover': {
                bgcolor: 'rgba(255,255,255,0.12)',
                borderColor: 'rgba(129,140,248,0.7)',
              },
            }}
          >
            <svg width="20" height="20" viewBox="0 0 48 48" className="mr-3 shrink-0">
              <path
                fill="#FFC107"
                d="M43.6 20.14H42V20H24v8h11.3c-1.63 4.73-6.11 8-11.3 8-6.63 0-12-5.37-12-12s5.37-12 12-12c3.06 0 5.83 1.16 7.94 3.02l5.66-5.66A19.9 19.9 0 0 0 24 4C12.95 4 4 12.95 4 24s8.95 20 20 20 20-8.95 20-20c0-1.32-.13-2.62-.4-3.86z"
              />
              <path
                fill="#FF3D00"
                d="M6.31 14.69l6.58 4.83C14.4 15.45 18.83 12 24 12c3.06 0 5.83 1.16 7.94 3.02l5.66-5.66A19.9 19.9 0 0 0 24 4C16.32 4 9.66 8.34 6.31 14.69z"
              />
              <path
                fill="#4CAF50"
                d="M24 44c5.16 0 9.86-1.97 13.41-5.16l-6.19-5.24A11.94 11.94 0 0 1 24 36c-5.2 0-9.6-3.28-11.3-8L6.1 32.87C9.43 39.4 16.17 44 24 44z"
              />
              <path
                fill="#1976D2"
                d="M43.6 20.14H42V20H24v8h11.3c-.78 2.27-2.21 4.22-4.05 5.6l6.19 5.24C36.9 42.85 44 38.5 44 24c0-1.32-.13-2.62-.4-3.86z"
              />
            </svg>
            Continue with Google
          </Button>
        </Box>
      </Box>
    </Box>
  )
}