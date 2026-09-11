import { useState } from 'react'
import { useGoogleLogin } from '@react-oauth/google'
import { useNavigate } from 'react-router-dom'
import { Box, Typography, Alert, Paper, Button } from '@mui/material'
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
        // Same token is the Gmail OAuth token AND the Firebase credential
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
    <Box className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-50 to-indigo-100">
      <Paper className="p-10 rounded-3xl shadow-2xl w-full max-w-md" elevation={6}>
        <Box className="text-center mb-6">
          <Typography variant="h4" component="h1" fontWeight={700} className="text-gray-800">
            Gmail Client
          </Typography>
          <Typography variant="body1" className="text-gray-500 mt-2">
            Sign in with Google to view your inbox
          </Typography>
        </Box>

        {error && (
          <Alert severity="error" className="mb-4">
            {error}
          </Alert>
        )}

        <Box className="flex justify-center">
          <Button
            onClick={() => login()}
            variant="outlined"
            size="large"
            fullWidth
            sx={{
              color: '#444',
              borderColor: '#dadce0',
              bgcolor: '#fff',
              textTransform: 'none',
              py: 1.5,
              '&:hover': { bgcolor: '#f8f9fa', borderColor: '#dadce0' },
            }}
          >
            <svg width="20" height="20" viewBox="0 0 48 48" className="mr-3">
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
            Sign in with Google
          </Button>
        </Box>

        <Typography variant="caption" className="block text-center text-gray-400 mt-6">
          We only request read-only access to your Gmail inbox.
        </Typography>
      </Paper>
    </Box>
  )
}