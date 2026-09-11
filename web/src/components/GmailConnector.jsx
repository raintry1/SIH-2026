import { useState } from 'react'
import { useGoogleLogin } from '@react-oauth/google'
import { Box, Typography, Button, Paper, Alert } from '@mui/material'
import { storeGmailToken } from '../auth/authService'

const GMAIL_SCOPES =
  'email profile openid https://www.googleapis.com/auth/gmail.readonly'

export default function GmailConnector({ onConnected }) {
  const [error, setError] = useState(null)

  const login = useGoogleLogin({
    scope: GMAIL_SCOPES,
    onSuccess: async (tokenResponse) => {
      if (!tokenResponse.access_token) {
        setError('Google did not return an access token.')
        return
      }
      storeGmailToken(tokenResponse.access_token)
      onConnected()
    },
    onError: (err) => {
      console.error('Gmail connect failed:', err)
      setError(
        'Could not connect Gmail. If the consent screen blocks the gmail.readonly scope or your email is not listed as a test user, see the README.'
      )
    },
  })

  return (
    <Box className="min-h-[calc(100vh-64px)] flex items-center justify-center bg-gray-50">
      <Paper className="p-10 rounded-3xl shadow-lg w-full max-w-md" elevation={3}>
        <Box className="text-center mb-6">
          <Typography variant="h5" component="h2" fontWeight={600}>
            Connect your Gmail
          </Typography>
          <Typography variant="body2" className="text-gray-500 mt-2">
            To read your inbox securely, grant read-only Gmail access.
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
            variant="contained"
            size="large"
            sx={{ textTransform: 'none', px: 4 }}
            color="primary"
          >
            Connect Gmail
          </Button>
        </Box>

        <Typography variant="caption" className="block text-center text-gray-400 mt-6">
          We only request read-only access to your Gmail inbox.
        </Typography>
      </Paper>
    </Box>
  )
}