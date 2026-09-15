import { useState } from 'react'
import { useGoogleLogin } from '@react-oauth/google'
import { Box, Typography, Button, Alert } from '@mui/material'
import { EmailOutlined, ShieldOutlined } from '@mui/icons-material'
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
    <Box className="app-min-height flex items-center justify-center px-4 py-8">
      <Box className="relative w-full max-w-md">
        <Box className="aurora-card rounded-3xl p-6 sm:p-8 shadow-2xl text-center">
          <Box
            className="mx-auto mb-5 flex items-center justify-center rounded-2xl"
            sx={{
              width: 64,
              height: 64,
              background: 'linear-gradient(135deg, #6366f1, #a855f7)',
              boxShadow: '0 8px 28px rgba(129,140,248,0.5)',
            }}
          >
            <EmailOutlined sx={{ color: '#fff', fontSize: 32 }} />
          </Box>

          <Typography variant="h5" component="h2" fontWeight={700} className="mb-1.5">
            Connect your Gmail
          </Typography>
          <Typography variant="body2" className="text-slate-400 mb-6">
            Grant read-only Gmail access to start scanning your inbox for
            phishing links and malware attachments.
          </Typography>

          {error && (
            <Alert severity="error" className="mb-5" sx={{ borderRadius: 3 }}>
              {error}
            </Alert>
          )}

          <Button
            onClick={() => login()}
            variant="contained"
            size="large"
            fullWidth
            startIcon={<ShieldOutlined />}
            sx={{
              py: 1.5,
              borderRadius: 2.5,
              background: 'linear-gradient(135deg, #6366f1, #a855f7)',
              boxShadow: '0 8px 24px rgba(129,140,248,0.4)',
              '&:hover': {
                background: 'linear-gradient(135deg, #6366f1, #a855f7)',
                opacity: 0.92,
              },
            }}
          >
            Connect Gmail
          </Button>

          <Typography variant="caption" className="block text-center text-slate-500 mt-6">
            We only request read-only access to your Gmail inbox.
          </Typography>
        </Box>
      </Box>
    </Box>
  )
}