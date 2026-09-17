import { useState, useEffect } from 'react'
import { useMediaQuery, useTheme, Box, Typography, Alert, AlertTitle, Button } from '@mui/material'
import Layout from '../components/Layout'
import EmailList from '../components/EmailList'
import EmailDetail from '../components/EmailDetail'
import GmailConnector from '../components/GmailConnector'
import { hasGmailToken, clearTokens } from '../auth/authService'
import { MarkEmailReadOutlined } from '@mui/icons-material'

export default function Dashboard({ user }) {
  const theme = useTheme()
  const isMobile = useMediaQuery(theme.breakpoints.down('md'))
  const [selectedId, setSelectedId] = useState(null)
  const [selectedEmail, setSelectedEmail] = useState(null)
  // Tick so an expired/revoked Gmail token (cleared by the API interceptor)
  // immediately flips us back to the "Connect Gmail" screen.
  const [tokenVersion, setTokenVersion] = useState(0)
  const [scopeError, setScopeError] = useState(null)

  useEffect(() => {
    const handler = () => {
      setSelectedId(null)
      setSelectedEmail(null)
      setTokenVersion((v) => v + 1)
    }
    const scopeHandler = (e) => setScopeError(e.detail || 'Gmail scope missing')
    window.addEventListener('gmail-token-deleted', handler)
    window.addEventListener('gmail-scope-missing', scopeHandler)
    return () => {
      window.removeEventListener('gmail-token-deleted', handler)
      window.removeEventListener('gmail-scope-missing', scopeHandler)
    }
  }, [])

  const handleSelect = (id, email) => {
    setSelectedId(id)
    setSelectedEmail(email)
  }

  const handleBack = () => setSelectedId(null)

  if (scopeError) {
    return (
      <Layout user={user}>
        <Box className="p-6 max-w-xl mx-auto mt-10">
          <Alert severity="warning" sx={{ borderRadius: 3 }}>
            <AlertTitle>Gmail scope missing</AlertTitle>
            {scopeError}
          </Alert>
          <Button
            variant="outlined"
            sx={{ mt: 2 }}
            onClick={() => {
              clearTokens()
              setScopeError(null)
              window.dispatchEvent(new CustomEvent('gmail-token-deleted'))
            }}
          >
            Re-connect Gmail
          </Button>
        </Box>
      </Layout>
    )
  }

  if (!hasGmailToken()) {
    return (
      <Layout user={user}>
        <GmailConnector onConnected={() => window.location.reload()} />
      </Layout>
    )
  }

  return (
    <Layout user={user}>
      <Box
        className="flex app-height"
        sx={{ bgcolor: 'rgba(13, 18, 34, 0.4)' }}
      >
        {(!isMobile || !selectedId) && (
          <Box className="w-full md:w-[380px] lg:w-1/3 border-r flex-shrink-0"
            sx={{ borderColor: 'rgba(148,163,184,0.14)' }}
          >
            <EmailList selectedId={selectedId} onSelect={(id, e) => handleSelect(id, e)} />
          </Box>
        )}

        {selectedId ? (
          <Box className="flex-1 min-w-0">
            <EmailDetail emailId={selectedId} email={selectedEmail} onBack={isMobile ? handleBack : undefined} />
          </Box>
        ) : (
          !isMobile && (
            <Box className="flex-1 hidden md:flex items-center justify-center">
              <Box className="text-center">
                <Box
                  className="mx-auto mb-5 flex items-center justify-center rounded-2xl w-20 h-20"
                  sx={{
                    background: 'rgba(255,255,255,0.06)',
                    border: '1px solid rgba(148,163,184,0.2)',
                  }}
                >
                  <MarkEmailReadOutlined sx={{ fontSize: 40, color: '#64748b' }} />
                </Box>
                <Typography variant="h6" className="text-slate-300 font-semibold mb-1">
                  Select an email to read it
                </Typography>
                <Typography variant="body2" className="text-slate-500">
                  Links and attachments are scanned automatically for threats.
                </Typography>
              </Box>
            </Box>
          )
        )}
      </Box>
    </Layout>
  )
}