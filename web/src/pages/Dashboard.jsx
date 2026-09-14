import { useState } from 'react'
import { useMediaQuery, useTheme, IconButton, Box, Typography } from '@mui/material'
import Layout from '../components/Layout'
import EmailList from '../components/EmailList'
import EmailDetail from '../components/EmailDetail'
import GmailConnector from '../components/GmailConnector'
import { hasGmailToken } from '../auth/authService'
import { ArrowBack, MarkEmailReadOutlined } from '@mui/icons-material'

export default function Dashboard({ user }) {
  const theme = useTheme()
  const isMobile = useMediaQuery(theme.breakpoints.down('md'))
  const [selectedId, setSelectedId] = useState(null)
  const [selectedEmail, setSelectedEmail] = useState(null)

  const handleSelect = (id, email) => {
    setSelectedId(id)
    setSelectedEmail(email)
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
        className="flex h-[calc(100vh-64px)]"
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
          <Box className="flex-1 min-w-0 relative">
            {isMobile && (
              <Box className="absolute top-2 left-2 z-10">
                <IconButton onClick={() => setSelectedId(null)} aria-label="back">
                  <ArrowBack />
                </IconButton>
              </Box>
            )}
            <EmailDetail emailId={selectedId} email={selectedEmail} />
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