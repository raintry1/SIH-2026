import { useState } from 'react'
import { useMediaQuery, useTheme, IconButton, Box } from '@mui/material'
import Layout from '../components/Layout'
import EmailList from '../components/EmailList'
import EmailDetail from '../components/EmailDetail'
import GmailConnector from '../components/GmailConnector'
import { hasGmailToken } from '../auth/authService'
import { ArrowBack } from '@mui/icons-material'

export default function Dashboard({ user }) {
  const theme = useTheme()
  const isMobile = useMediaQuery(theme.breakpoints.down('md'))
  const [selectedId, setSelectedId] = useState(null)
  const [selectedEmail, setSelectedEmail] = useState(null)

  const handleSelect = (id, email) => {
    setSelectedId(id)
    setSelectedEmail(email)
  }

  // On a hard refresh, the sessionStorage Gmail token is gone even though
  // the user is still Firebase-authenticated. Show a "Connect Gmail" prompt.
  if (!hasGmailToken()) {
    return (
      <Layout user={user}>
        <GmailConnector
          onConnected={() => window.location.reload()}
        />
      </Layout>
    )
  }

  return (
    <Layout user={user}>
      <Box className="flex h-[calc(100vh-64px)] bg-white">
        {/* Email list */}
        {(!isMobile || !selectedId) && (
          <Box className="w-full md:w-96 lg:w-1/3 border-r flex-shrink-0">
            <EmailList selectedId={selectedId} onSelect={(id, e) => handleSelect(id, e)} />
          </Box>
        )}

        {/* Detail */}
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
              <Box className="text-center text-gray-400">
                <Box className="text-6xl mb-4">📬</Box>
                <Box className="text-lg">Select an email to read it</Box>
              </Box>
            </Box>
          )
        )}
      </Box>
    </Layout>
  )
}