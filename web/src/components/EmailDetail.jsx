import { useState, useEffect } from 'react'
import {
  Box,
  Typography,
  Avatar,
  CircularProgress,
  Alert,
  Divider,
  Chip,
} from '@mui/material'
import DOMPurify from 'dompurify'
import { fetchEmailDetail } from '../api/gmailApi'
import { formatFullDate } from '../utils/format'

export default function EmailDetail({ emailId, email }) {
  const [detail, setDetail] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  useEffect(() => {
    let cancelled = false
    if (!emailId) {
      setDetail(null)
      return
    }
    const load = async () => {
      setLoading(true)
      setError(null)
      try {
        const data = await fetchEmailDetail(emailId)
        if (!cancelled) setDetail(data)
      } catch (err) {
        if (!cancelled) setError(err?.response?.data?.error || err.message)
      } finally {
        if (!cancelled) setLoading(false)
      }
    }
    load()
    return () => {
      cancelled = true
    }
  }, [emailId])

  if (!emailId) {
    return (
      <Box className="h-full flex items-center justify-center">
        <Typography variant="body1" className="text-gray-400">
          Select an email to read it
        </Typography>
      </Box>
    )
  }

  if (loading) {
    return (
      <Box className="h-full flex items-center justify-center">
        <CircularProgress />
      </Box>
    )
  }

  if (error) {
    return (
      <Box className="p-4">
        <Alert severity="error">{error}</Alert>
      </Box>
    )
  }

  const sender = detail?.from || email?.sender?.name || email?.sender?.email || 'Unknown'
  const to = detail?.to || ''

  return (
    <Box className="h-full overflow-y-auto p-6">
      <Typography variant="h6" fontWeight={600} className="mb-2">
        {email?.subject || detail?.subject || '(no subject)'}
      </Typography>

      <Box className="flex items-center gap-3 mb-1">
        <Avatar className="mr-1" sx={{ bgcolor: 'primary.main' }}>
          {(sender[0] || '?').toUpperCase()}
        </Avatar>
        <Box>
          <Typography variant="subtitle2">{sender}</Typography>
          {to && (
            <Typography variant="caption" className="text-gray-500">
              to {to}
            </Typography>
          )}
        </Box>
        <Box className="ml-auto">
          {detail?.date && (
            <Chip
              size="small"
              variant="outlined"
              label={formatFullDate(detail.date)}
              className="text-gray-500"
            />
          )}
        </Box>
      </Box>

      <Divider className="my-4" />

      <Box className="mt-4">
        {detail?.bodyHtml ? (
          <div
            className="email-body prose prose-sm max-w-none"
            dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(detail.bodyHtml) }}
          />
        ) : (
          <Typography
            variant="body1"
            className="whitespace-pre-wrap break-words text-gray-800"
          >
            {detail?.bodyText || '(No readable body content)'}
          </Typography>
        )}
      </Box>
    </Box>
  )
}