import { useState, useEffect, useCallback, useRef } from 'react'
import {
  Box,
  List,
  Typography,
  CircularProgress,
  Alert,
  Button,
  Divider,
} from '@mui/material'
import EmailListItem from './EmailListItem'
import { fetchEmails } from '../api/gmailApi'

const POLL_INTERVAL = 30000 // 30s

export default function EmailList({ selectedId, onSelect }) {
  const [emails, setEmails] = useState([])
  const [loading, setLoading] = useState(true)
  const [loadingMore, setLoadingMore] = useState(false)
  const [error, setError] = useState(null)
  const [nextPageToken, setNextPageToken] = useState(null)
  const [hasMore, setHasMore] = useState(false)
  const [newCount, setNewCount] = useState(0)
  const firstRun = useRef(true)

  const load = useCallback(async (pageToken, append = false) => {
    try {
      const data = await fetchEmails(pageToken)
      setEmails((prev) => {
        const existing = new Map(prev.map((e) => [e.id, e]))
        ;(data.emails || []).forEach((e) => {
          if (!existing.has(e.id)) existing.set(e.id, e)
        })
        return Array.from(existing.values())
      })
      setNextPageToken(data.nextPageToken || null)
      setHasMore(Boolean(data.nextPageToken))
      if (append) setLoadingMore(false)
      else setLoading(false)
    } catch (err) {
      setError(err?.response?.data?.error || err.message)
      setLoading(false)
      setLoadingMore(false)
    }
  }, [])

  useEffect(() => {
    if (firstRun.current) {
      firstRun.current = false
      load()
    }
    const interval = setInterval(() => {
      load()
    }, POLL_INTERVAL)
    return () => clearInterval(interval)
  }, [load])

  const handleLoadMore = () => {
    setLoadingMore(true)
    load(nextPageToken, true)
  }

  if (loading) {
    return (
      <Box className="h-full flex items-center justify-center">
        <CircularProgress size={36} />
      </Box>
    )
  }

  if (error) {
    return (
      <Box className="p-4">
        <Alert severity="error" className="mb-3" sx={{ borderRadius: 3 }}>
          {error}
        </Alert>
        <Button
          variant="outlined"
          onClick={() => {
            setLoading(true)
            load()
          }}
        >
          Retry
        </Button>
      </Box>
    )
  }

  return (
    <Box className="h-full flex flex-col">
      <Box className="px-5 py-4 flex items-center justify-between bg-transparent border-b"
        sx={{ borderColor: 'rgba(148,163,184,0.14)' }}
      >
        <Box>
          <Typography variant="subtitle2" className="font-bold text-slate-200 tracking-tight">
            Inbox
          </Typography>
          <Typography variant="caption" className="text-slate-500">
            {emails.length} conversations
          </Typography>
        </Box>
      </Box>
      <List disablePadding className="overflow-y-auto flex-1">
        {emails.map((email) => (
          <EmailListItem
            key={email.id}
            email={email}
            selected={selectedId === email.id}
            onSelect={onSelect}
          />
        ))}
        {emails.length === 0 && (
          <Box className="p-6 text-center">
            <Typography variant="body1" className="text-slate-500">
              No emails found.
            </Typography>
          </Box>
        )}
      </List>
      {hasMore && (
        <Box className="p-3 text-center border-t bg-transparent"
          sx={{ borderColor: 'rgba(148,163,184,0.14)' }}
        >
          <Button onClick={handleLoadMore} disabled={loadingMore} variant="outlined" size="small">
            {loadingMore ? <CircularProgress size={20} /> : 'Load more'}
          </Button>
        </Box>
      )}
    </Box>
  )
}