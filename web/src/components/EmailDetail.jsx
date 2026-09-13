import { useState, useEffect } from 'react'
import {
  Box,
  Typography,
  Avatar,
  CircularProgress,
  Alert,
  AlertTitle,
  Divider,
  Chip,
  Stack,
  Link,
} from '@mui/material'
import {
  ShieldOutlined,
  CheckCircleOutline,
  WarningAmberOutlined,
  GppMaybeOutlined,
  ErrorOutline,
  HelpOutline,
} from '@mui/icons-material'
import DOMPurify from 'dompurify'
import { fetchEmailDetail, checkEmailLinks } from '../api/gmailApi'
import { formatFullDate } from '../utils/format'

const verdictMeta = {
  safe: { label: 'Safe', color: 'success', icon: CheckCircleOutline },
  suspicious: { label: 'Suspicious', color: 'warning', icon: WarningAmberOutlined },
  malicious: { label: 'Phishing / Malicious', color: 'error', icon: ErrorOutline },
  unknown: { label: 'Unknown', color: 'default', icon: HelpOutline },
}

const summaryMeta = {
  safe: { title: 'No phishing detected', severity: 'success', icon: CheckCircleOutline },
  suspicious: { title: 'Suspicious link detected', severity: 'warning', icon: WarningAmberOutlined },
  malicious: { title: 'Phishing risk detected!', severity: 'error', icon: GppMaybeOutlined },
  unknown: { title: 'Could not verify links', severity: 'info', icon: HelpOutline },
}

function bannerFor(summary) {
  if (!summary || summary.count === 0) {
    return {
      severity: 'success',
      title: 'No links in this email',
      icon: ShieldOutlined,
      text: 'No URLs were found to check.',
    }
  }
  const worst = summary.highestSeverity || summary.verdict || 'unknown'
  if (worst === 'malicious') {
    return {
      severity: 'error',
      title: 'Phishing risk detected!',
      icon: GppMaybeOutlined,
      text: `Found ${summary.counts?.malicious || 0} malicious link(s) in this email. Do not click them.`,
    }
  }
  if (worst === 'suspicious') {
    return {
      severity: 'warning',
      title: 'Suspicious link detected',
      icon: WarningAmberOutlined,
      text: `This email contains ${summary.counts?.suspicious || 0} suspicious link(s). Be careful before opening.`,
    }
  }
  if (worst === 'unknown') {
    return {
      severity: 'info',
      title: 'Could not verify links',
      icon: HelpOutline,
      text: 'The link check could not finish. Open links with caution.',
    }
  }
  return {
    severity: 'success',
    title: 'No phishing detected',
    icon: CheckCircleOutline,
    text: `Checked ${summary.count} link(s) - all appear safe.`,
  }
}

function VerdictChip({ verdict, threatScore, source }) {
  const meta = verdictMeta[verdict] || verdictMeta.unknown
  const Icon = meta.icon
  let label = meta.label
  if (threatScore != null && Number.isFinite(threatScore) && threatScore > 0) {
    label += ` (${threatScore})`
  }
  if (source) {
    label += ` · ${source === 'db' ? 'DB' : source === 'quick-scan' ? 'Scan' : source}`
  }
  return <Chip size="small" color={meta.color} icon={<Icon />} label={label} variant="outlined" />
}

export default function EmailDetail({ emailId, email }) {
  const [detail, setDetail] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [security, setSecurity] = useState(null)
  const [securityLoading, setSecurityLoading] = useState(false)
  const [securityError, setSecurityError] = useState(null)

  useEffect(() => {
    let cancelled = false
    if (!emailId) {
      setDetail(null)
      setSecurity(null)
      setSecurityError(null)
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

  useEffect(() => {
    let cancelled = false
    if (!emailId) {
      setSecurity(null)
      setSecurityError(null)
      return
    }
    const check = async () => {
      setSecurityLoading(true)
      setSecurityError(null)
      try {
        const data = await checkEmailLinks(emailId)
        if (!cancelled) setSecurity(data)
      } catch (err) {
        if (!cancelled) setSecurityError(err?.response?.data?.error || err.message)
      } finally {
        if (!cancelled) setSecurityLoading(false)
      }
    }
    check()
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
  const banner = securityLoading
    ? { severity: 'info', title: 'Checking links...', icon: ShieldOutlined, text: 'Analyzing URLs in this email for phishing.' }
    : bannerFor(security?.summary)
  const BannerIcon = banner.icon

  return (
    <Box className="h-full overflow-y-auto p-6">
      <Typography variant="h6" fontWeight={600} className="mb-2">
        {email?.subject || detail?.subject || '(no subject)'}
      </Typography>

      {securityLoading || security ? (
        <Alert
          severity={banner.severity}
          className="mb-3"
          icon={<BannerIcon fontSize="inherit" />}
        >
          <AlertTitle>{banner.title}</AlertTitle>
          {banner.text}
          {securityLoading && (
            <Box className="mt-2">
              <Typography variant="caption" className="text-gray-500">
                Checking up to 20 links...
              </Typography>
              <div className="h-1 w-full bg-gray-200 overflow-hidden rounded">
                <div className="h-full animate-pulse bg-blue-500" style={{ width: '60%' }} />
              </div>
            </Box>
          )}
        </Alert>
      ) : securityError ? (
        <Alert severity="warning" className="mb-3">
          <AlertTitle>Link check failed</AlertTitle>
          Could not check links: {securityError}
        </Alert>
      ) : null}

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

      {!securityLoading && security?.links?.length > 0 && (
        <Box className="mb-4 p-3 bg-gray-50 rounded-lg border border-gray-200">
          <Typography variant="subtitle2" fontWeight={600} className="mb-2 flex items-center gap-1">
            <ShieldOutlined fontSize="small" className="text-gray-500" />
            Links in this email ({security.links.length})
          </Typography>
          <Stack spacing={1}>
            {security.links.map((l, i) => {
              const blocked = l.verdict === 'malicious' || l.verdict === 'suspicious'
              let host = l.url
              try {
                host = new URL(l.url).hostname
              } catch {
                /* keep raw */
              }
              return (
                <Box
                  key={i}
                  className={`flex items-start gap-2 p-2 rounded-md border ${blocked ? 'bg-red-50 border-red-200' : 'border-gray-100'}`}
                >
                  <VerdictChip verdict={l.verdict} threatScore={l.threatScore} source={l.source} />
                  <Box className="min-w-0">
                    <Typography variant="body2" fontWeight={600} className="text-gray-800">
                      {host}
                    </Typography>
                    <Link
                      href={l.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-sm break-all text-blue-600"
                      onClick={(e) => {
                        if (blocked) e.preventDefault()
                      }}
                    >
                      {l.url}
                    </Link>
                    {blocked && (
                      <Typography variant="caption" className="text-red-600">
                        Click blocked - {l.verdict === 'malicious' ? 'phishing link' : 'proceed with caution'}
                      </Typography>
                    )}
                  </Box>
                </Box>
              )
            })}
          </Stack>
        </Box>
      )}

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