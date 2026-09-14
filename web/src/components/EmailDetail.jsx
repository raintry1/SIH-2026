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
  HelpOutline,
  AttachFileOutlined,
  LinkOutlined,
  InsertDriveFileOutlined,
  BlockOutlined,
} from '@mui/icons-material'
import DOMPurify from 'dompurify'
import { fetchEmailDetail, checkEmailLinks } from '../api/gmailApi'
import { formatFullDate } from '../utils/format'

const verdictChipStyle = {
  safe: { label: 'Safe', color: '#34d399', bg: 'rgba(16,185,129,0.15)', border: 'rgba(16,185,129,0.4)' },
  suspicious: { label: 'Suspicious', color: '#fbbf24', bg: 'rgba(245,158,11,0.12)', border: 'rgba(245,158,11,0.45)' },
  malicious: { label: 'Malicious', color: '#fb7185', bg: 'rgba(244,63,94,0.15)', border: 'rgba(244,63,94,0.5)' },
  unknown: { label: 'Unknown', color: '#94a3b8', bg: 'rgba(148,163,184,0.1)', border: 'rgba(148,163,184,0.35)' },
}

const summaryMeta = {
  safe: { title: 'No threats detected', severity: 'safe', icon: CheckCircleOutline },
  suspicious: { title: 'Suspicious content detected', severity: 'suspicious', icon: WarningAmberOutlined },
  malicious: { title: 'Security risk detected!', severity: 'malicious', icon: GppMaybeOutlined },
  unknown: { title: 'Could not verify content', severity: 'info', icon: HelpOutline },
}

function bannerFor(summary) {
  if (!summary || summary.count === 0) {
    return {
      severity: 'safe',
      title: 'Nothing to check',
      icon: ShieldOutlined,
      text: 'This email contains no links or attachments.',
    }
  }
  const worst = summary.highestSeverity || summary.verdict || 'unknown'
  const parts = []
  if (summary.linkCount) parts.push(`${summary.linkCount} link(s)`)
  if (summary.fileCount) parts.push(`${summary.fileCount} attachment(s)`)
  const scope = parts.join(' and ') || `${summary.count} item(s)`
  if (worst === 'malicious') {
    return {
      severity: 'malicious',
      title: 'Security risk detected!',
      icon: GppMaybeOutlined,
      text: `Found ${summary.counts?.malicious || 0} malicious link/attachment(s). Do not click or open them — treat this email as a threat.`,
    }
  }
  if (worst === 'suspicious') {
    return {
      severity: 'suspicious',
      title: 'Suspicious content detected',
      icon: WarningAmberOutlined,
      text: `Contains ${summary.counts?.suspicious || 0} suspicious link/attachment(s). Take caution before opening anything.`,
    }
  }
  if (worst === 'unknown') {
    return {
      severity: 'unknown',
      title: 'Could not verify content',
      icon: HelpOutline,
      text: `Checked ${scope} — some items could not be verified. Open with caution.`,
    }
  }
  return {
    severity: 'safe',
    title: 'No threats detected',
    icon: CheckCircleOutline,
    text: `Checked ${scope} — everything appears safe.`,
  }
}

function VerdictChip({ verdict, threatScore, source }) {
  const style = verdictChipStyle[verdict] || verdictChipStyle.unknown
  let label = style.label
  if (threatScore != null && Number.isFinite(threatScore) && threatScore > 0) {
    label += ` (${threatScore})`
  }
  if (source) {
    const sourceLabel = source === 'db' ? 'DB' : source === 'quick-scan' ? 'Scan' : source === 'heuristic' ? 'Heuristic' : source
    label += ` · ${sourceLabel}`
  }
  return (
    <Chip
      size="small"
      label={label}
      sx={{
        flexShrink: 0,
        color: style.color,
        bgcolor: style.bg,
        border: `1px solid ${style.border}`,
        fontWeight: 700,
        fontSize: '0.72rem',
        '& .MuiChip-label': { px: 1.2 },
      }}
    />
  )
}

function SecurityBanner({ banner, loading }) {
  const Icon = banner.icon
  const gradientClass =
    banner.severity === 'malicious'
      ? 'gradient-malicious'
      : banner.severity === 'suspicious'
        ? 'gradient-suspicious'
        : banner.severity === 'safe'
          ? 'gradient-safe'
          : 'gradient-info'
  const iconColor =
    banner.severity === 'malicious'
      ? '#fb7185'
      : banner.severity === 'suspicious'
        ? '#fbbf24'
        : banner.severity === 'safe'
          ? '#34d399'
          : '#38bdf8'

  return (
    <Box className={`rounded-2xl p-4 mb-4 ${gradientClass}`}>
      <Box className="flex items-start gap-3">
        <Box
          className="flex items-center justify-center shrink-0 rounded-xl"
          sx={{ width: 40, height: 40, bgcolor: `${iconColor}22`, border: `1px solid ${iconColor}55` }}
        >
          <Icon sx={{ color: iconColor }} />
        </Box>
        <Box className="min-w-0 flex-1">
          <Typography variant="subtitle1" fontWeight={700} sx={{ color: '#f1f5f9' }}>
            {banner.title}
          </Typography>
          <Typography variant="body2" className="text-slate-300" sx={{ color: '#cbd5e1' }}>
            {banner.text}
          </Typography>
          {loading && (
            <Box className="mt-2.5">
              <Typography variant="caption" className="text-slate-400">
                Scanning links and attachments...
              </Typography>
              <Box className="h-1.5 w-full bg-slate-700/40 overflow-hidden rounded-full mt-1.5">
                <Box className="h-full shimmer-bar w-full" />
              </Box>
            </Box>
          )}
        </Box>
      </Box>
    </Box>
  )
}

function ThreatCard({ icon: Icon, title, count, items, renderItem }) {
  if (count === 0) return null
  return (
    <Box
      className="rounded-2xl p-3.5 mb-4"
      sx={{ bgcolor: 'rgba(255,255,255,0.035)', border: '1px solid rgba(148,163,184,0.16)' }}
    >
      <Typography variant="subtitle2" fontWeight={700} className="mb-2.5 flex items-center gap-1.5" sx={{ color: '#e2e8f0' }}>
        <Icon fontSize="small" sx={{ color: '#818cf8' }} />
        {title}
        <Chip
          size="small"
          label={count}
          sx={{ ml: 1, height: 20, fontSize: '0.7rem', fontWeight: 700, bgcolor: 'rgba(99,102,241,0.2)', color: '#a5b4fc' }}
        />
      </Typography>
      <Stack spacing={1}>
        {items.map((item, i) => (
          <Box
            key={i}
            className="flex items-start gap-2.5 p-2.5 rounded-xl"
            sx={{
              bgcolor: item.verdict === 'malicious' ? 'rgba(244,63,94,0.10)' : item.verdict === 'suspicious' ? 'rgba(245,158,11,0.08)' : 'rgba(255,255,255,0.02)',
              border: `1px solid ${item.verdict === 'malicious' ? 'rgba(244,63,94,0.3)' : item.verdict === 'suspicious' ? 'rgba(245,158,11,0.3)' : 'rgba(148,163,184,0.15)'}`,
            }}
          >
            {renderItem(item)}
          </Box>
        ))}
      </Stack>
    </Box>
  )
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
        <Typography variant="body1" className="text-slate-500">
          Select an email to read it
        </Typography>
      </Box>
    )
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
        <Alert severity="error" sx={{ borderRadius: 3 }}>
          {error}
        </Alert>
      </Box>
    )
  }

  const sender = detail?.from || email?.sender?.name || email?.sender?.email || 'Unknown'
  const to = detail?.to || ''
  const banner = securityLoading
    ? {
        severity: 'info',
        title: 'Scanning this email...',
        icon: ShieldOutlined,
        text: 'Checking every link and attachment against Hybrid Analysis threat intelligence.',
      }
    : bannerFor(security?.summary)

  return (
    <Box className="h-full overflow-y-auto p-6 md:p-8">
      <Typography variant="h6" fontWeight={700} className="mb-4 tracking-tight" sx={{ color: '#f1f5f9' }}>
        {email?.subject || detail?.subject || '(no subject)'}
      </Typography>

      {(securityLoading || security) && <SecurityBanner banner={banner} loading={securityLoading} />}

      {!securityLoading && securityError && (
        <Alert severity="warning" className="mb-4" sx={{ borderRadius: 3 }}>
          <AlertTitle>Security check failed</AlertTitle>
          Could not check this email: {securityError}
        </Alert>
      )}

      <Box className="flex items-center gap-3 mb-1">
        <Avatar className="shrink-0" sx={{ bgcolor: 'primary.main', fontWeight: 700 }}>
          {(sender[0] || '?').toUpperCase()}
        </Avatar>
        <Box className="min-w-0">
          <Typography variant="subtitle2" fontWeight={700} sx={{ color: '#e2e8f0' }}>
            {sender}
          </Typography>
          {to && (
            <Typography variant="caption" className="text-slate-500">
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
              sx={{ borderColor: 'rgba(148,163,184,0.3)', color: '#94a3b8' }}
            />
          )}
        </Box>
      </Box>

      <Divider className="my-4" sx={{ borderColor: 'rgba(148,163,184,0.14)' }} />

      {!securityLoading && security?.links?.length > 0 && (
        <ThreatCard
          icon={LinkOutlined}
          title="Links in this email"
          count={security.links.length}
          items={security.links}
          renderItem={(l) => {
            const blocked = l.verdict === 'malicious' || l.verdict === 'suspicious'
            let host = l.url
            try {
              host = new URL(l.url).hostname
            } catch {
              /* keep raw */
            }
            return (
              <>
                <VerdictChip verdict={l.verdict} threatScore={l.threatScore} source={l.source} />
                <Box className="min-w-0">
                  <Typography variant="body2" fontWeight={600} className="text-slate-100">
                    {host}
                  </Typography>
                  <Link
                    href={l.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-sm break-all"
                    sx={{ color: blocked ? '#fb7185' : '#818cf8' }}
                    onClick={(e) => {
                      if (blocked) e.preventDefault()
                    }}
                  >
                    {l.url}
                  </Link>
                  {blocked && (
                    <Typography
                      variant="caption"
                      className="flex items-center gap-1 mt-0.5"
                      sx={{ color: '#fb7185', fontWeight: 600 }}
                    >
                      <BlockOutlined sx={{ fontSize: 13 }} />
                      Click blocked — {l.verdict === 'malicious' ? 'phishing link' : 'proceed with caution'}
                    </Typography>
                  )}
                </Box>
              </>
            )
          }}
        />
      )}

      {!securityLoading && security?.attachments?.length > 0 && (
        <ThreatCard
          icon={AttachFileOutlined}
          title="Attachments"
          count={security.attachments.length}
          items={security.attachments}
          renderItem={(a) => {
            const blocked = a.verdict === 'malicious' || a.verdict === 'suspicious'
            const sizeText =
              a.size > 1024 * 1024
                ? `${(a.size / 1024 / 1024).toFixed(1)} MB`
                : `${Math.max(1, Math.round(a.size / 1024))} KB`
            return (
              <>
                <VerdictChip verdict={a.verdict} threatScore={a.threatScore} source={a.source} />
                <Box className="min-w-0">
                  <Typography variant="body2" fontWeight={600} className="break-all text-slate-100">
                    <InsertDriveFileOutlined sx={{ fontSize: 14, mr: 0.5, verticalAlign: 'text-bottom', color: '#94a3b8' }} />
                    {a.filename}
                  </Typography>
                  <Typography variant="caption" className="text-slate-500">
                    {a.mimeType} · {sizeText}
                    {a.sha256 ? (
                      <Box component="span" className="font-mono text-slate-500" sx={{ fontSize: 11 }}>
                        {' '}
                        · sha256:{a.sha256.slice(0, 12)}…
                      </Box>
                    ) : null}
                  </Typography>
                  {a.note && (
                    <Typography variant="caption" className={`block break-words mt-0.5 ${blocked ? '' : ''}`} sx={{ color: blocked ? '#fb7185' : '#94a3b8' }}>
                      {a.note}
                    </Typography>
                  )}
                  {blocked && (
                    <Typography variant="caption" className="block mt-0.5" sx={{ color: '#fb7185', fontWeight: 600 }}>
                      {a.verdict === 'malicious'
                        ? 'Malicious attachment — do not open or download'
                        : 'Suspicious attachment — open with caution'}
                    </Typography>
                  )}
                </Box>
              </>
            )
          }}
        />
      )}

      <Box className="mt-4">
        {detail?.bodyHtml ? (
          <div
            className="email-body prose prose-sm max-w-none"
            dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(detail.bodyHtml) }}
          />
        ) : (
          <Typography variant="body1" className="whitespace-pre-wrap break-words text-slate-200">
            {detail?.bodyText || '(No readable body content)'}
          </Typography>
        )}
      </Box>
    </Box>
  )
}