import { useState, useEffect, useRef } from 'react'
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
  IconButton,
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
  ArrowBackOutlined,
  PublicOutlined,
  DnsOutlined,
  LockOutlined,
  SecurityOutlined,
  LocationOnOutlined,
  NetworkCheckOutlined,
  ExpandMoreOutlined,
  ExpandLessOutlined,
  DomainOutlined,
  LanguageOutlined,
  MailOutlineOutlined,
  FlagOutlined,
  GppBadOutlined,
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

function ScanProgress() {
  const startedAt = useRef(Date.now())
  const [progress, setProgress] = useState(0)
  const [stage, setStage] = useState(0)

  const stages = [
    'Extracting links & attachments...',
    'Querying threat intelligence...',
    'Analyzing file signatures...',
    'Finalizing security report...',
  ]

  // Smooth, game-style progress: eases toward 88% over ~28s so users never sit
  // wondering where the scan is. Actual result replaces the bar the moment the
  // API responds (100% is only ever set by the result render).
  useEffect(() => {
    const interval = setInterval(() => {
      const secsElapsed = Math.floor((Date.now() - startedAt.current) / 1000)
      const target = 88 // % cap
      const max = 28 // seconds
      const easeIn = 1 - Math.pow(1 - Math.min(1, secsElapsed / max), 3)
      setProgress(Math.min(target, Math.round(easeIn * target)))
      setStage((s) => {
        const thresholds = [7, 14, 21]
        if (s < stages.length - 1 && secsElapsed >= thresholds[s]) return s + 1
        return s
      })
    }, 1000)
    return () => clearInterval(interval)
  }, [])

  return (
    <Box className="mt-3">
      <Box className="flex items-center justify-between mb-2 gap-3">
        <Typography variant="caption" className="flex items-center gap-2 text-slate-300" sx={{ fontWeight: 600 }}>
          <Box className="w-2 h-2 rounded-full shrink-0" sx={{ bgcolor: '#818cf8', animation: 'scanPulse 1.2s ease-in-out infinite' }} />
          {stages[stage]}
        </Typography>
        <Typography variant="caption" className="font-mono shrink-0" sx={{ color: '#cbd5e1' }}>
          <span className="tabular-nums">{progress}%</span>
        </Typography>
      </Box>
      <Box className="h-2.5 w-full rounded-full overflow-hidden" sx={{ bgcolor: 'rgba(30,41,59,0.9)', border: '1px solid rgba(148,163,184,0.2)' }}>
        <Box
          className="h-full rounded-full"
          sx={{
            width: `${Math.max(6, progress)}%`,
            background: 'linear-gradient(90deg, #6366f1, #a855f7, #38bdf8)',
            backgroundSize: '200% 100%',
            animation: 'shimmer 1.6s ease-in-out infinite, scanFill 1s ease-out',
            transition: 'width 0.9s cubic-bezier(0.22, 1, 0.36, 1)',
          }}
        />
      </Box>
    </Box>
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
          {loading && <ScanProgress />}
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
            className="flex flex-wrap sm:flex-nowrap items-start gap-2.5 p-2.5 rounded-xl"
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

// ── Domain Intelligence components ────────────────────────────────────────────

const sectionCardSx = {
  bgcolor: 'rgba(255,255,255,0.03)',
  border: '1px solid rgba(148,163,184,0.14)',
  borderRadius: '12px',
}

function IntelKeyValue({ label, value, mono, warn }) {
  if (value == null || value === '' || value === false) return null
  return (
    <Box className="flex gap-2 items-start py-0.5">
      <Typography variant="caption" className="shrink-0 font-semibold mt-px" sx={{ color: '#94a3b8', minWidth: 90 }}>
        {label}
      </Typography>
      <Typography
        variant="caption"
        className={mono ? 'font-mono break-all' : 'break-all'}
        sx={{ color: warn ? '#fbbf24' : '#e2e8f0', fontWeight: 500 }}
      >
        {value}
      </Typography>
    </Box>
  )
}

function IntelSection({ icon: Icon, title, children, count, defaultOpen }) {
  const [open, setOpen] = useState(defaultOpen ?? false)
  return (
    <Box className="mb-1.5" sx={sectionCardSx}>
      <Box
        className="flex items-center gap-2 px-3 py-2 cursor-pointer select-none"
        onClick={() => setOpen((o) => !o)}
        sx={{ '&:hover': { bgcolor: 'rgba(255,255,255,0.03)' } }}
      >
        <Icon sx={{ color: '#818cf8', fontSize: 16 }} />
        <Typography variant="caption" fontWeight={700} className="flex-1" sx={{ color: '#e2e8f0' }}>
          {title}
        </Typography>
        {count != null && (
          <Chip
            size="small"
            label={count}
            sx={{ height: 18, fontSize: '0.65rem', fontWeight: 700, bgcolor: 'rgba(99,102,241,0.18)', color: '#a5b4fc', mr: 0.5 }}
          />
        )}
        {open ? <ExpandLessOutlined sx={{ fontSize: 16, color: '#94a3b8' }} /> : <ExpandMoreOutlined sx={{ fontSize: 16, color: '#94a3b8' }} />}
      </Box>
      {open && <Box className="px-3 pb-2.5 pt-1">{children}</Box>}
    </Box>
  )
}

function DomainInfoHeader({ intel }) {
  return (
    <Box className="mb-2.5 pb-2.5" sx={{ borderBottom: '1px solid rgba(148,163,184,0.14)' }}>
      <Box className="flex flex-wrap items-center gap-2 mb-1.5">
        <Typography variant="caption" fontWeight={700} sx={{ color: '#a5b4fc' }}>
          {intel.registrableDomain}
        </Typography>
        {intel.hosting && (
          <Chip
            size="small"
            label={intel.hosting.platform}
            sx={{ height: 20, fontSize: '0.65rem', fontWeight: 700, bgcolor: 'rgba(251,191,36,0.15)', color: '#fbbf24', border: '1px solid rgba(251,191,36,0.3)' }}
          />
        )}
        {intel.tinyTld && (
          <Chip
            size="small"
            label="Uncommon TLD"
            sx={{ height: 20, fontSize: '0.65rem', fontWeight: 700, bgcolor: 'rgba(251,146,60,0.12)', color: '#fb923c', border: '1px solid rgba(251,146,60,0.3)' }}
          />
        )}
      </Box>
      {intel.isSubdomain && (
        <Typography variant="caption" sx={{ color: '#94a3b8' }}>
          Subdomain: <span style={{ color: '#e2e8f0', fontWeight: 600 }}>{intel.subdomain}</span>
          <span style={{ margin: '0 4px', color: '#64748b' }}>|</span>
          Base domain: <span style={{ color: '#e2e8f0', fontWeight: 600 }}>{intel.registrableDomain}</span>
        </Typography>
      )}
      {intel.hosting && (
        <Typography variant="caption" className="block mt-1" sx={{ color: '#fbbf24', fontWeight: 500 }}>
          ⚠ {intel.hosting.note}
        </Typography>
      )}
      {intel.shortener && (
        <Box className="mt-1.5 p-2 rounded-lg" sx={{ bgcolor: 'rgba(99,102,241,0.08)', border: '1px solid rgba(99,102,241,0.2)' }}>
          <Typography variant="caption" sx={{ color: '#c7d2fe', fontWeight: 600 }}>
            🔗 Short link via {intel.shortener.service}
          </Typography>
          {intel.shortener.finalHost && (
            <Typography variant="caption" className="block mt-0.5" sx={{ color: '#94a3b8' }}>
              Redirects to: <span style={{ color: '#e2e8f0', fontWeight: 600 }}>{intel.shortener.finalHost}</span>
            </Typography>
          )}
          {intel.shortener.finalUrl && (
            <Typography variant="caption" className="block mt-0.5 font-mono break-all" sx={{ color: '#818cf8', fontSize: 11 }}>
              {intel.shortener.finalUrl}
            </Typography>
          )}
          {!intel.shortener.finalHost && (
            <Typography variant="caption" className="block mt-0.5" sx={{ color: '#f87171', fontWeight: 500 }}>
              Redirect target unreachable
            </Typography>
          )}
        </Box>
      )}
    </Box>
  )
}

function WhoisSection({ data }) {
  if (!data) return null
  const registrant = data.registrant
  const regAddr = registrant?.address
  const regLocation = [
    regAddr?.city,
    regAddr?.state,
    regAddr?.country,
  ]
    .filter(Boolean)
    .join(', ')
  return (
    <IntelSection icon={DomainOutlined} title="WHOIS & Registration">
      {registrant && (
        <>
          {!registrant.redacted && registrant.organization && (
            <IntelKeyValue label="Registrant Org" value={registrant.organization} />
          )}
          {!registrant.redacted && registrant.name && registrant.name !== 'REDACTED REGISTRANT' && (
            <IntelKeyValue label="Registrant" value={registrant.name} />
          )}
          {!registrant.redacted && regLocation && (
            <IntelKeyValue label="Registrant Location" value={regLocation} />
          )}
          {registrant.redacted && (
            <Typography variant="caption" className="block mb-1" sx={{ color: '#64748b' }}>
              Registrant details redacted by the registrar (privacy/GDPR).
            </Typography>
          )}
        </>
      )}
      <IntelKeyValue label="Registrar" value={data.registrar} />
      {data.registrarIanaId && <IntelKeyValue label="Registrar IANA ID" value={data.registrarIanaId} />}
      {data.registrarUrl && (
        <IntelKeyValue
          label="Registrar URL"
          value={
            <Link href={data.registrarUrl} target="_blank" rel="noopener noreferrer" sx={{ color: '#818cf8' }}>
              {data.registrarUrl}
            </Link>
          }
        />
      )}
      {data.abuseEmail && (
        <Typography variant="caption" className="block" sx={{ color: '#94a3b8', mb: 0.5 }}>
          Abuse contact: <span className="font-mono" style={{ color: '#e2e8f0' }}>{data.abuseEmail}</span>
        </Typography>
      )}
      <IntelKeyValue label="Created" value={data.created} />
      <IntelKeyValue label="Updated" value={data.updated} />
      <IntelKeyValue label="Expires" value={data.expires} />
      {data.domainAgeDays != null && (
        <IntelKeyValue
          label="Domain Age"
          value={`${Math.floor(data.domainAgeDays / 365)}y ${data.domainAgeDays % 365}d`}
          warn={data.domainAgeDays < 180}
        />
      )}
      {data.nameservers && data.nameservers.length > 0 && (
        <IntelKeyValue label="Nameservers" value={data.nameservers.join(', ')} mono />
      )}
      {data.dnssec != null && (
        <IntelKeyValue
          label="DNSSEC"
          value={data.dnssec ? 'Signed' : 'Not signed'}
          warn={!data.dnssec}
        />
      )}
      {data.status && data.status.length > 0 && (
        <IntelKeyValue label="Status" value={data.status.join(', ')} />
      )}
    </IntelSection>
  )
}

function DnsSection({ data }) {
  if (!data) return null
  const hasAny = data.a?.length || data.aaaa?.length || data.mx?.length || data.ns?.length || data.txt?.length || data.cname?.length
  if (!hasAny) return null
  return (
    <IntelSection icon={DnsOutlined} title="DNS Records">
      {data.a?.length > 0 && <IntelKeyValue label="A (IPv4)" value={data.a.join(', ')} mono />}
      {data.aaaa?.length > 0 && <IntelKeyValue label="AAAA (IPv6)" value={data.aaaa.join(', ')} mono />}
      {data.mx?.length > 0 && <IntelKeyValue label="MX (Mail)" value={data.mx.join(', ')} mono />}
      {data.ns?.length > 0 && <IntelKeyValue label="NS" value={data.ns.join(', ')} mono />}
      {data.cname?.length > 0 && <IntelKeyValue label="CNAME" value={data.cname.join(', ')} mono />}
      {data.txt?.length > 0 && <IntelKeyValue label="TXT" value={data.txt.join(' | ')} mono />}
    </IntelSection>
  )
}

function GeoSection({ data }) {
  if (!data?.details) return null
  const d = data.details
  const parts = [d.city, d.region, d.country_name].filter(Boolean).join(', ')
  return (
    <IntelSection icon={LocationOnOutlined} title="IP & Location">
      {data.ip && <IntelKeyValue label="IP Address" value={data.ip} mono />}
      {parts && <IntelKeyValue label="Location" value={parts} />}
      {d.country_code && <IntelKeyValue label="Country" value={`${d.country_code}  (${d.country_name || ''})`} />}
      {d.connection?.isp && <IntelKeyValue label="ISP" value={d.connection.isp} />}
      {d.connection?.org && d.connection.org !== d.connection?.isp && <IntelKeyValue label="Org" value={d.connection.org} />}
      {d.connection?.asn && <IntelKeyValue label="ASN" value={String(d.connection.asn)} />}
      {d.security?.proxy && <IntelKeyValue label="Proxy/VPN" value="Yes" warn />}
      {d.security?.tor && <IntelKeyValue label="Tor Exit" value="Yes" warn />}
    </IntelSection>
  )
}

function SslSection({ data }) {
  if (!data) return null
  return (
    <IntelSection icon={LockOutlined} title="SSL Certificate">
      {data.issuer && <IntelKeyValue label="Issuer" value={data.issuer} />}
      {data.commonName && <IntelKeyValue label="Common Name" value={data.commonName} mono />}
      {data.notBefore && <IntelKeyValue label="Valid From" value={data.notBefore} />}
      {data.notAfter && <IntelKeyValue label="Valid Until" value={data.notAfter} />}
      {data.daysLeft != null && (
        <IntelKeyValue
          label="Days Left"
          value={data.daysLeft === 0 ? 'Expired' : String(data.daysLeft)}
          warn={data.daysLeft < 30}
        />
      )}
      {data.count != null && data.count > 1 && <IntelKeyValue label="Total Certs" value={String(data.count)} />}
      {data.firstSeen && <IntelKeyValue label="First Seen" value={data.firstSeen} />}
    </IntelSection>
  )
}

function ThreatSection({ data }) {
  if (!data) return null
  return (
    <IntelSection icon={SecurityOutlined} title="Threat Intel">
      <Box className="flex items-center gap-2 mb-1">
        <Box
          className="w-2.5 h-2.5 rounded-full shrink-0"
          sx={{ bgcolor: data.listed ? '#fb7185' : '#34d399' }}
        />
        <Typography variant="caption" fontWeight={700} sx={{ color: data.listed ? '#fb7185' : '#34d399' }}>
          {data.listed ? 'LISTED on threat databases' : 'Not listed in any blocklist'}
        </Typography>
      </Box>
      {data.message && (
        <Typography variant="caption" className="block" sx={{ color: '#94a3b8', mt: 0.5 }}>
          {data.message}
        </Typography>
      )}
      {data.riskScore != null && (
        <IntelKeyValue label="Risk Score" value={String(data.riskScore) + ' / 100'} warn={data.riskScore > 50} />
      )}
    </IntelSection>
  )
}

function ReverseIpSection({ data }) {
  if (!data?.domains || data.domains.length === 0) return null
  const show = data.domains.slice(0, 8)
  return (
    <IntelSection icon={NetworkCheckOutlined} title="Reverse IP" count={data.domains.length}>
      <IntelKeyValue label="IP Address" value={data.ip} mono />
      <Typography variant="caption" className="block mb-1" sx={{ color: '#94a3b8' }}>
        {data.domains.length} other domain(s) share this IP:
      </Typography>
      <Box className="flex flex-wrap gap-1">
        {show.map((d, i) => (
          <Chip
            key={i}
            size="small"
            label={d}
            sx={{ height: 18, fontSize: '0.6rem', bgcolor: 'rgba(148,163,184,0.1)', color: '#cbd5e1', border: '1px solid rgba(148,163,184,0.18)' }}
          />
        ))}
        {data.domains.length > 8 && (
          <Chip size="small" label={`+${data.domains.length - 8}`} sx={{ height: 18, fontSize: '0.6rem', bgcolor: 'rgba(148,163,184,0.08)', color: '#94a3b8' }} />
        )}
      </Box>
    </IntelSection>
  )
}

function DomainIntelCard({ intel }) {
  if (!intel) return null
  return (
    <Box className="mt-2.5 mb-1 p-3 rounded-xl" sx={{ bgcolor: 'rgba(99,102,241,0.04)', border: '1px solid rgba(99,102,241,0.18)' }}>
      <Box className="flex items-center gap-2 mb-1">
        <PublicOutlined sx={{ color: '#818cf8', fontSize: 16 }} />
        <Typography variant="caption" fontWeight={700} sx={{ color: '#a5b4fc' }}>
          Domain Intelligence
        </Typography>
      </Box>
      <DomainInfoHeader intel={intel} />
      <WhoisSection data={intel.whois} />
      <DnsSection data={intel.dns} />
      <GeoSection data={intel.geo} />
      <SslSection data={intel.ssl} />
      <ThreatSection data={intel.threat} />
      <ReverseIpSection data={intel.reverseIp} />
    </Box>
  )
}

const SEVERITY_COLORS = {
  high: { label: '#f87171', bg: 'rgba(248,113,113,0.12)', border: 'rgba(248,113,113,0.3)' },
  medium: { label: '#fbbf24', bg: 'rgba(251,191,36,0.1)', border: 'rgba(251,191,36,0.3)' },
  low: { label: '#fbbf24', bg: 'rgba(251,191,36,0.08)', border: 'rgba(251,191,36,0.2)' },
}

function AuthChip({ label, value }) {
  if (!value) return null
  const pass = value === 'pass'
  const bad = value === 'fail'
  return (
    <Chip
      size="small"
      label={`${label}: ${value.toUpperCase()}`}
      sx={{
        height: 20, fontSize: '0.62rem', fontWeight: 700,
        bgcolor: bad ? 'rgba(248,113,113,0.15)' : pass ? 'rgba(52,211,153,0.12)' : 'rgba(251,191,36,0.12)',
        color: bad ? '#f87171' : pass ? '#34d399' : '#fbbf24',
        border: `1px solid ${bad ? 'rgba(248,113,113,0.3)' : pass ? 'rgba(52,211,153,0.3)' : 'rgba(251,191,36,0.3)'}`,
      }}
    />
  )
}

// Sender / email OSINT card - shown under the banner when an email is flagged.
// phishingSeverity = the hybrid-analysis verdict (malicious/suspicious/unknown/
// safe). It always drives the headline risk: if phishing was detected the risk
// must NOT read "Low" just because the mail headers look clean.
function EmailIntelCard({ intel, phishingSeverity }) {
  if (!intel) return null
  const { sender, replyTo, returnPath, senderHeader, auth, sendingIp, senderIp, senderGeo, providerIp, providerHost, providerGeo, geo, flags, spamScore, brandSpoof, senderDomainIntel } = intel
  const score = spamScore || 0
  const threatRank = { malicious: 3, suspicious: 2, unknown: 1, safe: 0 }
  const osintRank = score > 9 ? 3 : score > 5 ? 2 : 1
  const effectiveRank = Math.max(threatRank[phishingSeverity] || 0, osintRank)
  const riskLabel = effectiveRank >= 3 ? 'High' : effectiveRank === 2 ? 'Medium' : 'Low'
  const scoreWarn = effectiveRank >= 2
  const geoParts = (geo || senderGeo) ? [senderGeo?.city, senderGeo?.region, senderGeo?.country_name].filter(Boolean).join(', ') : null
  const providerParts = providerGeo ? [providerGeo.city, providerGeo.region, providerGeo.country_name].filter(Boolean).join(', ') : null
  const senderWhois = senderDomainIntel?.whois
  return (
    <Box className="mt-3 mb-1 p-3 rounded-xl" sx={{ bgcolor: 'rgba(248,113,113,0.04)', border: '1px solid rgba(248,113,113,0.22)' }}>
      <Box className="flex items-center gap-2 mb-1">
        <MailOutlineOutlined sx={{ color: '#f87171', fontSize: 16 }} />
        <Typography variant="caption" fontWeight={700} sx={{ color: '#fca5a5' }}>
          Sender Intelligence (OSINT)
        </Typography>
        <Chip
          size="small"
          label={`Risk ${riskLabel}${score ? ` · ${score}` : ''}`}
          sx={{
            ml: 'auto', height: 20, fontSize: '0.62rem', fontWeight: 700,
            bgcolor: scoreWarn ? 'rgba(248,113,113,0.15)' : 'rgba(52,211,153,0.12)',
            color: scoreWarn ? '#f87171' : '#34d399',
            border: `1px solid ${scoreWarn ? 'rgba(248,113,113,0.3)' : 'rgba(52,211,153,0.3)'}`,
          }}
        />
      </Box>

      <Box className="mb-1.5">
        <Typography variant="caption" fontWeight={600} sx={{ color: '#e2e8f0' }}>
          {intel.sender?.name || '(no display name)'}
        </Typography>
        <Typography variant="caption" className="block font-mono break-all" sx={{ color: '#cbd5e1' }}>
          {intel.sender?.email || 'unknown sender'}
        </Typography>
      </Box>

      {(flags || []).length > 0 && (
        <Box className="mb-1.5">
          {flags.map((f, i) => {
            const c = SEVERITY_COLORS[f.severity] || SEVERITY_COLORS.medium
            return (
              <Box
                key={i}
                className="flex items-start gap-1.5 px-2 py-1 mb-1 rounded-lg"
                sx={{ bgcolor: c.bg, border: `1px solid ${c.border}` }}
              >
                <FlagOutlined sx={{ color: c.label, fontSize: 13, mt: 0.3 }} />
                <Box className="min-w-0">
                  <Typography variant="caption" fontWeight={600} sx={{ color: c.label }} className="block">
                    {f.label}
                  </Typography>
                  {f.detail && (
                    <Typography variant="caption" className="block break-all" sx={{ color: '#94a3b8' }}>
                      {f.detail}
                    </Typography>
                  )}
                </Box>
              </Box>
            )
          })}
        </Box>
      )}

      <IntelSection icon={LockOutlined} title="Authentication">
        <Box className="flex gap-1.5 flex-wrap">
          <AuthChip label="SPF" value={auth?.spf} />
          <AuthChip label="DKIM" value={auth?.dkim} />
          <AuthChip label="DMARC" value={auth?.dmarc} />
        </Box>
        {auth?.dkimSignatures && (
          <IntelKeyValue label="DKIM Signature" value={auth.dkimSignatures.join('; ')} mono />
        )}
        {replyTo && <IntelKeyValue label="Reply-To" value={`${replyTo.name ? replyTo.name + ' ' : ''}${replyTo.email}`} mono />}
        {returnPath?.email && <IntelKeyValue label="Return-Path" value={returnPath.email} mono />}
        {senderHeader?.email && <IntelKeyValue label="Sender" value={senderHeader.email} mono />}
        {intel.messageId && <IntelKeyValue label="Message-ID" value={intel.messageId} mono />}
      </IntelSection>

      <IntelSection icon={LocationOnOutlined} title="Sending Origin">
        {(senderIp || sendingIp) && <IntelKeyValue label="Sender IP" value={senderIp || sendingIp} mono />}
        {geoParts && <IntelKeyValue label="Sender Location" value={geoParts} />}
        {senderGeo?.country_code && <IntelKeyValue label="Country" value={`${senderGeo.country_code}  (${senderGeo.country_name || ''})`} />}
        {senderGeo?.connection?.isp && <IntelKeyValue label="ISP" value={senderGeo.connection.isp} />}
        {senderGeo?.connection?.asn && <IntelKeyValue label="ASN" value={String(senderGeo.connection.asn)} />}
        {senderGeo?.security?.proxy || senderGeo?.security?.tor ? (
          <IntelKeyValue label="Anonymizer" value={senderGeo.security.proxy ? 'Proxy/VPN' : senderGeo.security.tor ? 'Tor exit' : 'Yes'} warn />
        ) : null}
        <Box sx={{ mt: 1, pt: 1, borderTop: '1px dashed rgba(148,163,184,0.25)' }} />
        <Typography variant="caption" fontWeight={600} sx={{ color: '#94a3b8' }}>
          Mail Service Provider
        </Typography>
        {providerIp && <IntelKeyValue label="Provider IP" value={providerIp} mono />}
        {providerHost && <IntelKeyValue label="Provider Host" value={providerHost} mono />}
        {providerParts && <IntelKeyValue label="Provider Location" value={providerParts} />}
        {providerGeo?.connection?.isp && <IntelKeyValue label="Provider ISP" value={providerGeo.connection.isp} />}
        {!providerIp && <IntelKeyValue label="Provider IP" value="Not available" />}
      </IntelSection>

      {senderDomainIntel && (
        <IntelSection icon={DomainOutlined} title="Sender Domain">
          <IntelKeyValue label="Domain" value={senderDomainIntel.registrableDomain || sender?.domain} mono />
          {senderDomainIntel.hosting && (
            <IntelKeyValue label="Hosting" value={senderDomainIntel.hosting.platform} />
          )}
          {senderWhois?.registrar && <IntelKeyValue label="Registrar" value={senderWhois.registrar} />}
          {senderWhois?.domainAgeDays != null && (
            <IntelKeyValue
              label="Domain Age"
              value={`${Math.floor(senderWhois.domainAgeDays / 365)}y ${senderWhois.domainAgeDays % 365}d`}
              warn={senderWhois.domainAgeDays < 180}
            />
          )}
          {senderWhois?.registrant && !senderWhois.registrant.redacted && (
            <>
              {senderWhois.registrant.organization && (
                <IntelKeyValue label="Registrant Org" value={senderWhois.registrant.organization} />
              )}
              {senderWhois.registrant.address?.state && (
                <IntelKeyValue label="State" value={senderWhois.registrant.address.state} />
              )}
              {senderWhois.registrant.address?.country && (
                <IntelKeyValue label="Country" value={senderWhois.registrant.address.country} />
              )}
            </>
          )}
        </IntelSection>
      )}
    </Box>
  )
}

export default function EmailDetail({ emailId, email, onBack }) {
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
    <Box className="h-full overflow-y-auto p-4 sm:p-6 md:p-8 min-w-0">
      {onBack && (
        <Box className="flex items-center gap-2 mb-3 -ml-1">
          <IconButton onClick={onBack} aria-label="back" sx={{ color: '#94a3b8' }}>
            <ArrowBackOutlined />
          </IconButton>
          <Typography variant="caption" className="text-slate-400 font-medium">
            Back to inbox
          </Typography>
        </Box>
      )}
      <Typography variant="h6" fontWeight={700} className="mb-4 tracking-tight break-words" sx={{ color: '#f1f5f9' }}>
        {email?.subject || detail?.subject || '(no subject)'}
      </Typography>

      {(securityLoading || security) && <SecurityBanner banner={banner} loading={securityLoading} />}

      {!securityLoading && security?.emailIntel && (
        <EmailIntelCard intel={security.emailIntel} phishingSeverity={security.summary?.highestSeverity || security.summary?.verdict} />
      )}

      {!securityLoading && securityError && (
        <Alert severity="warning" className="mb-4" sx={{ borderRadius: 3 }}>
          <AlertTitle>Security check failed</AlertTitle>
          Could not check this email: {securityError}
        </Alert>
      )}

      <Box className="flex flex-wrap items-center gap-3 mb-1 min-w-0">
        <Avatar className="shrink-0" sx={{ bgcolor: 'primary.main', fontWeight: 700 }}>
          {(sender[0] || '?').toUpperCase()}
        </Avatar>
        <Box className="min-w-0 flex-1">
          <Typography variant="subtitle2" fontWeight={700} className="break-words" sx={{ color: '#e2e8f0' }}>
            {sender}
          </Typography>
          {to && (
            <Typography variant="caption" className="text-slate-500 break-all">
              to {to}
            </Typography>
          )}
        </Box>
        <Box className="shrink-0">
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
                <Box className="min-w-0 flex-1">
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
                  {(l.verdict === 'malicious' || l.verdict === 'suspicious') && l.domainIntel && (
                    <DomainIntelCard intel={l.domainIntel} />
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

      <Box className="mt-4 min-w-0 overflow-x-auto">
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