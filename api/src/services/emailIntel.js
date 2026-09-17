// Email OSINT service.
// When an email is flagged as phishing we surface intelligence about the SENDER
// itself: who the From address claims to be vs. what the mail headers prove.
//
// Everything here reads only the message headers (already fetched by gmail.js),
// plus free passive lookups - no sandbox, no API keys:
//   - Display-name spoofing (From says "Google" but the address is @evil.io)
//   - Reply-To / Return-Path / Sender domain mismatches (classic re-routing)
//   - SPF / DKIM / DMARC results from Authentication-Results + DKIM-Signature
//   - First external Received hop -> sending IP -> geo (ipwho.is)
//   - Sender-domain WHOIS + age via domainIntel.js (real registry data)

import { getDomainIntel } from './domainIntel.js'

const HTTP_TIMEOUT_MS = 9000

// Prominent brands used in spoofing campaigns. If the display name matches one
// but the email domain does NOT, that is a strong social-engineering signal.
const KNOWN_BRANDS = [
  'google', 'gmail', 'youtube', 'microsoft', 'outlook', 'office', 'hotmail',
  'apple', 'icloud', 'amazon', 'paypal', 'facebook', 'whatsapp', 'instagram',
  'netflix', 'dropbox', 'linkedin', 'twitter', 'x', 'github', 'gitlab',
  'slack', 'zoom', 'adobe', 'salesforce', 'shopify', 'walmart', 'fedex',
  'ups', 'dhl', 'state bank of india', 'sbi', 'hdfc', 'icici', 'axis bank',
  'bank of india', 'pnc', 'chase', 'wells fargo', 'paytm', 'phonepe', 'gpay',
  'uber', 'airbnb', 'coinbase', 'binance', 'no-reply', 'noreply', 'do-not-reply',
]

const LOW_REPUTATION_TLDS = new Set([
  'tk', 'ml', 'ga', 'cf', 'gq', 'zip', 'mov', 'xyz', 'top', 'click', 'link',
  'support', 'accountant', 'work', 'stream', 'download', 'men', 'loan',
  'win', 'bid', 'trade', 'review', 'date',
])

function getHeader(headers, name) {
  if (!headers) return null
  const found = headers.find(
    (h) => h.name && h.name.toLowerCase() === name.toLowerCase()
  )
  return found ? found.value : null
}

function getAllHeaders(headers, name) {
  if (!headers) return []
  return headers
    .filter((h) => h.name && h.name.toLowerCase() === name.toLowerCase())
    .map((h) => h.value)
}

function splitAddresses(value) {
  if (!value) return []
  const out = []
  // Matches inline groups of "Name <a@b.com>, c@d.com" - supports quoted names.
  const re = /(?:([^<,]*?)\s*<([^>]+)>|([^\s,]+@[^\s,]+))/g
  let m
  while ((m = re.exec(value)) !== null) {
    const name = (m[1] || '').replace(/"/g, '').trim()
    const email = (m[2] || m[3] || '').trim().toLowerCase()
    if (email) out.push({ name, email })
  }
  return out
}

function domainOf(email) {
  if (!email) return null
  const at = email.lastIndexOf('@')
  if (at < 0) return null
  return email.slice(at + 1).toLowerCase()
}

function looksLegitBrand(displayName, domain) {
  if (!displayName || !domain) return null
  const clean = displayName.toLowerCase().replace(/[^a-z0-9 ]/g, ' ').replace(/\s+/g, ' ').trim()
  for (const brand of KNOWN_BRANDS) {
    if (clean === brand || clean.startsWith(brand + ' ') || clean.endsWith(' ' + brand) || clean.includes(' ' + brand + ' ')) {
      const brandAddr = domain.split('.')[0]
      // If the address domain actually is the brand (google.com, paypal.com)
      // it is legit - no flag. If not, it is an imposter presenting a brand name.
      return {
        brand,
        imposter: !(
          domain === brand.replace(/[^a-z0-9.]/g, '') + '.com' ||
          domain === brand + '.com' ||
          domain === 'accounts.' + brand + '.com' ||
          /\.google\.com$/.test(domain) && brand === 'google' ||
          /\.microsoft\.com$/.test(domain) && brand === 'microsoft' ||
          brandAddr === brand ||
          domain.includes(brand + '.')
        ),
      }
    }
  }
  return null
}

// Parse "Authentication-Results: mail.sender.com;\n spf=pass smtp.mailfrom=..."
// into { spf, dkim, dmarc } verdicts (pass/fail/softfail/temperror etc.).
function parseAuthResults(headers) {
  const results = { spf: null, dkim: null, dmarc: null, raw: [] }
  for (const raw of getAllHeaders(headers, 'Authentication-Results')) {
    results.raw.push(raw)
    const first = raw.split(';')[0].trim()
    const parts = raw.split(';').slice(1).join('\n')
    const grab = (label) => {
      const m = parts.match(new RegExp(label + '\\s*=\\s*(pass|fail|softfail|neutral|none|temperror|permerror|policy)', 'i'))
      return m ? m[1].toLowerCase() : null
    }
    let spf = grab('spf')
    let dkim = grab('dkim')
    let dmarc = grab('dmarc')
    if (!spf && /@domain\./i.test(first)) spf = grab('spf')
    if (spf) results.spf = results.spf || spf
    if (dkim) results.dkim = results.dkim || dkim
    if (dmarc) results.dmarc = results.dmarc || dmarc
  }
  return results
}

function parseDkimSignatures(headers) {
  const out = []
  for (const sig of getAllHeaders(headers, 'DKIM-Signature')) {
    const d = sig.match(/d=([^;]+)/i)
    const s = sig.match(/s=([^;]+)/i)
    if (d) out.push(s ? `${d[1].trim()} (${s[1].trim()})` : d[1].trim())
  }
  return out
}

// Received-chain parsing.
//
// Headers arrive in message order: the FIRST Received line is the NEWEST hop
// (added by the receiving side, e.g. mx.google.com) and the LAST is the OLDEST
// (the very first hop made by the sender's mail client / server).
//   - senderIp: the IP on the OLDEST hop = the real sending host.
//   - providerIp: the last external MTA that handed the mail to Gmail = the
//     sending mail-service provider's server (e.g. an AWS/Mailchimp/Serverless
//     edge). We pick the first public IP going from the newest hop down past
//     Google's own ranges.

const GOOGLE_IP_RANGES = new Set([
  '34.', '35.', '64.233.', '66.102.', '66.249.', '72.14.', '74.125.',
  '104.154.', '104.196.', '142.250.', '172.217.', '173.194.', '209.85.',
  '216.58.', '216.239.',
])

function isPublicIp(ip) {
  if (!ip) return false
  const parts = ip.split('.').map(Number)
  if (parts.length !== 4 || parts.some((n) => Number.isNaN(n))) return false
  if (
    parts[0] === 10 ||
    parts[0] === 127 ||
    parts[0] === 0 ||
    (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
    (parts[0] === 192 && parts[1] === 168) ||
    (parts[0] === 169 && parts[1] === 254) ||
    (parts[0] >= 224 && parts[0] <= 255)
  ) return false
  return true
}

function isGoogleIp(ip) {
  if (!ip) return false
  for (const prefix of GOOGLE_IP_RANGES) if (ip.startsWith(prefix)) return true
  return false
}

// Split one Received line into the IPs seen before/after "by". Returns the
// from-IP and by-IP if present.
function parseReceivedHop(line) {
  const byIdx = line.toLowerCase().indexOf(' by ')
  const fromPart = byIdx > 0 ? line.slice(0, byIdx) : line
  const byPart = byIdx > 0 ? line.slice(byIdx + 4) : ''
  const ips = (s) => (s.match(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g) || [])
  return {
    from: ips(fromPart),
    by: ips(byPart),
  }
}

// [[senderIp, senderHost], providerIp, providerHost]
function extractIps(headers) {
  const hopIps = getAllHeaders(headers, 'Received').map(parseReceivedHop)
  // hopIps[0] = newest (Gmail), hopIps[last] = oldest (origin).
  let senderIp = null
  let providerIp = null
  let providerHost = null
  for (let i = hopIps.length - 1; i >= 0 && !senderIp; i--) {
    for (const ip of hopIps[i].from) {
      if (isPublicIp(ip) && !isGoogleIp(ip)) {
        senderIp = ip
        break
      }
    }
  }
  for (let i = 0; i < hopIps.length && !providerIp; i++) {
    for (const ip of hopIps[i].from) {
      if (isPublicIp(ip) && !isGoogleIp(ip)) {
        providerIp = ip
        break
      }
    }
  }
  // Gmail sends with a "Received: from mail-x.google.com (mail-x.google.com.
  // [IP]) by mx.google.com". The provider hostname that handed mail to Gmail
  // is the from-clause token on the newest Received line.
  if (hopIps.length) {
    const newest = getAllHeaders(headers, 'Received')[0]
    const m = newest.match(/from\s+([A-Za-z0-9._-]+(?:\.[A-Za-z0-9._-]+)*)/i)
    if (m) {
      const host = m[1]
      providerHost = host === 'unknown' || host === 'fwd' || host === 'localhost' || isGoogleIp(host)
        ? null
        : host
    }
  }
  return { senderIp, providerIp, providerHost }
}

function firstExternalIp(headers) {
  // Kept for compatibility with the older single-IP consumers (geo lookup for
  // the sender). Prefer extractIps().senderIp in new code.
  if (!Array.isArray(headers)) return null
  const { senderIp } = extractIps(headers)
  return senderIp
}

async function lookupIpGeo(ip) {
  if (!ip) return null
  try {
    const res = await fetch(`https://ipwho.is/${encodeURIComponent(ip)}`, {
      headers: { accept: 'application/json' },
      signal: AbortSignal.timeout(HTTP_TIMEOUT_MS),
    })
    if (!res.ok) return null
    const data = await res.json()
    return data?.success === false ? null : data
  } catch {
    return null
  }
}

// ---- Main entry point -----------------------------------------------------

export async function buildEmailIntel(headers) {
  try {
    return await gather(headers)
  } catch (e) {
    console.warn(`[emailIntel] lookup failed: ${e.message}`)
    return null
  }
}

async function gather(headers) {
  if (!Array.isArray(headers) || headers.length === 0) return null

  const fromValue = getHeader(headers, 'From') || ''
  const from = splitAddresses(fromValue)[0] || null
  const fromDomain = from ? domainOf(from.email) : null

  const replyToList = splitAddresses(getHeader(headers, 'Reply-To'))
  const replyTo = replyToList[0] || null
  const replyToDomain = replyTo ? domainOf(replyTo.email) : null

  const returnPathRaw = getHeader(headers, 'Return-Path') || getHeader(headers, 'Errors-To') || ''
  const returnPath = returnPathRaw.replace(/[<>]/g, '').trim()
  const returnPathEmail = returnPath.includes('@') ? returnPath : null
  const returnPathDomain = returnPathEmail ? domainOf(returnPathEmail) : null

  const senderRaw = getHeader(headers, 'Sender')
  const sender = splitAddresses(senderRaw)[0] || null
  const senderDomain = sender ? domainOf(sender.email) : null

  const auth = parseAuthResults(headers)
  const dkimSigs = parseDkimSignatures(headers)
  const messageId = getHeader(headers, 'Message-ID') || null
  const date = getHeader(headers, 'Date') || null
  const subject = getHeader(headers, 'Subject') || null
  const email = from?.email || null

  // --- spoofing / re-routing flags -----------------------------------------
  const flags = []
  const displayName = from?.name || ''
  const brandMatch = looksLegitBrand(displayName, fromDomain)
  if (brandMatch?.imposter) {
    flags.push({
      severity: 'high',
      label: `Display name masquerades as "${brandMatch.brand}"`,
      detail: `"${displayName}" but the address is from ${fromDomain}`,
    })
  }
  // brandMatch && !imposter = legitimate brand domain, no flag.
  if (fromDomain && replyToDomain && replyToDomain !== fromDomain) {
    flags.push({
      severity: replyToDomain ? 'high' : 'low',
      label: 'Reply-To domain differs from From',
      detail: `From ${fromDomain} but replies go to ${replyToDomain}`,
    })
  }
  if (fromDomain && returnPathDomain && returnPathDomain !== fromDomain && !returnPathDomain.endsWith('.google.com')) {
    flags.push({
      severity: 'high',
      label: 'Return-Path domain differs from From',
      detail: `Envelope sender is ${returnPathDomain}, not ${fromDomain}`,
    })
  }
  if (fromDomain && senderDomain && senderDomain !== fromDomain && !/^bounce|^mailer|^smtp|^em/.test(senderDomain)) {
    flags.push({
      severity: 'medium',
      label: 'Sender header domain differs from From',
      detail: `Sender ${senderDomain} vs From ${fromDomain}`,
    })
  }
  if (auth.spf && auth.spf !== 'pass') flags.push({
    severity: auth.spf === 'fail' ? 'high' : 'medium',
    label: `SPF ${auth.spf.toUpperCase()}`,
    detail: 'Sender IP was not authorised to send for this domain',
  })
  if (auth.dkim && auth.dkim !== 'pass') flags.push({
    severity: auth.dkim === 'fail' ? 'high' : 'medium',
    label: `DKIM ${auth.dkim.toUpperCase()}`,
    detail: 'Message signature validation did not pass',
  })
  if (auth.dmarc && auth.dmarc !== 'pass') flags.push({
    severity: auth.dmarc === 'fail' ? 'high' : 'medium',
    label: `DMARC ${auth.dmarc.toUpperCase()}`,
    detail: 'Domain-level authentication policy not satisfied',
  })
  if (fromDomain && LOW_REPUTATION_TLDS.has(fromDomain.split('.').pop())) {
    flags.push({
      severity: 'medium',
      label: 'Sender uses a low-reputation TLD',
      detail: `Domain ${fromDomain} uses a cheap/abuse-prone TLD`,
    })
  }

  const { senderIp, providerIp, providerHost } = extractIps(headers)
  const [geo, providerGeo, senderIntel] = await Promise.all([
    senderIp ? lookupIpGeo(senderIp).catch(() => null) : Promise.resolve(null),
    providerIp && providerIp !== senderIp ? lookupIpGeo(providerIp).catch(() => null) : Promise.resolve(null),
    fromDomain ? getDomainIntel(`https://${fromDomain}/`).catch(() => null) : Promise.resolve(null),
  ])

  // Numeric risk score from the flags + domain freshness.
  const weight = { high: 3, medium: 2, low: 1 }
  let spamScore = flags.reduce((acc, f) => acc + (weight[f.severity] || 1), 0)
  const age = senderIntel?.whois?.domainAgeDays
  if (age != null) {
    if (age < 30) spamScore += 3
    else if (age < 180) spamScore += 2
    else if (age < 365) spamScore += 1
  } else if (senderIntel == null) {
    // Sender domain had no WHOIS at all - freshest possible.
    spamScore += 2
  }

  return {
    sender: {
      name: from?.name || null,
      email,
      domain: fromDomain,
      displayName,
    },
    brandSpoof: brandMatch?.imposter ? { brand: brandMatch.brand, displayName } : null,
    replyTo: replyTo ? { name: replyTo.name, email: replyTo.email, domain: replyToDomain } : null,
    returnPath: returnPathEmail
      ? { email: returnPathEmail, domain: returnPathDomain }
      : returnPath
        ? { email: null, domain: returnPathDomain, raw: returnPath }
        : null,
    senderHeader: sender ? { email: sender.email, domain: senderDomain } : null,
    auth: {
      spf: auth.spf,
      dkim: auth.dkim,
      dmarc: auth.dmarc,
      dkimSignatures: dkimSigs.length ? dkimSigs : null,
    },
    messageId,
    date,
    subject,
    sendingIp: senderIp,
    senderIp,
    senderGeo: geo,
    providerIp,
    providerHost,
    providerGeo,
    geo,
    senderDomainIntel: senderIntel,
    flags,
    spamScore,
  }
}

export default buildEmailIntel