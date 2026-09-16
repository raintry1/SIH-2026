// Domain intelligence service.
// When a link is flagged malicious/suspicious, we enrich it with passive DNS,
// WHOIS, IP geolocation, SSL certificate, threat-list and reverse-IP data about
// the REAL registrable domain behind that URL.
//
// Handles three tricky cases before any lookup runs:
//   1) Long / obfuscated links  -> registrable domain is extracted with tldts
//      so the public suffix rules (co.uk, com.au, netlify.app) are honoured.
//   2) Subdomains               -> subdomain + base domain are reported
//      separately, and if the base is a known free-hosting platform
//      (netlify.app, onrender.com, vercel.app, ...) we say so explicitly,
//      because anyone can host anything there.
//   3) URL shorteners           -> the redirect chain is followed to the final
//      destination and the intelligence is gathered for THAT domain, with the
//      shortener hop reported as well.
//
// Every lookup degrades gracefully: a failing provider returns null for its
// section instead of failing the whole check. The full suite runs in parallel.

import { parse as parseDomain } from 'tldts'

const HTTP_TIMEOUT_MS = 9000

// Free-hosting platforms that hand out subdomains to anyone. A phishing link
// living on one of these is almost always attacker-controlled.
const HOSTING_PLATFORMS = [
  { suffix: 'netlify.app', name: 'Netlify' },
  { suffix: 'vercel.app', name: 'Vercel' },
  { suffix: 'web.app', name: 'Firebase Hosting (Google)' },
  { suffix: 'firebaseapp.com', name: 'Firebase Hosting (Google)' },
  { suffix: 'onrender.com', name: 'Render' },
  { suffix: 'railway.app', name: 'Railway' },
  { suffix: 'herokuapp.com', name: 'Heroku' },
  { suffix: 'github.io', name: 'GitHub Pages' },
  { suffix: 'gitlab.io', name: 'GitLab Pages' },
  { suffix: 'pages.dev', name: 'Cloudflare Pages' },
  { suffix: 'workers.dev', name: 'Cloudflare Workers' },
  { suffix: 'surge.sh', name: 'Surge.sh' },
  { suffix: 'glitch.me', name: 'Glitch' },
  { suffix: 'repl.co', name: 'Replit' },
  { suffix: 'replit.app', name: 'Replit' },
  { suffix: 'pythonanywhere.com', name: 'PythonAnywhere' },
  { suffix: 'azurewebsites.net', name: 'Azure App Service' },
  { suffix: 'cloudfront.net', name: 'AWS CloudFront' },
  { suffix: 's3.amazonaws.com', name: 'AWS S3' },
  { suffix: 'storage.googleapis.com', name: 'Google Cloud Storage' },
  { suffix: 'firebasestorage.googleapis.com', name: 'Firebase Storage' },
  { suffix: 'fly.dev', name: 'Fly.io' },
  { suffix: 'deno.dev', name: 'Deno Deploy' },
  { suffix: 'koyeb.app', name: 'Koyeb' },
  { suffix: 'cyclic.app', name: 'Cyclic' },
  { suffix: 'ngrok-free.app', name: 'ngrok' },
  { suffix: 'ngrok.io', name: 'ngrok' },
  { suffix: 'wixsite.com', name: 'Wix' },
  { suffix: 'wordpress.com', name: 'WordPress.com' },
  { suffix: 'blogspot.com', name: 'Blogger (Google)' },
  { suffix: 'sites.google.com', name: 'Google Sites' },
  { suffix: 'iwopop.com', name: 'Freehostia' },
  { suffix: 'myfreesites.net', name: 'MyFreeSites' },
  { suffix: 'webador.com', name: 'Webador' },
]

// Known URL shorteners. If a link points to one of these we expand it before
// gathering intelligence so the verdict reflects the REAL destination.
const SHORTENERS = [
  { suffix: 'tinyurl.com', name: 'TinyURL' },
  { suffix: 'bit.ly', name: 'Bitly' },
  { suffix: 't.co', name: 'X / Twitter' },
  { suffix: 'goo.gl', name: 'Google URL Shortener' },
  { suffix: 'ow.ly', name: 'Hootsuite' },
  { suffix: 'is.gd', name: 'is.gd' },
  { suffix: 'cutt.ly', name: 'Cuttly' },
  { suffix: 'rebrand.ly', name: 'Rebrandly' },
  { suffix: 'shorturl.at', name: 'ShortURL' },
  { suffix: 'tiny.cc', name: 'TinyCC' },
  { suffix: 'rb.gy', name: 'Rebrandly' },
  { suffix: '1tk.us', name: '1tk.us' },
  { suffix: 'shor.by', name: 'ShorBy' },
  { suffix: 'ouo.io', name: 'Ouo.io' },
  { suffix: 'tny.sh', name: 'Tny.sh' },
  { suffix: 'vgd.me', name: 'v.gd / is.gd' },
  { suffix: 'u.to', name: 'u.to' },
  { suffix: 'zipline.io', name: 'Zipline' },
  { suffix: 's.id', name: 'Short.id' },
  { suffix: 'xurls.co', name: 'xurls' },
  { suffix: 'short.io', name: 'Short.io' },
  { suffix: 'linktr.ee', name: 'Linktree' },
  { suffix: 'gcp.click', name: 'Google Cloud Platform' },
  { suffix: 'dr.click', name: 'DR.click' },
]

const SINGLE_LABEL_TLDS = new Set([
  'app', 'io', 'co', 'me', 'dev', 'tech', 'xyz', 'site', 'online', 'store',
  'link', 'click', 'top', 'live', 'cloud', 'page', 'gq', 'tk', 'ml', 'ga',
  'cf', 'zip', 'mov', 'ai', 'sh', 'gl', 'gg', 'ly',
])

function matchList(hostname, list) {
  if (!hostname) return null
  for (const entry of list) {
    if (hostname === entry.suffix || hostname.endsWith('.' + entry.suffix)) {
      return entry
    }
  }
  return null
}

function parseHost(url) {
  try {
    const u = new URL(url)
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return null
    return u
  } catch {
    return null
  }
}

// Follow redirects (location chain) without downloading bodies, up to 6 hops.
async function resolveRedirects(url) {
  const MAX_HOPS = 6
  let current = url
  const chain = []
  for (let hop = 0; hop < MAX_HOPS; hop++) {
    let res
    try {
      res = await fetch(current, {
        method: 'GET',
        redirect: 'manual',
        headers: { 'user-agent': 'Mozilla/5.0 (SecurityScanner)' },
        signal: AbortSignal.timeout(HTTP_TIMEOUT_MS),
      })
    } catch {
      break
    }
    const location = (res.headers.get('location') || '').trim()
    if (![301, 302, 303, 307, 308].includes(res.status) || !location) {
      chain.push(current)
      break
    }
    chain.push(current)
    try {
      current = new URL(location, current).toString()
    } catch {
      break
    }
  }
  return { chain, final: current }
}

async function expandShortener(url) {
  const { final } = await resolveRedirects(url)
  if (final && final !== url) return final
  return null
}

// ---- Shortener resolution (shared with phishing.js) -------------------------

// Cache expansions so repeated checks of the same short link don't re-resolve.
const shortenerResolveCache = new Map()
const SHORTENER_RESOLVE_TTL_MS = 30 * 60 * 1000

// If `url` is a known shortener, resolve it to the real destination.
// Returns null when the url is NOT a shortener at all (fast path - no network).
// Returns { service, host, resolvedUrl, finalHost } when it is - resolvedUrl is
// null if the redirect couldn't be followed.
export async function resolveShortener(url) {
  let hostname = null
  try {
    hostname = new URL(url).hostname.toLowerCase()
  } catch {
    return null
  }
  const shortener = matchList(hostname, SHORTENERS)
  if (!shortener) return null

  const cachedHit = shortenerResolveCache.get(url)
  if (cachedHit && Date.now() - cachedHit.at < SHORTENER_RESOLVE_TTL_MS) return cachedHit.info

  const resolvedUrl = await expandShortener(url).catch(() => null)
  let finalHost = null
  if (resolvedUrl) {
    try {
      finalHost = new URL(resolvedUrl).hostname.toLowerCase()
    } catch {
      /* keep null */
    }
  }
  const info = { service: shortener.name, host: hostname, resolvedUrl, finalHost }
  shortenerResolveCache.set(url, { at: Date.now(), info })
  return info
}

// ---- Individual lookups ----------------------------------------------------

// WHOIS via who-dat first (clean JSON), falling back to RDAP via airat.top for
// domains who-dat rejects (e.g. foo.app where the suffix IS the domain).
async function lookupWhois(domain) {
  try {
    const res = await fetch(`https://who-dat.as93.net/${encodeURIComponent(domain)}`, {
      headers: { accept: 'application/json' },
      signal: AbortSignal.timeout(HTTP_TIMEOUT_MS),
    })
    if (res.ok) {
      const data = await res.json()
      if (data?.isRegistered !== false && data?.registrar) return { source: 'who-dat', data }
    }
  } catch {
    /* fall through to RDAP */
  }
  const rdapRes = await fetch(`https://whois.api.airat.top/?domain=${encodeURIComponent(domain)}`, {
    headers: { accept: 'application/json' },
    signal: AbortSignal.timeout(HTTP_TIMEOUT_MS),
  })
  if (!rdapRes.ok) throw new Error(`whois HTTP ${rdapRes.status}`)
  const rdap = await rdapRes.json()
  if (!rdap?.rdap?.registrar) return null
  return { source: 'rdap', data: rdap.rdap }
}

async function lookupDns(domain) {
  const res = await fetch(`https://networkcalc.com/api/dns/lookup/${encodeURIComponent(domain)}`, {
    headers: { accept: 'application/json' },
    signal: AbortSignal.timeout(HTTP_TIMEOUT_MS),
  })
  if (!res.ok) throw new Error(`dns HTTP ${res.status}`)
  const data = await res.json()
  return data?.records || data || null
}

async function lookupIpGeo(ip) {
  const res = await fetch(`https://ipwho.is/${encodeURIComponent(ip)}`, {
    headers: { accept: 'application/json' },
    signal: AbortSignal.timeout(HTTP_TIMEOUT_MS),
  })
  if (!res.ok) throw new Error(`geo HTTP ${res.status}`)
  const data = await res.json()
  return data?.success === false ? null : data
}

// SSL via crt.sh first, falling back to issued.live which bundles cert + WHOIS
// data. crt.sh returns the full cert history but can be flaky; issued.live is
// simple but reliable and provides the issuer / expiry we need.
async function lookupSsl(domain) {
  try {
    const res = await fetch(`https://crt.sh/?q=${encodeURIComponent(domain)}&output=json`, {
      headers: { accept: 'application/json', 'user-agent': 'Mozilla/5.0 (SIH Security Scanner)' },
      signal: AbortSignal.timeout(10000),
    })
    if (res.ok) {
      const data = await res.json()
      if (Array.isArray(data)) return data
    }
  } catch {
    /* fall through to issued.live */
  }
  const fallback = await fetch(`https://issued.live/${encodeURIComponent(domain)}`, {
    headers: { accept: 'application/json' },
    signal: AbortSignal.timeout(HTTP_TIMEOUT_MS),
  })
  if (!fallback.ok) return null
  const issued = await fallback.json()
  // Map issued.live shape into a crt.sh-like array the frontend can process.
  if (!issued?.ssl_issuer) return null
  return [
    {
      issuer_name: issued.ssl_issuer,
      common_name: issued.domain,
      not_before: issued.registered || null,
      not_after: issued.ssl_expires || null,
      entry_timestamp: issued.last_update || null,
    },
  ]
}

// Threat-list reputation via PhishDestroy (no auth).
async function lookupThreat(domain) {
  const res = await fetch(`https://api.destroy.tools/v1/check?domain=${encodeURIComponent(domain)}`, {
    headers: { accept: 'application/json' },
    signal: AbortSignal.timeout(HTTP_TIMEOUT_MS),
  })
  if (!res.ok) throw new Error(`phishdestroy HTTP ${res.status}`)
  return res.json()
}

async function lookupReverseIp(ip) {
  const res = await fetch(`https://api.hackertarget.com/reverseiplookup/?q=${encodeURIComponent(ip)}`, {
    headers: { accept: 'text/plain' },
    signal: AbortSignal.timeout(HTTP_TIMEOUT_MS),
  })
  if (!res.ok) throw new Error(`reverseip HTTP ${res.status}`)
  const text = (await res.text()).trim()
  if (!text || /API count exceeded|error/i.test(text) || !text.includes('.')) return null
  return text.split('\n').map((s) => s.trim()).filter((s) => s).slice(0, 15)
}

// ---- Aggregation -----------------------------------------------------------

function cleanDate(v) {
  if (!v) return null
  const s = String(v)
  return s.length >= 10 ? s.slice(0, 10) : null
}

function domainAgeDays(createdIso) {
  if (!createdIso) return null
  const t = new Date(createdIso).getTime()
  if (!Number.isFinite(t)) return null
  return Math.max(0, Math.floor((Date.now() - t) / (1000 * 60 * 60 * 24)))
}

// Shape WHOIS into a compact viewModel. Handles who-dat's flat format AND the
// RDAP shape returned by airat.top.
function shapeWhois(entry) {
  if (!entry?.data) return null
  const d = entry.data

  let registrar = null
  let created = null
  let updated = null
  let expires = null
  let nameservers = null
  let status = null
  let registrant = null

  if (entry.source === 'who-dat') {
    registrar = d?.registrar?.name || d?.registrar || null
    created = d?.dates?.created || d?.creation_date || d?.created_date || null
    updated = d?.dates?.updated || d?.updated_date || null
    expires = d?.dates?.expires || d?.expiration_date || d?.registry_expiry_date || null
    nameservers = Array.isArray(d?.nameservers)
      ? d.nameservers.map((n) => (typeof n === 'string' ? n.toLowerCase().replace(/\.$/, '') : n?.name?.toLowerCase().replace(/\.$/, ''))).filter(Boolean)
      : null
    status = Array.isArray(d?.status) ? d.status : d?.status ? [String(d.status)] : null
    // who-dat hides PII by default
  } else {
    // RDAP
    registrar = d?.registrar?.name || null
    created = d?.events?.registration || d?.events?.created || null
    updated = d?.events?.lastChanged || d?.events?.lastUpdate || null
    expires = d?.events?.expiration || d?.events?.expires || null
    nameservers = Array.isArray(d?.nameservers)
      ? d.nameservers.map((n) => String(n).toLowerCase().replace(/\.$/, ''))
      : null
    status = Array.isArray(d?.status) ? d.status : d?.status ? [String(d.status)] : null
    registrant = null
  }

  return {
    registrar,
    registrant,
    created: cleanDate(created),
    updated: cleanDate(updated),
    expires: cleanDate(expires),
    domainAgeDays: domainAgeDays(created),
    nameservers: nameservers && nameservers.length > 0 ? nameservers.slice(0, 8) : null,
    status: status && status.length > 0 ? status.slice(0, 6) : null,
  }
}

function shapeDns(raw) {
  if (!raw) return null
  // networkcalc returns records as an object: {A:[{address,ttl}], MX:[...], ...}
  const src = raw?.records || raw
  const a = []
  const aaaa = []
  const mx = []
  const ns = []
  const txt = []
  const cname = []
  const push = (arr, v) => {
    if (v && !arr.includes(String(v))) arr.push(String(v))
  }
  for (const [type, list] of Object.entries(src)) {
    if (!Array.isArray(list)) continue
    const key = type.toUpperCase()
    for (const r of list) {
      if (key === 'A') push(a, r.address || r.answer || r.value)
      else if (key === 'AAAA') push(aaaa, r.address || r.answer || r.value)
      else if (key === 'MX') push(mx, r.exchange || r.address || r.answer)
      else if (key === 'NS') push(ns, r.nameserver || r.nameserver_name || r.value)
      else if (key === 'TXT') push(txt, r.value || r.txt || r.data)
      else if (key === 'CNAME') push(cname, r.alias || r.target || r.value)
    }
  }
  return { a, aaaa, mx, ns, txt: txt.slice(0, 5), cname }
}

function pickIpv4(dns) {
  if (!dns?.a || dns.a.length === 0) return null
  const pub = dns.a.find((ip) => {
    const parts = ip.split('.').map(Number)
    if (parts.length !== 4) return false
    if (parts[0] === 10 || parts[0] === 127) return false
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return false
    if (parts[0] === 192 && parts[1] === 168) return false
    return true
  })
  return pub || dns.a[0]
}

function shapeThreat(raw) {
  if (!raw) return null
  return {
    listed: Boolean(raw?.threat),
    message: raw?.message || null,
    note: raw?.note || null,
    checkedAt: raw?.checked_at || null,
    riskScore: Number.isFinite(Number(raw?.risk_score)) ? Number(raw.risk_score) : null,
  }
}

function groupCerts(certs) {
  if (!Array.isArray(certs) || certs.length === 0) return null
  const now = new Date()
  const valid = certs.filter((c) => c?.not_after && new Date(c.not_after) > now)
  const latest = valid.sort((x, y) => new Date(y.not_after) - new Date(x.not_after))[0] || certs[0]
  return {
    count: certs.length,
    issuer: latest?.issuer_name || null,
    commonName: latest?.common_name || null,
    notBefore: latest?.not_before?.slice(0, 10) || null,
    notAfter: latest?.not_after?.slice(0, 10) || null,
    firstSeen: latest?.entry_timestamp?.slice(0, 10) || null,
    daysLeft: latest?.not_after
      ? Math.max(0, Math.floor((new Date(latest.not_after) - now) / (1000 * 60 * 60 * 24)))
      : null,
  }
}

// ---- Main entry point ------------------------------------------------------

const intelCache = new Map()
const INTEL_CACHE_TTL_MS = 2 * 60 * 60 * 1000

async function gatherIntelForUrl(url) {
  const parsed = parseHost(url)
  if (!parsed) return null

  const hostname = parsed.hostname.toLowerCase()

  // --- was the ORIGINAL link a shortener? resolve to the real destination ---
  const shortenerInfo = await resolveShortener(url)
  let targetHostname = hostname
  let shortener = null
  if (shortenerInfo) {
    shortener = {
      service: shortenerInfo.service,
      host: shortenerInfo.host,
      finalUrl: shortenerInfo.resolvedUrl,
      finalHost: shortenerInfo.finalHost,
    }
    if (shortenerInfo.resolvedUrl && shortenerInfo.finalHost) {
      targetHostname = shortenerInfo.finalHost
    }
  }

  // --- parse the destination host ------------------------------------------
  const targetParsed = parseDomain(targetHostname)
  const registrableDomain = targetParsed.domain || targetParsed.hostname
  const subdomain = targetParsed.subdomain || null
  const isSubdomain = Boolean(subdomain)

  // --- hosting platform + tiny-TLD awareness -------------------------------
  const hostPlatform = matchList(registrableDomain, HOSTING_PLATFORMS)
  const tinyTld =
    SINGLE_LABEL_TLDS.has((targetParsed.publicSuffix || '').toLowerCase()) ||
    (targetParsed.publicSuffix === '' && String(targetParsed.hostname.split('.').pop()).length <= 2)

  // Cache the expensive lookups keyed by registrable domain.
  const cached = intelCache.get(registrableDomain)
  if (cached && Date.now() - cached.at < INTEL_CACHE_TTL_MS) {
    return {
      hostname,
      finalHost: targetHostname,
      registrableDomain,
      subdomain,
      isSubdomain,
      hosting: hostPlatform
        ? { platform: hostPlatform.name, suffix: hostPlatform.suffix, note: 'Free subdomain hosting - anyone can host content here' }
        : null,
      tinyTld: tinyTld || null,
      shortener,
      ...cached.data,
    }
  }

  // Every lookup fires in parallel. DNS is resolved first so geo + reverse-IP
  // reuse the same resolved address, but geo/reverse never block the bundle.
  let dnsResult = null
  const dnsPromise = lookupDns(registrableDomain)
    .then((d) => {
      dnsResult = shapeDns(d)
      return dnsResult
    })
    .catch((e) => {
      console.warn(`[domainIntel] DNS failed for ${registrableDomain}: ${e.message}`)
      return null
    })

  const tasks = {
    dns: dnsPromise,
    whois: lookupWhois(registrableDomain).then(shapeWhois).catch((e) => {
      console.warn(`[domainIntel] WHOIS failed for ${registrableDomain}: ${e.message}`)
      return null
    }),
    ssl: lookupSsl(registrableDomain).then(groupCerts).catch((e) => {
      console.warn(`[domainIntel] SSL failed for ${registrableDomain}: ${e.message}`)
      return null
    }),
    threat: lookupThreat(registrableDomain).then(shapeThreat).catch((e) => {
      console.warn(`[domainIntel] Threat-list failed for ${registrableDomain}: ${e.message}`)
      return null
    }),
  }

  const geoPromise = dnsPromise.then(async () => {
    const ip = dnsResult ? pickIpv4(dnsResult) : null
    if (!ip) return { ip: null, details: null }
    const details = await lookupIpGeo(ip).catch((e) => {
      console.warn(`[domainIntel] Geo failed for ${ip}: ${e.message}`)
      return null
    })
    return { ip, details }
  })

  const reversePromise = dnsPromise.then(async () => {
    const ip = dnsResult ? pickIpv4(dnsResult) : null
    if (!ip) return { ip: null, domains: null }
    const domains = await lookupReverseIp(ip).catch((e) => {
      console.warn(`[domainIntel] Reverse-IP failed for ${ip}: ${e.message}`)
      return null
    })
    return { ip, domains }
  })

  const [dns, whois, ssl, threat, geoRes, reverseRes] = await Promise.all([
    dnsPromise,
    tasks.whois,
    tasks.ssl,
    tasks.threat,
    geoPromise,
    reversePromise,
  ])

  const data = {
    whois,
    dns,
    geo: geoRes,
    reverseIp: reverseRes,
    threat,
    ssl,
  }

  intelCache.set(registrableDomain, { at: Date.now(), data })

  return {
    hostname,
    finalHost: targetHostname,
    registrableDomain,
    subdomain,
    isSubdomain,
    hosting: hostPlatform
      ? { platform: hostPlatform.name, suffix: hostPlatform.suffix, note: 'Free subdomain hosting - anyone can host content here' }
      : null,
    tinyTld: tinyTld || null,
    shortener,
    ...data,
  }
}

export async function getDomainIntel(url) {
  try {
    return await gatherIntelForUrl(url)
  } catch (e) {
    console.warn(`[domainIntel] lookup failed for ${url}: ${e.message}`)
    return null
  }
}

export default getDomainIntel