// Hybrid Analysis (Falcon Sandbox) phishing URL check service.
// Flow per URL: 1) free hash-based lookup in the detonation DB, 2) if nothing
// conclusive, submit a quick scan and poll until finished.
// Never throws on provider failures - returns unknown verdict so the app keeps working.

import { getDomainIntel, resolveShortener } from './domainIntel.js'

const BASE_URL = 'https://hybrid-analysis.com/api/v2'
const API_KEY = process.env.HYBRIDANALYSIS_API_KEY || ''

const MAX_LINKS = 20
const MAX_CONCURRENCY = 4
const QUICK_SCAN_POLL_INTERVAL_MS = 4000
const QUICK_SCAN_MAX_WAIT_MS = 90000
// Give the free DB lookups this head start before spending a quick-scan
// submission. Known URLs resolve in <3s, so no quota is wasted on them.
const QUICK_SCAN_GRACE_MS = 3000

// Gmail/Google-owned infrastructure hosts are always safe to open, never
// flagged by scanners, and just slow the check down - skip them entirely:
// they are excluded from the reported links so "Links in this email" only
// contains URLs the user actually needs to care about.
const TRUSTED_INFRA_DOMAINS = ['googleusercontent.com', 'gmail.com', 'googlemail.com']

function isTrustedInfraHost(hostname) {
  if (!hostname) return false
  return TRUSTED_INFRA_DOMAINS.some((d) => hostname === d || hostname.endsWith('.' + d))
}

// In-memory cache: url -> { verdict, threatScore, checkedAt }
const cache = new Map()
const CACHE_TTL_MS = 30 * 60 * 1000
// Domain-level cache so multiple new URLs of the same domain share one scan
// result and don't burn the 2-scans/hour/domain allowance.
const domainCache = new Map()
const DOMAIN_CACHE_TTL_MS = 2 * 60 * 60 * 1000

function hostOf(url) {
  try {
    return new URL(url).hostname
  } catch {
    return null
  }
}

function apiHeaders() {
  return {
    'accept': 'application/json',
    'api-key': API_KEY,
    'user-agent': 'Falcon Sandbox',
  }
}

const SEVERITY_RANK = { safe: 0, unknown: 1, suspicious: 2, malicious: 3 }
function severityRankOf(r) {
  return r ? SEVERITY_RANK[r.verdict] ?? 0 : 0
}

// Normalize the string verdicts returned by DB lookups.
function verdictFromString(str) {
  switch ((str || '').trim().toLowerCase()) {
    case 'malicious':
    case 'high':
    case 'danger':
      return { verdict: 'malicious', label: 'Malicious' }
    case 'suspicious':
    case 'medium':
      return { verdict: 'suspicious', label: 'Suspicious' }
    case 'whitelisted':
    case 'no specific threat':
    case 'clean':
    case 'low':
      return { verdict: 'safe', label: str }
    default:
      return null
  }
}

function extractUrls(html) {
  if (!html) return []
  const found = new Set()
  // href="..." in HTML
  const hrefRe = /href\s*=\s*["']([^"']+)["']/gi
  // bare http(s):// URLs in text
  const bareRe = /https?:\/\/[^\s<>"']+/g

  let m
  while ((m = hrefRe.exec(html)) !== null) {
    found.add(m[1])
  }
  while ((m = bareRe.exec(html)) !== null) {
    found.add(m[0])
  }

  const clean = (u) => {
    try {
      const parsed = new URL(u)
      // only http/https protocols matter
      if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return null
      // drop tracking fragments like #section - keep path+query
      parsed.hash = ''
      parsed.username = ''
      parsed.password = ''
      return parsed.toString()
    } catch {
      return null
    }
  }

  const cleaned = []
  for (const u of found) {
    const c = clean(u)
    if (c && !cleaned.includes(c)) cleaned.push(c)
    if (cleaned.length >= MAX_LINKS) break
  }
  return cleaned
}

// Step 1: determine the SHA256 Hybrid Analysis computes for a given URL.
async function getUrlHash(url) {
  const res = await fetch(`${BASE_URL}/submit/hash-for-url`, {
    method: 'POST',
    headers: { ...apiHeaders(), 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ url }).toString(),
    signal: AbortSignal.timeout(25000),
  })
  if (!res.ok) throw new Error(`hash-for-url failed: ${res.status}`)
  return res.json()
}

// Step 2: free DB lookup - returns reports that already detonated this URL hash.
// A brand-new URL has no reports yet and the API answers 404 -> treat as empty.
async function searchByHash(sha256) {
  const res = await fetch(`${BASE_URL}/search/hash?hash=${encodeURIComponent(sha256)}`, {
    method: 'GET',
    headers: apiHeaders(),
    signal: AbortSignal.timeout(25000),
  })
  if (res.status === 404) return { reports: [] }
  if (!res.ok) throw new Error(`search/hash failed: ${res.status}`)
  return res.json()
}

// Combine DB report verdicts into one result.
// Historical detonations are noisy: google.com carries old (2020-21) malicious
// reports that no longer reflect reality. So there are TWO windows:
//   - FRESH (2yr): recent real-world evidence. Trust flags only when they
//     outnumber clean reports in this window; a flag-free but clean window
//     means the domain checks out TODAY.
//   - LONG (5yr): used only when the fresh window has no data at all.
// Mixed/unclear data falls through to heuristics and then a live quick scan.
const FRESH_WINDOW_SECONDS = 2 * 365 * 24 * 60 * 60
const LONG_WINDOW_SECONDS = 5 * 365 * 24 * 60 * 60

function tsOfId(id) {
  if (!/^[0-9a-f]{24}$/i.test(id)) return null
  const ts = parseInt(id.slice(0, 8), 16)
  return Number.isFinite(ts) ? ts : null
}

function idIsWithin(id, seconds, nowSeconds) {
  const ts = tsOfId(id)
  return ts !== null && nowSeconds - ts <= seconds
}

function countVerdicts(reports, nowSeconds, windowSeconds) {
  const out = { malicious: 0, suspicious: 0, safe: 0, total: 0 }
  for (const rep of reports) {
    if (rep.state !== 'SUCCESS' || !rep.verdict) continue
    if (!idIsWithin(rep.id, windowSeconds, nowSeconds)) continue
    const mapped = verdictFromString(rep.verdict)
    if (!mapped) continue
    out.total += 1
    if (mapped.verdict === 'malicious') out.malicious += 1
    else if (mapped.verdict === 'suspicious') out.suspicious += 1
    else out.safe += 1
  }
  return out
}

function resolveVerdictFromCounts(fresh, long) {
  // Fresh (last 2 years) evidence is what the domain looks like TODAY.
  if (fresh.total > 0) {
    if (fresh.malicious > 0 && fresh.malicious >= fresh.safe) {
      return { verdict: 'malicious', label: 'Malicious', threatScore: 80, source: 'db' }
    }
    if (fresh.suspicious > 0 && fresh.suspicious >= fresh.safe) {
      return { verdict: 'suspicious', label: 'Suspicious', threatScore: 50, source: 'db' }
    }
    if (fresh.malicious === 0 && fresh.suspicious === 0) {
      return { verdict: 'safe', label: 'No specific threat', threatScore: 0, source: 'db' }
    }
    // Mixed fresh evidence -> let heuristics/quick-scan decide.
    return null
  }
  // No fresh data at all (domain not detonated recently). Fall back to the
  // longer window, but only when a flag decisively dominates (safe reports
  // from the same window prove the domain is/was legitimate).
  if (long.total === 0) return null
  if (long.safe > 0) {
    // Mixed signals: safe and malicious/suspicious both present -> ambiguous,
    // let heuristics or quick-scan decide. Old false-positive flags on brand
    // domains (paypal.com "suspicious" in 2023 + "safe" in 2023) stay null.
    return null
  }
  if (long.malicious > 0) {
    return { verdict: 'malicious', label: 'Malicious', threatScore: 80, source: 'db' }
  }
  if (long.suspicious > 0) {
    return { verdict: 'suspicious', label: 'Suspicious', threatScore: 50, source: 'db' }
  }
  return null
}

function aggregateSearch(searchData) {
  const reports = searchData?.reports || []
  const nowSeconds = Math.floor(Date.now() / 1000)
  const fresh = countVerdicts(reports, nowSeconds, FRESH_WINDOW_SECONDS)
  const long = countVerdicts(reports, nowSeconds, LONG_WINDOW_SECONDS)
  return resolveVerdictFromCounts(fresh, long)
}

// Step 3: free text search - exact URL match in the submitted-samples DB.
// Unlike search/hash this does not require prior detonation of the URL hash,
// and it is a search (not a submission) so it is never blocked by the
// per-domain quick-scan quota. A result with verdict "malicious" for the exact
// URL is the strongest available signal.
async function searchByTerms(url) {
  const res = await fetch(`${BASE_URL}/search/terms`, {
    method: 'POST',
    headers: { ...apiHeaders(), 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ url }).toString(),
    signal: AbortSignal.timeout(25000),
  })
  if (!res.ok) throw new Error(`search/terms failed: ${res.status}`)
  return res.json()
}

function isRecentTime(iso, nowSeconds, windowSeconds) {
  if (!iso) return false
  const ts = new Date(iso).getTime() / 1000
  if (!Number.isFinite(ts)) return false
  return nowSeconds - ts <= windowSeconds
}

// Exact-URL record aggregation. Only records whose submit_name IS this URL
// count; verdicts use the same dual (fresh/long) window rule as search/hash so
// legit domains (google.com) stay clean.
function aggregateSearchTerms(data, url) {
  const results = data?.result || []
  const nowSeconds = Math.floor(Date.now() / 1000)
  const normUrl = (u) => {
    try {
      return new URL(u).toString()
    } catch {
      return u
    }
  }
  const target = normUrl(url)
  const exact = results.filter(
    (r) => r.verdict && r.submit_name && normUrl(r.submit_name) === target
  )

  const tallyExact = (windowSeconds) => {
    const out = { malicious: 0, suspicious: 0, safe: 0, total: 0 }
    for (const rep of exact) {
      if (!isRecentTime(rep.analysis_start_time, nowSeconds, windowSeconds)) continue
      const mapped = verdictFromString(rep.verdict)
      if (!mapped) continue
      out.total += 1
      if (mapped.verdict === 'malicious') out.malicious += 1
      else if (mapped.verdict === 'suspicious') out.suspicious += 1
      else out.safe += 1
    }
    return out
  }

  const fresh = tallyExact(FRESH_WINDOW_SECONDS)
  const long = tallyExact(LONG_WINDOW_SECONDS)
  if (fresh.malicious > 0 && fresh.malicious >= fresh.safe) {
    return { verdict: 'malicious', label: 'Malicious', threatScore: 85, source: 'db' }
  }
  if (fresh.suspicious > 0 && fresh.suspicious >= fresh.safe) {
    return { verdict: 'suspicious', label: 'Suspicious', threatScore: 50, source: 'db' }
  }
  if (fresh.total > 0 && fresh.malicious === 0 && fresh.suspicious === 0) {
    return { verdict: 'safe', label: 'No specific threat', threatScore: 0, source: 'db' }
  }
  // No fresh data: only trust a long-window flag when clean reports are absent
  // (mixed signals are old false positives on legitimate domains).
  if (long.safe > 0) return null
  if (long.malicious > 0) {
    return { verdict: 'malicious', label: 'Malicious', threatScore: 85, source: 'db' }
  }
  if (long.suspicious > 0) {
    return { verdict: 'suspicious', label: 'Suspicious', threatScore: 50, source: 'db' }
  }
  return null
}

// Submit a URL for quick scan. Returns the scan response (id + scanners_v2).
async function submitQuickScan(url) {
  const res = await fetch(`${BASE_URL}/quick-scan/url`, {
    method: 'POST',
    headers: { ...apiHeaders(), 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ url, scan_type: 'all' }).toString(),
    signal: AbortSignal.timeout(25000),
  })
  if (!res.ok) throw new Error(`quick-scan submit failed: ${res.status}`)
  return res.json()
}

// Poll a quick scan until finished (or until the overall deadline expires).
async function pollQuickScan(scanId) {
  const deadline = Date.now() + QUICK_SCAN_MAX_WAIT_MS
  while (Date.now() < deadline) {
    const res = await fetch(`${BASE_URL}/quick-scan/${encodeURIComponent(scanId)}`, {
      method: 'GET',
      headers: apiHeaders(),
      signal: AbortSignal.timeout(25000),
    })
    if (!res.ok) throw new Error(`quick-scan status failed: ${res.status}`)
    const data = await res.json()
    if (data.finished === true) return data
    await new Promise((r) => setTimeout(r, QUICK_SCAN_POLL_INTERVAL_MS))
  }
  return { finished: false, verdict_human: 'unknown' }
}

// Combine per-scanner statuses from scanners_v2 into one verdict.
// A single noisy scanner ("suspicious") surrounded by clean results is treated
// as clean to avoid false positives on legitimate domains (google.com showed
// clean_dns=suspicious + 4 clean). A genuine phishing page produced
// clean_dns=suspicious + scam_adviser=unsure alongside a couple of clean
// scanners, so weak signals (suspicious/unsure) are weighed against clean ones.
function aggregateQuickScan(scanData) {
  const scanners = scanData?.scanners_v2 || {}
  const statuses = []
  const percents = []
  for (const s of Object.values(scanners)) {
    if (!s || !s.status) continue
    statuses.push(String(s.status).toLowerCase())
    const p = Number(s.percent)
    if (Number.isFinite(p) && p > 0) percents.push(p)
  }
  if (statuses.length === 0) return null

  const count = (val) => statuses.filter((s) => s === val).length
  const malicious = count('malicious')
  const weakSignals = count('suspicious') + count('unsure')
  const cleanSignals = count('clean') + count('whitelisted')

  if (malicious > 0) {
    return { verdict: 'malicious', label: 'Malicious', threatScore: 90, source: 'quick-scan' }
  }
  // Phishing test page: clean_dns=suspicious + scam_adviser=unsure vs 2 clean
  if (weakSignals > 0 && weakSignals >= cleanSignals) {
    const threatScore = percents.length > 0 ? Math.max(...percents) : 50
    return { verdict: 'suspicious', label: 'Suspicious', threatScore, source: 'quick-scan' }
  }
  if (cleanSignals > 0) return { verdict: 'safe', label: 'Clean', threatScore: 0, source: 'quick-scan' }
  return null
}

// Structural/phishing heuristics that need NO external API: raw-IP hosting,
// unusual ports and tell-tale page paths are statistical dead-ratings on their
// own, but together they flag pages HA either has no record of or cannot reach
// (HA quick-scan returned 400 "domain does not exist" for IP-hosted URLs).
// Kept conservative so legit domains never trip it.
const PHISHY_PATH_FRAGMENTS = [
  'reportviewer.aspx',
  'files.php',
  'master.php',
  'invoice.php',
  'tracking.php',
  'update-account',
  'updateaccount',
  'login.php',
  'signin.php',
  'verify.php',
  'confirm.php',
  'billing.php',
  'payment.php',
  'banking',
  'webscr',
  'secure-login',
  'account-verify',
  'password-reset',
]
const RAW_IP_RE = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/

function heuristicVerdict(url) {
  try {
    const parsed = new URL(url)
    const host = parsed.hostname

    const rawIp = RAW_IP_RE.test(host)
    const unusualPort = Boolean(parsed.port) && parsed.port !== '80' && parsed.port !== '443'
    const noHttps = parsed.protocol !== 'https:'
    const pathLower = parsed.pathname.toLowerCase()
    const phishyPath = PHISHY_PATH_FRAGMENTS.some((p) => pathLower.includes(p))
    // Obfuscation: heavily percent-encoded values in the query or path.
    const encodedQuery = (parsed.pathname + parsed.search).match(/%[0-9a-f]{2}/gi) || []
    const heavyEncoding = encodedQuery.length >= 2

    let score = 0
    if (rawIp) score += 3
    if (unusualPort) score += 2
    if (phishyPath) score += 2
    if (rawIp && noHttps) score += 1
    if (heavyEncoding) score += 1
    // Raw-IP + port is overwhelmingly hosting-rogue content.
    if (rawIp && unusualPort) score += 2

    if (score >= 6) return { verdict: 'malicious', label: 'Malicious', threatScore: 85, source: 'heuristic' }
    if (score >= 4) return { verdict: 'suspicious', label: 'Suspicious', threatScore: 60, source: 'heuristic' }
  } catch {
    // unparseable URL - never guessed
  }
  return null
}

// Full check pipeline for a single URL: every source runs in PARALLEL so the
// answer arrives as soon as the fastest conclusive source reports.
async function checkUrl(url) {
  // Resolve URL shorteners (tinyurl, bit.ly, ...) to the REAL destination first.
  // Two different short links share the shortener host but point at different
  // content, so without this the per-host domain cache would give them all the
  // same verdict and the check would run against the redirect host instead of
  // the actual page. The verdict therefore reflects what the link really opens.
  const shortenerInfo = await resolveShortener(url)
  const targetUrl = shortenerInfo?.resolvedUrl || url

  const cached = cache.get(targetUrl)
  if (cached && Date.now() - cached.checkedAt < CACHE_TTL_MS) {
    return { url, ...(shortenerInfo && shortenerInfo.resolvedUrl ? { shortener: shortenerInfo } : {}), ...cached }
  }

  // Same-domain reuse: if we already scanned the host recently, share its verdict.
  // For short links the target host is the resolved destination, so two links
  // that resolve to the same real domain share a scan - but different targets
  // are scanned independently.
  const host = hostOf(targetUrl)
  const hostHit = host && domainCache.get(host)
  if (hostHit && Date.now() - hostHit.checkedAt < DOMAIN_CACHE_TTL_MS) {
    cache.set(targetUrl, { ...hostHit, checkedAt: Date.now() })
    return {
      url,
      ...(shortenerInfo && shortenerInfo.resolvedUrl ? { shortener: shortenerInfo } : {}),
      verdict: hostHit.verdict,
      label: hostHit.label,
      threatScore: hostHit.threatScore,
      source: hostHit.source,
    }
  }

  const defaultResult = { verdict: 'unknown', label: 'No verdict', threatScore: null, source: null }
  const isConclusive = (r) => Boolean(r) && r.verdict !== 'unknown'

  // Kick off every source immediately: two free DB lookups plus the on-demand
  // quick scan. All three run at the same time; the first conclusive result wins.
  const dbTask = (async () => {
    try {
      const hashData = await getUrlHash(targetUrl)
      if (hashData?.sha256) {
        const searchData = await searchByHash(hashData.sha256)
        return aggregateSearch(searchData)
      }
    } catch (dbErr) {
      console.warn(`Hybrid DB lookup failed for ${targetUrl}: ${dbErr.message}`)
    }
    return null
  })()

  const termsTask = (async () => {
    try {
      const termsData = await searchByTerms(targetUrl)
      return aggregateSearchTerms(termsData, targetUrl)
    } catch (termsErr) {
      console.warn(`Hybrid search/terms failed for ${targetUrl}: ${termsErr.message}`)
      return null
    }
  })()

  // The quick scan is a scarce resource (per-domain quota), so it waits a short
  // grace period for the free DB lookups to answer. If they stay silent it
  // starts immediately - never waiting on slow DB timeouts.
  const scanTask = (async () => {
    const early = await Promise.race([
      dbTask.then((r) => (isConclusive(r) ? 'db' : null)),
      termsTask.then((r) => (isConclusive(r) ? 'terms' : null)),
      new Promise((resolve) => setTimeout(() => resolve('timeout'), QUICK_SCAN_GRACE_MS)),
    ])
    if (early) return null // DB answered first - don't burn scan quota
    try {
      const submitRes = await submitQuickScan(targetUrl)
      const scanId = submitRes.id || submitRes.scan_id
      if (scanId) {
        const scanData = await pollQuickScan(scanId)
        return aggregateQuickScan(scanData)
      }
    } catch (scanErr) {
      console.warn(`Hybrid quick-scan failed for ${targetUrl}: ${scanErr.message}`)
    }
    return null
  })()

  // Resolve the moment a conclusive answer exists - a fast DB hit must not be
  // held hostage by a still-running sandbox scan (and vice versa).
  const result = await new Promise((resolve) => {
    let done = false
    const finish = (r) => {
      if (!done) {
        done = true
        resolve(r)
      }
    }

    dbTask
      .then(async (dbResult) => {
        const termsResult = await termsTask
        const best = [dbResult, termsResult]
          .filter(isConclusive)
          .sort((a, b) => (severityRankOf(b) || 0) - (severityRankOf(a) || 0))[0]
        if (best) return finish(best)
        // Both DB routes silent - wait on the sandbox scan already in flight.
        scanTask.then((scanResult) => finish(scanResult || defaultResult))
      })
      .catch(() => finish(defaultResult))
  })

  // Structural heuristics are the safety net whenever the external providers
  // stay silent (fresh IP-hosted URLs, or while HA quick-scan is unavailable).
  // They only ever upgrade an unknown verdict, never downgrade a real flag.
  let finalResult = result
  if (!isConclusive(result)) {
    const heuristic = heuristicVerdict(targetUrl)
    if (heuristic) finalResult = heuristic
  }

  cache.set(targetUrl, { ...finalResult, checkedAt: Date.now() })
  if (host) domainCache.set(host, { ...finalResult, checkedAt: Date.now() })

  const out = { url, ...finalResult }
  // Keep the original short URL visible so the UI can show "shortened link".
  if (shortenerInfo && shortenerInfo.resolvedUrl) {
    out.shortener = shortenerInfo
    out.targetUrl = targetUrl
  }
  return out
}

// Run an async fn over items with a bounded number of in-flight workers.
async function mapConcurrently(items, limit, fn) {
  const results = new Array(items.length)
  let cursor = 0
  async function worker() {
    while (cursor < items.length) {
      const idx = cursor++
      results[idx] = await fn(items[idx])
    }
  }
  const workers = Array.from({ length: Math.min(limit, items.length) }, () => worker())
  await Promise.all(workers)
  return results
}

// Extract links from an email body and check each one
export async function checkEmailLinks(emailHtml) {
  const allUrls = extractUrls(emailHtml)
  // Drop Gmail/Google infrastructure URLs (signature images, etc.) - they are
  // always safe and don't belong in the "links to verify" list.
  const urls = allUrls.filter((u) => !isTrustedInfraHost(hostOf(u)))
  if (urls.length === 0) {
    return { links: [], summary: { verdict: 'safe', count: 0, highestSeverity: 'safe' } }
  }
  const checked = await mapConcurrently(urls, MAX_CONCURRENCY, (url) => checkUrl(url))
  const results = checked.filter(Boolean)

  // Domain intelligence is expensive (up to 6 external lookups per domain), so
  // it is only fetched for links that actually look dangerous. Links flagged
  // malicious or suspicious share a domain -> lookup once, apply to all.
  // Short links are grouped by their REAL target host so two different short
  // links that resolve to different pages each get their own intelligence.
  const flagged = results.filter((r) => r.verdict === 'malicious' || r.verdict === 'suspicious')
  if (flagged.length > 0) {
    const byHost = new Map()
    for (const link of flagged) {
      const key = hostOf(link.targetUrl || link.url)
      if (!key) continue
      if (!byHost.has(key)) byHost.set(key, [])
      byHost.get(key).push(link)
    }
    await Promise.all(
      [...byHost.values()].map(async (group) => {
        const sample = group[0].url
        const intel = await getDomainIntel(sample).catch(() => null)
        for (const link of group) link.domainIntel = intel
      })
    )
  }

  const severityRank = { safe: 0, unknown: 1, suspicious: 2, malicious: 3 }
  let highest = 'safe'
  for (const r of results) {
    const rank = severityRank[r.verdict] ?? 0
    if (rank > (severityRank[highest] ?? 0)) highest = r.verdict
  }

  const counts = results.reduce((acc, r) => {
    acc[r.verdict] = (acc[r.verdict] || 0) + 1
    return acc
  }, {})

  return {
    links: results,
    summary: {
      verdict: highest,
      count: results.length,
      highestSeverity: highest,
      counts,
    },
  }
}

export default checkEmailLinks