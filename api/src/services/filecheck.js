// Hybrid Analysis (Falcon Sandbox) file / attachment protection service.
// Flow per file: 1) hash the attachment bytes (sha256), 2) free DB lookup of
// that hash, 3) if the file was never analyzed, apply a type/extension
// heuristic so executable and macro-capable files are flagged even when their
// exact hash is unknown to the threat DB.
// Never throws on provider failures - returns an unknown verdict so the app
// keeps working (same contract as the URL scanner).

import { createHash } from 'node:crypto'

const BASE_URL = 'https://hybrid-analysis.com/api/v2'
const API_KEY = process.env.HYBRIDANALYSIS_API_KEY || ''

const MAX_ATTACHMENTS = 10
const MAX_FILE_BYTES = 25 * 1024 * 1024
const MAX_CONCURRENCY = 4

// A report is recent when its id timestamp (first 8 hex chars, unix seconds)
// falls inside this window - same rule as the URL scanner.
const RECENT_WINDOW_SECONDS = 2 * 365 * 24 * 60 * 60

// File types that can execute code or load malware on open. When the file
// hash is unknown to the DB these are flagged suspicious rather than safe.
const HIGH_RISK_EXTENSIONS = new Set([
  'exe', 'dll', 'bat', 'cmd', 'com', 'scr', 'js', 'jse', 'vbs', 'vbe',
  'wsf', 'wsh', 'ps1', 'ps2', 'psc1', 'msi', 'msp', 'msu', 'lnk', 'pif',
  'cpl', 'jar', 'hta', 'gadget', 'ocx', 'sys', 'drv', 'vhd', 'vhdx', 'iso',
  'app', 'deb', 'rpm',
])

// Documents that support embedded macros - a common phishing carrier.
const MACRO_EXTENSIONS = new Set(['docm', 'xlsm', 'pptm', 'dotm', 'xltm', 'potm'])

// Archives that can hide executables inside.
const ARCHIVE_EXTENSIONS = new Set(['zip', 'rar', '7z', 'tar', 'gz', 'bz2', 'xz'])

function apiHeaders() {
  return {
    'accept': 'application/json',
    'api-key': API_KEY,
    'user-agent': 'Falcon Sandbox',
  }
}

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

function isRecentId(id, nowSeconds) {
  if (!/^[0-9a-f]{24}$/i.test(id)) return false
  const ts = parseInt(id.slice(0, 8), 16)
  return Number.isFinite(ts) && (nowSeconds - ts) <= RECENT_WINDOW_SECONDS
}

// Free DB lookup by file hash. Same endpoint as URLs: /search/hash. A file
// that was never detonated yields 404 -> treat as empty.
async function searchByHash(sha256) {
  const res = await fetch(`${BASE_URL}/search/hash?hash=${encodeURIComponent(sha256)}`, {
    method: 'GET',
    headers: apiHeaders(),
    signal: AbortSignal.timeout(8000),
  })
  if (res.status === 404) return { reports: [] }
  if (!res.ok) throw new Error(`search/hash failed: ${res.status}`)
  return res.json()
}

// Combine DB reports for one file hash into a single verdict. Unlike domains,
// a file hash identifies one exact set of bytes, so any recent malicious
// detonation of it is a genuine signal; reports across environments are
// tallied with the same dominance rule used for URLs.
function aggregateHash(searchData) {
  const reports = searchData?.reports || []
  const nowSeconds = Math.floor(Date.now() / 1000)
  const recent = reports.filter((r) => r.state === 'SUCCESS' && r.verdict && isRecentId(r.id, nowSeconds))
  if (recent.length === 0) return null

  let malicious = 0
  let suspicious = 0
  let safe = 0
  for (const rep of recent) {
    const mapped = verdictFromString(rep.verdict)
    if (!mapped) continue
    if (mapped.verdict === 'malicious') malicious += 1
    else if (mapped.verdict === 'suspicious') suspicious += 1
    else safe += 1
  }

  // "no verdict" reports from the DB must NOT be treated as clean - a sample
  // that the sandbox could not analyze is not proof of safety. If no report
  // mapped to a usable verdict, fall through to the type heuristic.
  if (malicious + suspicious + safe === 0) return null

  if (malicious > 0 && malicious >= safe) {
    return { verdict: 'malicious', label: 'Malicious', threatScore: 90, source: 'db' }
  }
  if (suspicious > 0 && suspicious >= safe) {
    return { verdict: 'suspicious', label: 'Suspicious', threatScore: 50, source: 'db' }
  }
  if (malicious === 0 && recent.length > 0) {
    return { verdict: 'safe', label: 'No specific threat', threatScore: 0, source: 'db' }
  }
  return null
}

function extensionOf(filename) {
  if (!filename) return ''
  const dot = filename.lastIndexOf('.')
  if (dot < 0) return ''
  return filename.slice(dot + 1).toLowerCase()
}

// When the file hash is unknown to the DB, classify by file type. Risky
// executables/macro docs/archives are suspicious; ordinary documents and media
// are reported as "no known threat" (marked source=heuristic in the UI).
function classifyByType(file) {
  const ext = extensionOf(file.filename)
  if (!ext) {
    return { verdict: 'unknown', label: 'No verdict', threatScore: null, source: null, note: null }
  }
  if (HIGH_RISK_EXTENSIONS.has(ext)) {
    return {
      verdict: 'suspicious',
      label: `Executable (.${ext})`,
      threatScore: null,
      source: 'heuristic',
      note: `${ext.toUpperCase()} files can execute code on your device. This exact file is not in the threat database - treat it with caution.`,
    }
  }
  if (MACRO_EXTENSIONS.has(ext)) {
    return {
      verdict: 'suspicious',
      label: `Macro-enabled document (.${ext})`,
      threatScore: null,
      source: 'heuristic',
      note: `Macro-enabled documents are a common phishing carrier. This exact file is not in the threat database - open it only if you trust the sender.`,
    }
  }
  if (ARCHIVE_EXTENSIONS.has(ext)) {
    return {
      verdict: 'suspicious',
      label: `Archive (.${ext})`,
      threatScore: null,
      source: 'heuristic',
      note: `Archives can hide executables. This exact file is not in the threat database - extract and open it with caution.`,
    }
  }
  return {
    verdict: 'safe',
    label: 'No known threat',
    threatScore: 0,
    source: 'heuristic',
    note: null,
  }
}

async function checkFile(file, fetchBytes) {
  if (!file.attachmentId) {
    return {
      ...file,
      sha256: null,
      verdict: 'unknown',
      label: 'Inaccessible attachment',
      threatScore: null,
      source: null,
      note: 'This attachment could not be fetched for scanning.',
    }
  }
  if (file.size > MAX_FILE_BYTES) {
    return {
      ...file,
      sha256: null,
      verdict: 'unknown',
      label: 'Too large to scan',
      threatScore: null,
      source: null,
      note: `File is ${(file.size / 1024 / 1024).toFixed(1)} MB; the ${MAX_FILE_BYTES / 1024 / 1024} MB scan limit protects your data.`,
    }
  }

  let bytes
  try {
    bytes = await fetchBytes(file)
  } catch (err) {
    console.warn(`Attachment fetch failed for ${file.filename}: ${err.message}`)
    return {
      ...file,
      sha256: null,
      verdict: 'unknown',
      label: 'Read failed',
      threatScore: null,
      source: null,
      note: 'The attachment bytes could not be read for scanning.',
    }
  }

  const sha256 = createHash('sha256').update(bytes).digest('hex')
  let result = { verdict: 'unknown', label: 'No verdict', threatScore: null, source: null, note: null }

  try {
    const searchData = await searchByHash(sha256)
    const aggregated = aggregateHash(searchData)
    if (aggregated) result = { ...aggregated, note: null }
  } catch (dbErr) {
    console.warn(`Hybrid hash lookup failed for ${file.filename}: ${dbErr.message}`)
  }

  if (result.verdict === 'unknown') {
    result = classifyByType(file)
  }

  return { ...file, sha256, ...result }
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

// Check every attachment of an email.
//   attachments: metadata array from gmail.js (filename, mimeType, size, attachmentId)
//   fetchBytes:  (file) => Promise<Buffer> - resolves raw attachment bytes
export async function checkEmailAttachments(attachments, fetchBytes) {
  const files = (attachments || []).slice(0, MAX_ATTACHMENTS)
  if (files.length === 0) {
    return { attachments: [], summary: { verdict: 'safe', count: 0, highestSeverity: 'safe' } }
  }
  const checked = await mapConcurrently(files, MAX_CONCURRENCY, (file) => checkFile(file, fetchBytes))
  const results = checked.filter(Boolean)

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
    attachments: results,
    summary: {
      verdict: highest,
      count: results.length,
      highestSeverity: highest,
      counts,
    },
  }
}

export default checkEmailAttachments