// Timing test for the parallel URL check pipeline.
// Usage: node scripts/test-parallel.mjs
import { checkEmailLinks } from '../src/services/phishing.js'
import { checkEmailAttachments } from '../src/services/filecheck.js'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import path from 'node:path'
import dotenv from 'dotenv'
dotenv.config()

const __dirname = path.dirname(fileURLToPath(import.meta.url))

function space(n = 1) { console.log('\n' + '='.repeat(n ? 60 : 0)) }

// 1) Links test - known malicious + safe + never-seen domain
const html = `
  <a href="https://something-for-you-check.netlify.app/?id=7202927639">bad phishing</a>
  <a href="https://www.google.com/">google</a>
  <a href="https://never-seen-12345.example.com/page">new domain</a>
`
console.time('links-parallel')
const linkResult = await checkEmailLinks(html)
console.timeEnd('links-parallel')
space(0)
console.log(JSON.stringify(linkResult.links, null, 2))
space(0)

// 2) Attachments test - real malware bytes from temp samples
// invalid function removed
const samplesDir = path.join(process.env.USERPROFILE || process.env.HOME || '', 'AppData', 'Local', 'Temp', 'opencode')

function fakeFile(filename) {
  const p = path.join(samplesDir, filename)
  const bytes = readFileSync(p)
  return { filename, mimeType: 'application/octet-stream', size: bytes.length, attachmentId: 'fake', sha256: createHash('sha256').update(bytes).digest('hex') }
}

// simulate fetchBytes reading from disk
const fakeFetch = async (file) => readFileSync(path.join(samplesDir, file.filename))

console.time('files-parallel')
const fileResult = await checkEmailAttachments(
  [
    { filename: 'emotet.bin', mimeType: 'application/octet-stream', size: 683008, attachmentId: '1' },
    { filename: 'normal_memo.pdf', mimeType: 'application/pdf', size: 100, attachmentId: '2' },
  ],
  async (file) => {
    if (file.filename === 'emotet.bin') return readFileSync(path.join(samplesDir, 'ext_emotet', '106fb5f7a2b5d0e0af8609949ef37543_JaffaCakes118'))
    return Buffer.from('%PDF-1.4 fake normal pdf content')
  }
)
console.timeEnd('files-parallel')
space(0)
console.log(JSON.stringify(fileResult.attachments, null, 2))
space(0)

// 3) Full combined (route-level) timing
console.time('combined')
const combined = await Promise.all([
  checkEmailLinks(html),
  checkEmailAttachments(
    [
      { filename: 'emotet.bin', mimeType: 'application/octet-stream', size: 683008, attachmentId: '1' },
      { filename: 'normal_memo.pdf', mimeType: 'application/pdf', size: 100, attachmentId: '2' },
    ],
    async (file) => {
      if (file.filename === 'emotet.bin') return readFileSync(path.join(samplesDir, 'ext_emotet', '106fb5f7a2b5d0e0af8609949ef37543_JaffaCakes118'))
      return Buffer.from('%PDF-1.4 fake normal pdf content')
    }
  ),
])
console.timeEnd('combined')
space(0)
console.log('links:', combined[0].links.map((l) => `${l.verdict}:${l.hostname ?? l.url}`))
console.log('files:', combined[1].attachments.map((a) => `${a.verdict}:${a.filename}`))
space(0)
console.log('DONE - parallel pipeline')
process.exit(0)