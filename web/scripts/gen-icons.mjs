import { deflateSync } from 'node:zlib'
import { mkdirSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const outDir = join(root, 'public', 'pwa')
mkdirSync(outDir, { recursive: true })

const CRC_TABLE = (() => {
  const t = new Uint32Array(256)
  for (let n = 0; n < 256; n++) {
    let c = n
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1
    t[n] = c >>> 0
  }
  return t
})()

function crc32(buf) {
  let c = 0xffffffff
  for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8)
  return (c ^ 0xffffffff) >>> 0
}

function chunk(type, data) {
  const len = Buffer.alloc(4)
  len.writeUInt32BE(data.length)
  const typeBuf = Buffer.from(type, 'ascii')
  const crc = Buffer.alloc(4)
  crc.writeUInt32BE(crc32(Buffer.concat([typeBuf, data])))
  return Buffer.concat([len, typeBuf, data, crc])
}

function encodePng(size, rgba) {
  const raw = Buffer.alloc((size * 4 + 1) * size)
  for (let y = 0; y < size; y++) {
    const rowStart = y * (size * 4 + 1)
    raw[rowStart] = 0
    rgba.copy(raw, rowStart + 1, y * size * 4, (y + 1) * size * 4)
  }
  const ihdr = Buffer.alloc(13)
  ihdr.writeUInt32BE(size, 0)
  ihdr.writeUInt32BE(size, 4)
  ihdr[8] = 8
  ihdr[9] = 6
  const png = Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', ihdr),
    chunk('IDAT', deflateSync(raw, { level: 9 })),
    chunk('IEND', Buffer.alloc(0)),
  ])
  const w = png.readUInt32BE(16)
  const h = png.readUInt32BE(20)
  if (w !== size || h !== size) throw new Error(`PNG dimension mismatch: ${w}x${h}`)
  return png
}

const clamp01 = (v) => Math.min(1, Math.max(0, v))
const lerp = (a, b, t) => a + (b - a) * t
const smooth = (t) => t * t * (3 - 2 * t)

function hexToRgb(h) {
  return [parseInt(h.slice(1, 3), 16), parseInt(h.slice(3, 5), 16), parseInt(h.slice(5, 7), 16)]
}

function mixRgb(a, b, t) {
  return [Math.round(lerp(a[0], b[0], t)), Math.round(lerp(a[1], b[1], t)), Math.round(lerp(a[2], b[2], t))]
}

const BG_CENTER = hexToRgb('#4f46e5')
const BG_EDGE = hexToRgb('#050312')
const SHIELD_TOP = hexToRgb('#6366f1')
const SHIELD_BOTTOM = hexToRgb('#d946ef')
const CHECK = hexToRgb('#ffffff')

function bgColor(x, y) {
  const d = Math.hypot(x - 0.5, y - 0.5)
  return mixRgb(BG_CENTER, BG_EDGE, smooth(clamp01(d / Math.SQRT1_2)))
}

function inRoundedRect(x, y, x0, y0, x1, y1, r) {
  if (x < x0 || x > x1 || y < y0 || y > y1) return false
  const nx = Math.max(x0 + r, Math.min(x, x1 - r))
  const ny = Math.max(y0 + r, Math.min(y, y1 - r))
  const dx = x - nx
  const dy = y - ny
  return dx * dx + dy * dy <= r * r
}

function inShield(x, y) {
  if (inRoundedRect(x, y, 0.28, 0.18, 0.72, 0.58, 0.09)) return true
  if (y >= 0.58 && y <= 0.86) {
    const t = clamp01((y - 0.58) / 0.28)
    return Math.abs(x - 0.5) <= 0.22 * (1 - t)
  }
  return false
}

function distToSegment(px, py, ax, ay, bx, by) {
  const dx = bx - ax
  const dy = by - ay
  const len2 = dx * dx + dy * dy
  let t = len2 === 0 ? 0 : clamp01(((px - ax) * dx + (py - ay) * dy) / len2)
  return Math.hypot(px - (ax + t * dx), py - (ay + t * dy))
}

const CHECK_SEGMENTS = [
  [0.42, 0.53, 0.485, 0.595],
  [0.485, 0.595, 0.6, 0.45],
]

function checkDist(x, y) {
  let d = Infinity
  for (const [ax, ay, bx, by] of CHECK_SEGMENTS) {
    d = Math.min(d, distToSegment(x, y, ax, ay, bx, by))
  }
  return d
}

function sampleContent(x, y) {
  if (checkDist(x, y) <= 0.03 && inShield(x, y)) return CHECK
  if (inShield(x, y)) return mixRgb(SHIELD_TOP, SHIELD_BOTTOM, clamp01((y - 0.18) / 0.68))
  return null
}

const SS = 4

function renderIcon(size, contentScale) {
  const off = (1 - contentScale) / 2
  const rgba = Buffer.alloc(size * size * 4)
  const n = SS * SS
  for (let py = 0; py < size; py++) {
    for (let px = 0; px < size; px++) {
      let r = 0
      let g = 0
      let b = 0
      let a = 0
      for (let sy = 0; sy < SS; sy++) {
        for (let sx = 0; sx < SS; sx++) {
          const u = (px + (sx + 0.5) / SS) / size
          const v = (py + (sy + 0.5) / SS) / size
          const c = sampleContent(off + u * contentScale, off + v * contentScale) ?? bgColor(u, v)
          r += c[0]
          g += c[1]
          b += c[2]
          a += 255
        }
      }
      const i = (py * size + px) * 4
      rgba[i] = Math.round(r / n)
      rgba[i + 1] = Math.round(g / n)
      rgba[i + 2] = Math.round(b / n)
      rgba[i + 3] = Math.round(a / n)
    }
  }
  return rgba
}

function writePng(name, size, contentScale) {
  const png = encodePng(size, renderIcon(size, contentScale))
  const file = join(outDir, name)
  writeFileSync(file, png)
  console.log(`wrote ${name}  ${png.length} bytes  ${png.readUInt32BE(16)}x${png.readUInt32BE(20)}`)
}

writePng('icon-192.png', 192, 1)
writePng('icon-512.png', 512, 1)
writePng('icon-maskable-512.png', 512, 0.8)

const favicon = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100">
  <defs>
    <radialGradient id="bg" cx="0.5" cy="0.5" r="0.71">
      <stop offset="0" stop-color="#4f46e5"/>
      <stop offset="1" stop-color="#050312"/>
    </radialGradient>
    <linearGradient id="shield" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0" stop-color="#6366f1"/>
      <stop offset="1" stop-color="#d946ef"/>
    </linearGradient>
  </defs>
  <rect width="100" height="100" rx="22" fill="url(#bg)"/>
  <path d="M 50 16 C 58 16 66 19 72 23 L 72 44 C 72 64 62 81 50 87 C 38 81 28 64 28 44 L 28 23 C 34 19 42 16 50 16 Z" fill="url(#shield)"/>
  <path d="M40 52 L48 60 L61 45" fill="none" stroke="#ffffff" stroke-width="6.5" stroke-linecap="round" stroke-linejoin="round"/>
</svg>
`
writeFileSync(join(root, 'public', 'favicon.svg'), favicon)
console.log('wrote favicon.svg')