import { google } from 'googleapis'

// Builds a Gmail client for the caller using the user's OAuth access token.
// The token is passed per-request via the x-gmail-token header and is never stored.
function getGmailClient(accessToken) {
  if (!accessToken) {
    const err = new Error('Missing Gmail access token')
    err.status = 400
    throw err
  }
  const auth = new google.auth.OAuth2()
  auth.setCredentials({ access_token: accessToken })
  return google.gmail({ version: 'v1', auth })
}

function getHeader(headers, name) {
  if (!headers) return null
  const found = headers.find(
    (h) => h.name && h.name.toLowerCase() === name.toLowerCase()
  )
  return found ? found.value : null
}

// Parse an address like "Name <name@example.com>"
function parseAddress(value) {
  if (!value) return null
  const match = value.match(/^(.*?)\s*<([^>]+)>$/)
  if (match) {
    return { name: match[1].replace(/"/g, '').trim(), email: match[2].trim() }
  }
  return { name: '', email: value.trim() }
}

// Extract the primary (non-attachment) text and HTML body parts
function extractBody(parts) {
  const bodyText = []
  const bodyHtml = []
  const walk = (nodes) => {
    if (!nodes) return
    for (const node of nodes) {
      if (node.mimeType === 'text/plain' && node.body?.data) {
        bodyText.push(node.body.data)
      } else if (node.mimeType === 'text/html' && node.body?.data) {
        bodyHtml.push(node.body.data)
      } else if (node.parts) {
        walk(node.parts)
      }
    }
  }
  walk(parts)

  const decode = (data) =>
    Buffer.from(data.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8')

  return {
    bodyText: bodyText.length ? decode(bodyText[0]) : null,
    bodyHtml: bodyHtml.length ? decode(bodyHtml[0]) : null,
  }
}

// Collect attachment metadata from the multipart tree. Inline images and real
// attachments both appear as parts that carry a filename; the bytes are fetched
// lazily on demand (attachmentId) by the security scanner, never here.
function extractAttachments(parts) {
  const out = []
  const walk = (nodes) => {
    if (!nodes) return
    for (const node of nodes) {
      if (node.filename) {
        out.push({
          filename: node.filename,
          mimeType: node.mimeType || 'application/octet-stream',
          size: Number(node.body?.size) || 0,
          attachmentId: node.body?.attachmentId || null,
        })
      } else if (node.parts) {
        walk(node.parts)
      }
    }
  }
  walk(parts)
  return out
}

function mapMessage(msg) {
  const headers = msg.payload?.headers || []
  const from = parseAddress(getHeader(headers, 'From'))
  const sender = {
    name: from?.name || '',
    email: from?.email || '',
  }
  return {
    id: msg.id,
    threadId: msg.threadId,
    subject: getHeader(headers, 'Subject') || '(no subject)',
    sender,
    from: getHeader(headers, 'From'),
    to: getHeader(headers, 'To'),
    date: getHeader(headers, 'Date'),
    unread: (msg.labelIds || []).includes('UNREAD'),
    snippet: msg.snippet || '',
  }
}

export async function listEmails(accessToken, { pageToken, maxResults = 50 }) {
  const gmail = getGmailClient(accessToken)
  const res = await gmail.users.messages.list({
    userId: 'me',
    maxResults,
    pageToken: pageToken || undefined,
  })

  const messages = res.data.messages || []
  const emails = await Promise.all(
    messages.map(async (m) => {
      // Use format=metadata to keep the list light
      const detail = await gmail.users.messages.get({
        userId: 'me',
        id: m.id,
        format: 'metadata',
        metadataHeaders: ['From', 'Subject', 'Date'],
      })
      return mapMessage(detail.data)
    })
  )

  return {
    emails,
    nextPageToken: res.data.nextPageToken || null,
    resultSizeEstimate: res.data.resultSizeEstimate || 0,
  }
}

export async function getEmail(accessToken, id) {
  const gmail = getGmailClient(accessToken)
  const res = await gmail.users.messages.get({
    userId: 'me',
    id,
    format: 'full',
  })

  const msg = res.data
  const headers = msg.payload?.headers || []
  const body = extractBody(msg.payload?.parts)
  const message = mapMessage(msg)
  return {
    ...message,
    internalDate: msg.internalDate,
    labelIds: msg.labelIds || [],
    attachments: extractAttachments(msg.payload?.parts),
    ...body,
  }
}

// Fetch raw bytes for a single attachment by its Gmail attachmentId.
export async function getAttachmentBytes(accessToken, messageId, attachmentId) {
  if (!attachmentId) throw new Error('Attachment has no id')
  const gmail = getGmailClient(accessToken)
  const res = await gmail.users.messages.attachments.get({
    userId: 'me',
    messageId,
    id: attachmentId,
  })
  const data = res.data?.data
  if (!data) {
    const err = new Error('Attachment is empty')
    err.status = 400
    throw err
  }
  return Buffer.from(data.replace(/-/g, '+').replace(/_/g, '/'), 'base64')
}