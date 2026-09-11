export function parseDate(dateString) {
  if (!dateString) return ''
  const date = new Date(dateString)
  if (isNaN(date)) return dateString

  const now = new Date()
  const sameYear = date.getFullYear() === now.getFullYear()
  const sameDay =
    date.getFullYear() === now.getFullYear() &&
    date.getMonth() === now.getMonth() &&
    date.getDate() === now.getDate()

  if (sameDay) {
    return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
  }
  if (sameYear) {
    return date.toLocaleDateString([], { month: 'short', day: 'numeric' })
  }
  return date.toLocaleDateString([], { month: 'short', day: 'numeric', year: 'numeric' })
}

export function formatFullDate(dateString) {
  if (!dateString) return ''
  const date = new Date(dateString)
  if (isNaN(date)) return dateString
  return date.toLocaleString([], {
    weekday: 'short',
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  })
}