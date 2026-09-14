import { Box, Typography, ListItemButton, Avatar } from '@mui/material'
import { parseDate } from '../utils/format'

const avatarGradients = [
  'linear-gradient(135deg, #6366f1, #a855f7)',
  'linear-gradient(135deg, #06b6d4, #3b82f6)',
  'linear-gradient(135deg, #f59e0b, #ef4444)',
  'linear-gradient(135deg, #10b981, #06b6d4)',
  'linear-gradient(135deg, #ec4899, #8b5cf6)',
  'linear-gradient(135deg, #84cc16, #10b981)',
]

function initials(name) {
  const parts = name.trim().split(/\s+/).filter(Boolean)
  if (parts.length === 0) return '?'
  const first = parts[0][0]
  const last = parts.length > 1 ? parts[parts.length - 1][0] : ''
  return (first + last).toUpperCase()
}

export default function EmailListItem({ email, selected, onSelect }) {
  const sender = email.sender?.name || email.sender?.email || 'Unknown'
  const gradient = avatarGradients[email.id?.length % avatarGradients.length] || avatarGradients[0]

  return (
    <ListItemButton
      selected={selected}
      onClick={() => onSelect(email.id)}
      className="!px-4 !py-3.5"
      sx={{
        borderLeft: '3px solid transparent',
        '&.Mui-selected': {
          bgcolor: 'rgba(99,102,241,0.14)',
          borderLeft: '3px solid #818cf8',
        },
        '&.Mui-selected:hover': { bgcolor: 'rgba(99,102,241,0.2)' },
        '&:hover': { bgcolor: 'rgba(255,255,255,0.05)' },
      }}
    >
      <Avatar className="mr-3 shrink-0" sx={{ background: gradient, fontWeight: 700 }}>
        {initials(sender)}
      </Avatar>
      <Box className="min-w-0 flex-1">
        <Box className="flex justify-between items-center gap-2">
          <Typography
            variant="subtitle2"
            fontWeight={email.unread ? 700 : 500}
            className="truncate"
            sx={{ color: email.unread ? '#f1f5f9' : '#cbd5e1' }}
          >
            {sender}
          </Typography>
          <Typography variant="caption" className="text-slate-500 whitespace-nowrap">
            {email.date ? parseDate(email.date) : ''}
          </Typography>
        </Box>
        <Typography
          variant="body2"
          fontWeight={email.unread ? 600 : 450}
          className="truncate"
          sx={{ color: email.unread ? '#e2e8f0' : '#94a3b8' }}
        >
          {email.subject}
        </Typography>
        <Typography variant="caption" className="block truncate text-slate-500">
          {email.snippet}
        </Typography>
      </Box>
    </ListItemButton>
  )
}