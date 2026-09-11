import { Box, Typography, ListItemButton, Avatar, Divider } from '@mui/material'
import { parseDate } from '../utils/format'

export default function EmailListItem({ email, selected, onSelect }) {
  const sender = email.sender?.name || email.sender?.email || 'Unknown'
  const senderInitial = (sender[0] || '?').toUpperCase()

  return (
    <>
      <ListItemButton
        selected={selected}
        onClick={() => onSelect(email.id)}
        className="!px-4 !py-3"
        sx={{
          '&.Mui-selected': { bgcolor: 'primary.light' },
        }}
      >
        <Avatar className="mr-3 shrink-0" sx={{ bgcolor: 'primary.main' }}>
          {senderInitial}
        </Avatar>
        <Box className="min-w-0 flex-1">
          <Box className="flex justify-between items-center gap-2">
            <Typography
              variant="subtitle2"
              fontWeight={email.unread ? 700 : 400}
              className="truncate"
            >
              {sender}
            </Typography>
            <Typography variant="caption" className="text-gray-400 whitespace-nowrap">
              {email.date ? parseDate(email.date) : ''}
            </Typography>
          </Box>
          <Typography
            variant="body2"
            fontWeight={email.unread ? 600 : 400}
            className="truncate text-gray-800"
          >
            {email.subject}
          </Typography>
          <Typography variant="caption" className="block truncate text-gray-500">
            {email.snippet}
          </Typography>
        </Box>
      </ListItemButton>
      <Divider />
    </>
  )
}