import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  AppBar,
  Toolbar,
  Typography,
  Avatar,
  Menu,
  MenuItem,
  Tooltip,
  ListItemIcon,
  Box,
} from '@mui/material'
import { ShieldOutlined, Logout, MailOutline } from '@mui/icons-material'
import { logout } from '../auth/authService'

export default function Layout({ user, children }) {
  const navigate = useNavigate()
  const [anchorEl, setAnchorEl] = useState(null)

  const handleMenuOpen = (e) => setAnchorEl(e.currentTarget)
  const handleMenuClose = () => setAnchorEl(null)

  const handleLogout = async () => {
    handleMenuClose()
    await logout()
    navigate('/')
  }

  return (
    <div className="min-h-screen flex flex-col aurora-bg">
      <AppBar
        position="sticky"
        elevation={0}
        sx={{
          background: 'rgba(10, 14, 26, 0.7)',
          backdropFilter: 'blur(14px)',
          borderBottom: '1px solid rgba(148, 163, 184, 0.16)',
        }}
      >
        <Toolbar>
          <Box className="flex items-center gap-2.5">
            <Box
              className="flex items-center justify-center rounded-xl"
              sx={{
                width: 38,
                height: 38,
                background: 'linear-gradient(135deg, #6366f1, #a855f7)',
                boxShadow: '0 4px 14px rgba(129,140,248,0.5)',
              }}
            >
              <ShieldOutlined fontSize="small" sx={{ color: '#fff' }} />
            </Box>
            <Typography variant="h6" className="font-extrabold tracking-tight">
              <span className="gradient-text">SecureMail</span>
            </Typography>
          </Box>

          <Box sx={{ flexGrow: 1 }} />

          {user && (
            <Tooltip title={user.email}>
              <Avatar
                src={user.photoURL}
                alt={user.displayName}
                onClick={handleMenuOpen}
                className="cursor-pointer ring-2 ring-indigo-400/50"
                sx={{ width: 36, height: 36 }}
              />
            </Tooltip>
          )}
          <Menu
            anchorEl={anchorEl}
            open={Boolean(anchorEl)}
            onClose={handleMenuClose}
            PaperProps={{ sx: { mt: 1, background: '#151c33', borderRadius: 3 } }}
          >
            <MenuItem disabled>
              <Typography variant="body2">{user?.email}</Typography>
            </MenuItem>
            <MenuItem onClick={handleLogout}>
              <ListItemIcon>
                <Logout fontSize="small" />
              </ListItemIcon>
              Logout
            </MenuItem>
          </Menu>
        </Toolbar>
      </AppBar>
      <main className="flex-1">{children}</main>
    </div>
  )
}