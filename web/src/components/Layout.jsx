import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  AppBar,
  Toolbar,
  Typography,
  Avatar,
  Button,
  Menu,
  MenuItem,
  Tooltip,
} from '@mui/material'
import { MailOutline, Logout } from '@mui/icons-material'
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
    <div className="min-h-screen flex flex-col bg-gray-50">
      <AppBar position="static" color="primary" elevation={1}>
        <Toolbar>
          <MailOutline className="mr-2" />
          <Typography variant="h6" component="div" sx={{ flexGrow: 1 }}>
            Gmail Client
          </Typography>
          {user && (
            <Tooltip title={user.email}>
              <Avatar
                src={user.photoURL}
                alt={user.displayName}
                className="cursor-pointer"
                onClick={handleMenuOpen}
              />
            </Tooltip>
          )}
          <Menu anchorEl={anchorEl} open={Boolean(anchorEl)} onClose={handleMenuClose}>
            <MenuItem disabled>
              <Typography variant="body2">{user?.email}</Typography>
            </MenuItem>
            <MenuItem onClick={handleLogout}>
              <Logout fontSize="small" className="mr-2" />
              Logout
            </MenuItem>
          </Menu>
        </Toolbar>
      </AppBar>
      <main className="flex-1">{children}</main>
    </div>
  )
}