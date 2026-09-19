import { useEffect, useState } from 'react'
import { Box, Typography, Button, Slide, Collapse } from '@mui/material'
import DownloadRoundedIcon from '@mui/icons-material/DownloadRounded'
import CloseRoundedIcon from '@mui/icons-material/CloseRounded'
import ShareRoundedIcon from '@mui/icons-material/ShareRounded'
import LaptopRoundedIcon from '@mui/icons-material/LaptopRounded'
import PhoneAndroidRoundedIcon from '@mui/icons-material/PhoneAndroidRounded'
import InfoOutlinedIcon from '@mui/icons-material/InfoOutlined'
import {
  isStandalone,
  isInstallDismissed,
  dismissInstallPrompt,
  getPlatform,
} from '../utils/pwaHelper'

export default function InstallPopup() {
  const [standalone, setStandalone] = useState(() => isStandalone())
  const [deferredPrompt, setDeferredPrompt] = useState(() => (typeof window !== 'undefined' ? window.__pwaPrompt : null))
  const [open, setOpen] = useState(false)
  const [showManualGuide, setShowManualGuide] = useState(false)
  const [platform, setPlatform] = useState(() => getPlatform())

  useEffect(() => {
    if (typeof window === 'undefined') return

    // If running in standalone app window (desktop app / mobile PWA), NEVER show popup
    if (isStandalone()) {
      setStandalone(true)
      setOpen(false)
      return
    }

    setPlatform(getPlatform())

    // If prompt is already captured on window, pick it up
    if (window.__pwaPrompt) {
      setDeferredPrompt(window.__pwaPrompt)
    }

    // Auto-open popup in browser after a short delay if not dismissed this session
    const timer = setTimeout(() => {
      if (!isStandalone() && !isInstallDismissed()) {
        setOpen(true)
      }
    }, 600)

    // Listen to display-mode change (e.g. app launched in standalone)
    const mediaQuery = window.matchMedia('(display-mode: standalone)')
    const handleDisplayChange = (e) => {
      if (e.matches) {
        setStandalone(true)
        setOpen(false)
      }
    }
    if (mediaQuery.addEventListener) {
      mediaQuery.addEventListener('change', handleDisplayChange)
    }

    // Capture browser beforeinstallprompt
    const handleBeforeInstall = (e) => {
      if (isStandalone()) return
      e.preventDefault()
      window.__pwaPrompt = e
      setDeferredPrompt(e)
      if (!isInstallDismissed()) {
        setOpen(true)
      }
    }

    const handlePromptReady = (e) => {
      if (isStandalone()) return
      if (e.detail) {
        setDeferredPrompt(e.detail)
      }
      if (!isInstallDismissed()) {
        setOpen(true)
      }
    }

    // Capture when installation completes
    const handleAppInstalled = () => {
      setOpen(false)
      window.__pwaPrompt = null
      setDeferredPrompt(null)
      dismissInstallPrompt()
    }

    // Listen to manual open requests
    const handleRequestInstall = () => {
      if (!isStandalone()) {
        setOpen(true)
      }
    }

    window.addEventListener('beforeinstallprompt', handleBeforeInstall)
    window.addEventListener('pwa-prompt-ready', handlePromptReady)
    window.addEventListener('appinstalled', handleAppInstalled)
    window.addEventListener('request-pwa-install', handleRequestInstall)

    return () => {
      clearTimeout(timer)
      window.removeEventListener('beforeinstallprompt', handleBeforeInstall)
      window.removeEventListener('pwa-prompt-ready', handlePromptReady)
      window.removeEventListener('appinstalled', handleAppInstalled)
      window.removeEventListener('request-pwa-install', handleRequestInstall)
      if (mediaQuery.removeEventListener) {
        mediaQuery.removeEventListener('change', handleDisplayChange)
      }
    }
  }, [])

  // If already running inside installed app window, do not show
  if (standalone || !open) {
    return null
  }

  const handleInstallClick = async () => {
    const promptEvent = deferredPrompt || window.__pwaPrompt
    if (promptEvent) {
      try {
        promptEvent.prompt()
        const { outcome } = await promptEvent.userChoice
        if (outcome === 'accepted') {
          setOpen(false)
          window.__pwaPrompt = null
          setDeferredPrompt(null)
          dismissInstallPrompt()
        }
      } catch (err) {
        console.error('Install prompt error:', err)
        setShowManualGuide(true)
      }
    } else {
      // If browser hasn't provided prompt (or already prompted), show manual instruction
      setShowManualGuide(true)
    }
  }

  const handleDismiss = () => {
    dismissInstallPrompt()
    setOpen(false)
  }

  return (
    <Slide in={open} direction="up" mountOnEnter unmountOnExit>
      <Box
        sx={{
          position: 'fixed',
          left: 0,
          right: 0,
          bottom: 0,
          zIndex: 1400,
          display: 'flex',
          justifyContent: 'center',
          p: { xs: 1.5, sm: 2.5 },
          pointerEvents: 'none',
        }}
      >
        <Box
          className="aurora-card"
          sx={{
            width: '100%',
            maxWidth: 460,
            borderRadius: 3,
            p: 2.5,
            pointerEvents: 'auto',
            boxShadow: '0 20px 50px rgba(2, 6, 23, 0.85), 0 0 0 1px rgba(129, 140, 248, 0.25)',
            backdropFilter: 'blur(24px)',
            background: 'rgba(15, 23, 42, 0.95)',
          }}
        >
          {/* Header */}
          <Box sx={{ display: 'flex', alignItems: 'flex-start', gap: 1.5 }}>
            <Box
              sx={{
                width: 46,
                height: 46,
                flexShrink: 0,
                borderRadius: 2.5,
                background: 'linear-gradient(135deg, #6366f1, #a855f7)',
                boxShadow: '0 4px 14px rgba(129, 140, 248, 0.5)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
              }}
            >
              <DownloadRoundedIcon sx={{ color: '#fff', fontSize: 26 }} />
            </Box>

            <Box sx={{ flex: 1, minWidth: 0 }}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, lineHeight: 1.3 }}>
                <span className="gradient-text">Install SecureMail App</span>
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5, fontSize: '0.85rem' }}>
                {platform.isIOS
                  ? 'Add to Home Screen for a faster, full-screen experience.'
                  : 'Install this app on your device for instant launch and a full-screen experience.'}
              </Typography>
            </Box>

            <Box
              component="button"
              type="button"
              onClick={handleDismiss}
              aria-label="Dismiss"
              sx={{
                border: 0,
                background: 'transparent',
                color: 'text.secondary',
                cursor: 'pointer',
                p: 0.5,
                borderRadius: 1,
                display: 'flex',
                '&:hover': { color: '#fff', background: 'rgba(255,255,255,0.08)' },
              }}
            >
              <CloseRoundedIcon fontSize="small" />
            </Box>
          </Box>

          {/* iOS Safari instructions */}
          {platform.isIOSSafari && (
            <Box
              sx={{
                mt: 2,
                p: 1.5,
                borderRadius: 2,
                background: 'rgba(99, 102, 241, 0.1)',
                border: '1px solid rgba(129, 140, 248, 0.25)',
                display: 'flex',
                flexDirection: 'column',
                gap: 0.5,
              }}
            >
              <Typography variant="caption" sx={{ color: '#e2e8f0', display: 'flex', alignItems: 'center', gap: 1 }}>
                <ShareRoundedIcon sx={{ fontSize: 16, color: '#818cf8' }} />
                1. Tap the <strong>Share</strong> icon in Safari&apos;s bottom bar
              </Typography>
              <Typography variant="caption" sx={{ color: '#e2e8f0', display: 'flex', alignItems: 'center', gap: 1 }}>
                <DownloadRoundedIcon sx={{ fontSize: 16, color: '#818cf8' }} />
                2. Scroll down and tap <strong>&apos;Add to Home Screen&apos;</strong>
              </Typography>
            </Box>
          )}

          {/* Manual guidance fallback when browser requires omnibar click */}
          <Collapse in={showManualGuide}>
            <Box
              sx={{
                mt: 2,
                p: 1.5,
                borderRadius: 2,
                background: 'rgba(99, 102, 241, 0.1)',
                border: '1px solid rgba(129, 140, 248, 0.25)',
                display: 'flex',
                alignItems: 'flex-start',
                gap: 1,
              }}
            >
              <InfoOutlinedIcon sx={{ fontSize: 18, color: '#818cf8', mt: 0.2 }} />
              <Typography variant="caption" sx={{ color: '#e2e8f0', lineHeight: 1.4 }}>
                To install, click the <strong>Install icon (⊕)</strong> in your browser&apos;s address bar (top-right), or open <strong>Menu (⋮)</strong> &rarr; <strong>&apos;Install SecureMail&apos;</strong>.
              </Typography>
            </Box>
          </Collapse>

          {/* Action buttons */}
          <Box sx={{ display: 'flex', gap: 1.2, mt: 2.2, justifyContent: 'flex-end', alignItems: 'center' }}>
            <Button
              onClick={handleDismiss}
              color="inherit"
              size="small"
              sx={{
                color: 'text.secondary',
                fontSize: '0.85rem',
                '&:hover': { color: '#fff' },
              }}
            >
              Not now
            </Button>

            {!platform.isIOSSafari && (
              <Button
                onClick={handleInstallClick}
                variant="contained"
                size="small"
                startIcon={
                  platform.isAndroid ? (
                    <PhoneAndroidRoundedIcon />
                  ) : (
                    <LaptopRoundedIcon />
                  )
                }
                sx={{
                  background: 'linear-gradient(135deg, #6366f1, #8b5cf6)',
                  fontWeight: 600,
                  fontSize: '0.85rem',
                  px: 2,
                  boxShadow: '0 4px 14px rgba(99, 102, 241, 0.4)',
                  '&:hover': {
                    background: 'linear-gradient(135deg, #4f46e5, #7c3aed)',
                  },
                }}
              >
                Install App
              </Button>
            )}
          </Box>
        </Box>
      </Box>
    </Slide>
  )
}
