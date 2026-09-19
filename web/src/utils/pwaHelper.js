/**
 * PWA Helper utilities for cross-platform detection and installation state.
 */

const DISMISSED_KEY = 'securemail:install-popup-dismissed'
const INSTALLED_KEY = 'securemail:app-installed'

/**
 * Checks if the web app is currently running inside the installed standalone PWA window or webview.
 */
export function isStandalone() {
  if (typeof window === 'undefined') return false

  return Boolean(
    window.matchMedia('(display-mode: standalone)').matches ||
    window.matchMedia('(display-mode: window-controls-overlay)').matches ||
    window.matchMedia('(display-mode: minimal-ui)').matches ||
    window.navigator.standalone === true ||
    (document.referrer && document.referrer.startsWith('android-app://'))
  )
}

/**
 * Checks whether the app is currently running in an installed standalone window.
 */
export function isAppInstalled() {
  return isStandalone()
}

/**
 * Checks if user dismissed the install popup in this session.
 */
export function isInstallDismissed() {
  try {
    return sessionStorage.getItem(DISMISSED_KEY) === '1'
  } catch {
    return false
  }
}

/**
 * Marks popup as dismissed for this session.
 */
export function dismissInstallPrompt() {
  try {
    sessionStorage.setItem(DISMISSED_KEY, '1')
  } catch {}
}

/**
 * Clears dismiss flag.
 */
export function clearDismissed() {
  try {
    sessionStorage.removeItem(DISMISSED_KEY)
    localStorage.removeItem(INSTALLED_KEY)
  } catch {}
}

/**
 * Requests opening the install prompt.
 */
export function requestInstallPrompt() {
  if (typeof window !== 'undefined') {
    try {
      sessionStorage.removeItem(DISMISSED_KEY)
    } catch {}
    window.dispatchEvent(new CustomEvent('request-pwa-install'))
  }
}

/**
 * Detect platform details for platform-tailored installation guides.
 */
export function getPlatform() {
  if (typeof window === 'undefined') {
    return { isIOS: false, isMac: false, isAndroid: false, isWindows: false, isSafari: false }
  }

  const ua = window.navigator.userAgent || ''
  const isIOS =
    (/iPad|iPhone|iPod/.test(ua) || (navigator.maxTouchPoints > 1 && /Macintosh/.test(ua))) &&
    !window.MSStream
  const isAndroid = /Android/i.test(ua)
  const isMac = /Macintosh|MacIntel|MacPPC|Mac68K/.test(ua) && !isIOS
  const isWindows = /Windows|Win32|Win64|WOW64/.test(ua)
  const isSafari = /^((?!chrome|android).)*safari/i.test(ua)

  return {
    isIOS,
    isAndroid,
    isMac,
    isWindows,
    isSafari,
    isIOSSafari: isIOS && isSafari,
    isMacSafari: isMac && isSafari,
  }
}
