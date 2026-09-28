'use client'

/**
 * SecureMailScope Client-Side Analysis Persistence
 *
 * Manages sessionStorage for canonical analysis results across page navigation.
 * Complies with prototype requirements:
 *  - Survives client navigation across /upload, /analysis, /findings, /reports, /lab
 *  - Cleared upon application refresh (F5/reload)
 */

import type { CanonicalAnalysis } from './types'

export const STORAGE_KEY_ANALYSIS = 'secureMailScopeAnalysis'
export const STORAGE_KEY_SESSION = 'secureMailScopeSession'
export const STORAGE_KEY_METADATA = 'secureMailScopePcapMetadata'

let lifecycleHandled = false

/**
 * Checks if the prototype was refreshed (page reload) and clears temporary analysis.
 */
export function handlePageLifecycle(): void {
  if (typeof window === 'undefined' || lifecycleHandled) return
  lifecycleHandled = true

  try {
    const navEntries = performance.getEntriesByType('navigation') as PerformanceNavigationTiming[]
    const isReload = navEntries.length > 0
      ? navEntries[0].type === 'reload'
      : Boolean(
          window.performance &&
          (window.performance as unknown as { navigation?: { type: number } }).navigation?.type === 1
        )

    if (isReload) {
      sessionStorage.removeItem(STORAGE_KEY_ANALYSIS)
      sessionStorage.removeItem(STORAGE_KEY_SESSION)
      sessionStorage.removeItem(STORAGE_KEY_METADATA)
    }
  } catch (err) {
    console.warn('Could not inspect navigation timing:', err)
  }
}

/**
 * Saves canonical analysis and metadata to sessionStorage.
 */
export function saveAnalysisSession(analysis: CanonicalAnalysis): void {
  if (typeof window === 'undefined') return
  try {
    const serialized = JSON.stringify(analysis)
    sessionStorage.setItem(STORAGE_KEY_ANALYSIS, serialized)
    sessionStorage.setItem(STORAGE_KEY_SESSION, analysis.session.id)
    sessionStorage.setItem(
      STORAGE_KEY_METADATA,
      JSON.stringify({
        filename: analysis.capture.filename,
        packetCount: analysis.capture.packetCount,
        format: analysis.capture.format,
        timestamp: analysis.analysisTimestamp,
        score: analysis.securityScore.total,
        grade: analysis.securityScore.grade,
      })
    )
  } catch (err) {
    console.error('Failed to save analysis to sessionStorage:', err)
  }
}

/**
 * Retrieves the canonical analysis from sessionStorage.
 */
export function getStoredAnalysis(): CanonicalAnalysis | null {
  if (typeof window === 'undefined') return null
  handlePageLifecycle()
  try {
    const raw = sessionStorage.getItem(STORAGE_KEY_ANALYSIS)
    if (!raw) return null
    return JSON.parse(raw) as CanonicalAnalysis
  } catch (err) {
    console.error('Failed to parse analysis from sessionStorage:', err)
    return null
  }
}

/**
 * Retrieves the current stored session ID.
 */
export function getStoredSessionId(): string | null {
  if (typeof window === 'undefined') return null
  handlePageLifecycle()
  try {
    return sessionStorage.getItem(STORAGE_KEY_SESSION)
  } catch {
    return null
  }
}

/**
 * Explicitly clears the temporary analysis.
 */
export function clearStoredAnalysis(): void {
  if (typeof window === 'undefined') return
  try {
    sessionStorage.removeItem(STORAGE_KEY_ANALYSIS)
    sessionStorage.removeItem(STORAGE_KEY_SESSION)
    sessionStorage.removeItem(STORAGE_KEY_METADATA)
  } catch {
    // Ignore
  }
}
