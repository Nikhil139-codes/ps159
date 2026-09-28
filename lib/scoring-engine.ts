/**
 * SecureMailScope Scoring Engine
 *
 * Deterministic security scoring — every deduction has an explicit reason.
 * Score: 0-100. No random values.
 */

import type {
  LabConfiguration,
  ObservedTls,
  ObservedCertificate,
  ObservedStarttls,
  ObservedProtocol,
  ConfigurationComparison,
  SecurityScore,
  ScoreDeduction,
  TlsVersion,
} from './types'
import { gradeFromScore, levelFromScore } from './types'

export interface ScoringInput {
  configured: LabConfiguration | null
  observedTls: ObservedTls
  observedCert: ObservedCertificate
  observedStarttls: ObservedStarttls
  observedProtocol: ObservedProtocol
  comparison: ConfigurationComparison | null
}

const MAX_SCORE = 100

// Scoring weights (total max deductions = 100)
const WEIGHTS = {
  tlsVersion: 20,      // 20 pts for TLS version
  cipherSuite: 20,     // 20 pts for cipher
  keyExchange: 15,     // 15 pts for key exchange / PFS
  certificate: 25,     // 25 pts for certificate
  starttls: 10,        // 10 pts for STARTTLS
  consistency: 10,     // 10 pts for configured vs observed consistency
}

export function calculateSecurityScore(input: ScoringInput): SecurityScore {
  const deductions: ScoreDeduction[] = []

  // ── TLS Version scoring ──────────────────────────────────────────────────
  let tlsScore = WEIGHTS.tlsVersion
  const tlsVer = input.observedTls.version
  if (tlsVer === 'None') {
    deductions.push({ reason: 'No TLS encryption detected — traffic is plaintext', severity: 'CRITICAL', points: 20 })
    tlsScore = 0
  } else if (tlsVer === 'TLS1.0') {
    deductions.push({ reason: 'TLS 1.0 detected — deprecated, vulnerable to BEAST/POODLE', severity: 'HIGH', points: 18 })
    tlsScore = 2
  } else if (tlsVer === 'TLS1.1') {
    deductions.push({ reason: 'TLS 1.1 detected — deprecated protocol', severity: 'HIGH', points: 14 })
    tlsScore = 6
  } else if (tlsVer === 'TLS1.2') {
    tlsScore = 16 // TLS 1.2 is acceptable, minor deduction
    deductions.push({ reason: 'TLS 1.2 detected — modern but prefer TLS 1.3', severity: 'INFO', points: 4 })
  }
  // TLS 1.3 = full points (no deduction)

  // ── Cipher Suite scoring ──────────────────────────────────────────────────
  let cipherScore = WEIGHTS.cipherSuite
  const cipher = input.observedTls.cipherSuite
  if (!cipher || cipher === 'unknown') {
    deductions.push({ reason: 'Cipher suite not observable in capture', severity: 'INFO', points: 5 })
    cipherScore = 15
  } else if (isWeakCipher(cipher)) {
    deductions.push({ reason: `Weak cipher suite detected: ${cipher}`, severity: 'HIGH', points: 18 })
    cipherScore = 2
  } else if (isLegacyCipher(cipher)) {
    deductions.push({ reason: `Legacy cipher suite detected: ${cipher}`, severity: 'MEDIUM', points: 10 })
    cipherScore = 10
  }

  // ── Key Exchange / PFS scoring ────────────────────────────────────────────
  let kexScore = WEIGHTS.keyExchange
  if (!input.observedTls.forwardSecrecy) {
    if (tlsVer === 'TLS1.3') {
      // TLS 1.3 always has PFS — this would be a mis-detection
    } else {
      deductions.push({ reason: 'No Forward Secrecy — static key exchange in use', severity: 'MEDIUM', points: 12 })
      kexScore = 3
    }
  }
  if (input.observedTls.keyExchange === 'RSA') {
    deductions.push({ reason: 'RSA key exchange used — no PFS, vulnerable to future decryption', severity: 'MEDIUM', points: 8 })
    kexScore = Math.max(0, kexScore - 8)
  }

  // ── Certificate scoring ───────────────────────────────────────────────────
  let certScore = WEIGHTS.certificate
  if (!input.observedCert.present) {
    deductions.push({ reason: 'No certificate observed in capture', severity: 'HIGH', points: 15 })
    certScore = 10
  } else {
    if (input.observedCert.expired) {
      deductions.push({ reason: 'Certificate is expired', severity: 'HIGH', points: 15 })
      certScore -= 15
    }
    if (input.observedCert.notYetValid) {
      deductions.push({ reason: 'Certificate is not yet valid', severity: 'HIGH', points: 12 })
      certScore -= 12
    }
    if (input.observedCert.selfSigned) {
      deductions.push({ reason: 'Self-signed certificate — no trusted CA chain', severity: 'MEDIUM', points: 10 })
      certScore -= 10
    }
    if (!input.observedCert.chainValid) {
      deductions.push({ reason: 'Certificate chain is invalid or incomplete', severity: 'HIGH', points: 12 })
      certScore -= 12
    }
    if (isWeakPublicKey(input.observedCert.publicKeyAlgorithm, input.observedCert.publicKeyLength)) {
      deductions.push({
        reason: `Weak public key: ${input.observedCert.publicKeyAlgorithm} ${input.observedCert.publicKeyLength}-bit`,
        severity: 'HIGH',
        points: 10,
      })
      certScore -= 10
    }
    if (isWeakSignatureAlgorithm(input.observedCert.signatureAlgorithm)) {
      deductions.push({
        reason: `Weak signature algorithm: ${input.observedCert.signatureAlgorithm}`,
        severity: 'HIGH',
        points: 8,
      })
      certScore -= 8
    }
  }
  certScore = Math.max(0, certScore)

  // ── STARTTLS scoring ──────────────────────────────────────────────────────
  let starttlsScore = WEIGHTS.starttls
  if (!input.observedStarttls.advertised) {
    if (input.configured?.email.starttls) {
      deductions.push({ reason: 'STARTTLS was configured but not advertised', severity: 'HIGH', points: 10 })
      starttlsScore = 0
    } else {
      deductions.push({ reason: 'STARTTLS not offered — plaintext connections permitted', severity: 'MEDIUM', points: 6 })
      starttlsScore = 4
    }
  } else if (input.observedStarttls.advertised && !input.observedStarttls.negotiated) {
    deductions.push({ reason: 'STARTTLS advertised but not negotiated — TLS upgrade failed', severity: 'HIGH', points: 8 })
    starttlsScore = 2
  }

  // ── Configuration consistency scoring ────────────────────────────────────
  let consistencyScore = WEIGHTS.consistency
  if (input.comparison) {
    const mismatchCount = input.comparison.mismatches.length
    if (mismatchCount > 0) {
      const mismatchDeduction = Math.min(10, mismatchCount * 3)
      deductions.push({
        reason: `${mismatchCount} configuration mismatch${mismatchCount > 1 ? 'es' : ''} detected between configured and observed values`,
        severity: mismatchCount >= 3 ? 'HIGH' : 'MEDIUM',
        points: mismatchDeduction,
      })
      consistencyScore = Math.max(0, consistencyScore - mismatchDeduction)
    }
  } else {
    // External PCAP — no comparison possible, minor info deduction
    deductions.push({ reason: 'No SecureMailScope configuration metadata available for comparison', severity: 'INFO', points: 2 })
    consistencyScore = 8
  }

  // ── Calculate total ───────────────────────────────────────────────────────
  const totalDeductions = deductions.reduce((sum, d) => sum + d.points, 0)
  const rawTotal = MAX_SCORE - totalDeductions
  const total = Math.max(0, Math.min(100, rawTotal))

  return {
    total,
    grade: gradeFromScore(total),
    level: levelFromScore(total),
    deductions,
    breakdown: {
      tlsScore: Math.max(0, tlsScore),
      cipherScore: Math.max(0, cipherScore),
      keyExchangeScore: Math.max(0, kexScore),
      certificateScore: Math.max(0, certScore),
      starttlsScore: Math.max(0, starttlsScore),
      configConsistencyScore: Math.max(0, consistencyScore),
    },
  }
}

// ─── Cipher helpers ───────────────────────────────────────────────────────────

const WEAK_CIPHERS = new Set([
  'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
  'AES128-SHA',
  'AES256-SHA',
  '000a', // 3DES hex
  '002f', // AES128-SHA hex
  '0035', // AES256-SHA hex
])

const LEGACY_CIPHERS = new Set([
  'ECDHE-RSA-AES128-GCM-SHA256',
  'ECDHE-ECDSA-AES128-GCM-SHA256',
])

export function isWeakCipher(cipher: string): boolean {
  return WEAK_CIPHERS.has(cipher)
}

export function isLegacyCipher(cipher: string): boolean {
  return LEGACY_CIPHERS.has(cipher)
}

export function isWeakPublicKey(algorithm: string, length: number): boolean {
  if (algorithm === 'RSA' && length < 2048) return true
  if (algorithm === 'ECDSA' && length < 256) return true
  return false
}

export function isWeakSignatureAlgorithm(algorithm: string): boolean {
  return algorithm.includes('SHA1') || algorithm.includes('MD5')
}

// ─── PFS detection from observed key exchange ─────────────────────────────────

export function deriveObservedPFS(
  keyExchange: string,
  tlsVersion: TlsVersion,
): boolean {
  if (tlsVersion === 'TLS1.3') return true
  if (['ECDHE', 'DHE', 'X25519', 'X448'].includes(keyExchange)) return true
  return false
}
