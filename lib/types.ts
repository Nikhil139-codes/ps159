// ─── SecureMailScope Canonical Types ─────────────────────────────────────────
// ONE source of truth shared by: Email Lab, PCAPNG generator, parser,
// scoring engine, findings engine, and all pages.
// Version: 1.0

export const SCHEMA_VERSION = '1.0'
export const GENERATOR_VERSION = '1.0.0'

// ─── Email configuration ───────────────────────────────────────────────────

export type EmailProtocol = 'SMTP' | 'IMAP' | 'POP3'

export type StarttlsMode =
  | 'enabled_required'   // STARTTLS offered AND required (client must upgrade)
  | 'enabled_optional'   // STARTTLS offered, not required
  | 'disabled'           // No STARTTLS

export interface EmailConfig {
  protocol: EmailProtocol
  server: string
  port: number
  starttls: boolean
  starttlsMode: StarttlsMode
}

// ─── TLS configuration ────────────────────────────────────────────────────

export type TlsVersion = 'TLS1.0' | 'TLS1.1' | 'TLS1.2' | 'TLS1.3' | 'None'

export type CipherSuite =
  // TLS 1.3 cipher suites
  | 'TLS_AES_128_GCM_SHA256'
  | 'TLS_AES_256_GCM_SHA384'
  | 'TLS_CHACHA20_POLY1305_SHA256'
  // TLS 1.2 cipher suites
  | 'ECDHE-RSA-AES128-GCM-SHA256'
  | 'ECDHE-RSA-AES256-GCM-SHA384'
  | 'ECDHE-ECDSA-AES128-GCM-SHA256'
  | 'ECDHE-ECDSA-AES256-GCM-SHA384'
  | 'AES128-SHA'
  | 'AES256-SHA'
  | 'TLS_RSA_WITH_3DES_EDE_CBC_SHA'

export type KeyExchangeMechanism = 'ECDHE' | 'DHE' | 'RSA' | 'X25519' | 'X448'

export type NamedGroup =
  | 'X25519'
  | 'X448'
  | 'secp256r1'
  | 'secp384r1'
  | 'secp521r1'

export interface TlsConfig {
  version: TlsVersion
  cipherSuite: CipherSuite
  keyExchange: KeyExchangeMechanism
  namedGroup: NamedGroup
  forwardSecrecy: boolean // derived from keyExchange, not user-settable independently
}

// ─── Certificate configuration ────────────────────────────────────────────

export type CertKeyAlgorithm = 'RSA' | 'ECDSA' | 'Ed25519'
export type RsaKeyLength = 1024 | 2048 | 3072 | 4096
export type EcdsaCurve = 'P-256' | 'P-384' | 'P-521'
export type SignatureAlgorithm =
  | 'SHA256withRSA'
  | 'SHA384withRSA'
  | 'SHA512withRSA'
  | 'SHA1withRSA'
  | 'SHA256withECDSA'
  | 'SHA384withECDSA'
  | 'Ed25519'

export type CertScenario =
  | 'valid'
  | 'expired'
  | 'not_yet_valid'
  | 'self_signed'
  | 'invalid_chain'
  | 'weak_key'
  | 'weak_signature'

export interface CertificateConfig {
  enabled: boolean
  commonName: string
  issuer: string
  validFrom: string   // ISO date string
  validUntil: string  // ISO date string
  publicKeyAlgorithm: CertKeyAlgorithm
  publicKeyLength: number // RSA key length, or curve bit size for ECDSA
  signatureAlgorithm: SignatureAlgorithm
  chainValid: boolean
  scenario: CertScenario
}

// ─── Test scenario presets ────────────────────────────────────────────────

export type TestScenario =
  | 'secure'
  | 'legacy_tls'
  | 'weak_cipher'
  | 'expired_cert'
  | 'invalid_chain'
  | 'no_pfs'
  | 'starttls_issue'
  | 'custom'

// ─── CANONICAL LAB CONFIGURATION ─────────────────────────────────────────
// This is the one configuration object created in the Email Lab.
// It flows through: generator → PCAPNG embed → parser → analysis → scoring → findings → reports

export interface LabConfiguration {
  schemaVersion: string
  sessionId: string
  email: EmailConfig
  tls: TlsConfig
  certificate: CertificateConfig
  testScenario: TestScenario
  metadata: {
    createdAt: string
    generatorVersion: string
    source: string
    recipient?: string
    subject?: string
  }
}

// ─── Encrypted config manifest (embedded in PCAPNG custom block) ──────────

export interface EncryptedConfigManifest {
  algorithm: 'AES-256-GCM'
  iv: string         // base64
  authTag: string    // base64
  ciphertext: string // base64
  configHash: string // SHA-256 hex of the plaintext JSON config
  schemaVersion: string
  sessionId: string
  generatorVersion: string
}

// ─── Observable status ────────────────────────────────────────────────────

export type ObservableStatus = 'match' | 'mismatch' | 'not_observable' | 'unavailable'

// ─── Observed analysis from packet/capture parsing ────────────────────────

export interface ObservedCapture {
  filename: string
  format: 'PCAPNG' | 'PCAP' | 'unknown'
  timestamp: string
  packetCount: number
  durationSeconds: number
  sourceIp: string
  destinationIp: string
  sourcePort: number
  destinationPort: number
  hasSecureMailScopeMetadata: boolean
  metadataIntegrity: 'valid' | 'decryption_failed' | 'hash_mismatch' | 'missing' | 'tampered'
}

export interface ObservedProtocol {
  detected: EmailProtocol | 'unknown'
  port: number
  confidence: 'high' | 'medium' | 'low'
}

export interface ObservedStarttls {
  advertised: boolean
  negotiated: boolean
  required: boolean
  plaintextPhaseObserved: boolean
  encryptedPhaseObserved: boolean
}

export interface ObservedTls {
  version: TlsVersion | 'unknown'
  cipherSuite: string
  keyExchange: string
  namedGroup: string
  forwardSecrecy: boolean
  handshakeComplete: boolean
  clientHelloObserved: boolean
  serverHelloObserved: boolean
}

export interface ObservedCertificate {
  present: boolean
  commonName: string
  issuer: string
  validFrom: string
  validUntil: string
  expired: boolean
  notYetValid: boolean
  selfSigned: boolean
  publicKeyAlgorithm: string
  publicKeyLength: number
  signatureAlgorithm: string
  chainValid: boolean
}

// ─── Configuration comparison ────────────────────────────────────────────

export interface ComparisonField {
  configured: string
  observed: string
  status: ObservableStatus
}

export interface ConfigurationComparison {
  tlsVersion: ComparisonField
  cipherSuite: ComparisonField
  keyExchange: ComparisonField
  namedGroup: ComparisonField
  forwardSecrecy: ComparisonField
  starttls: ComparisonField
  starttlsRequired: ComparisonField
  certExpired: ComparisonField
  certChainValid: ComparisonField
  certCommonName: ComparisonField
  publicKeyAlgorithm: ComparisonField
  signatureAlgorithm: ComparisonField
  overallStatus: 'consistent' | 'configuration_mismatch' | 'unknown'
  mismatches: string[]
}

// ─── Security findings ────────────────────────────────────────────────────

export type FindingCategory =
  | 'TLS'
  | 'Cipher'
  | 'Certificate'
  | 'STARTTLS'
  | 'KeyExchange'
  | 'PFS'
  | 'Protocol'
  | 'Configuration'
  | 'Anomaly'

export type FindingSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'

export interface SecurityFinding {
  id: string
  category: FindingCategory
  severity: FindingSeverity
  title: string
  description: string
  evidence: Record<string, unknown>
  impact: string
  recommendation: string
  source: 'pcap-analysis' | 'configuration-check' | 'anomaly-detection'
  deduction: number
}

// ─── Anomaly detection ────────────────────────────────────────────────────

export type AnomalyType =
  | 'TLS_DOWNGRADE'
  | 'CIPHER_DOWNGRADE'
  | 'STARTTLS_NOT_NEGOTIATED'
  | 'CERT_MISMATCH'
  | 'CERT_EXPIRED'
  | 'UNEXPECTED_PROTOCOL'
  | 'CONFIG_MISMATCH'
  | 'INCOMPLETE_HANDSHAKE'
  | 'WEAK_PARAMS_OBSERVED'

export interface Anomaly {
  anomaly: boolean
  type: AnomalyType
  severity: FindingSeverity
  evidence: string
  configured?: string
  observed?: string
}

// ─── Security score ───────────────────────────────────────────────────────

export interface ScoreDeduction {
  reason: string
  severity: FindingSeverity
  points: number
}

export interface SecurityScore {
  total: number          // 0–100
  grade: 'A' | 'B' | 'C' | 'D' | 'F'
  level: 'Excellent' | 'Good' | 'Fair' | 'Poor' | 'Critical'
  deductions: ScoreDeduction[]
  breakdown: {
    tlsScore: number
    cipherScore: number
    keyExchangeScore: number
    certificateScore: number
    starttlsScore: number
    configConsistencyScore: number
  }
}

// ─── AI Assessment ────────────────────────────────────────────────────────

export interface AiAssessment {
  available: boolean
  provider: 'groq' | 'none'
  executiveSummary: string
  riskNarrative: string
  prioritizedFindings: string[]
  recommendations: string[]
  anomalyExplanations: string[]
  fallbackReason?: string
}

// ─── CANONICAL ANALYSIS OBJECT ────────────────────────────────────────────
// This is the single canonical result object flowing through:
// parser → analysis page → findings page → reports page

export interface CanonicalAnalysis {
  schemaVersion: string
  analysisTimestamp: string

  // Session info
  session: {
    id: string
    source: 'email-lab' | 'upload'
    captureFile: string
  }

  // What was captured
  capture: ObservedCapture

  // What was configured (from Email Lab, or null for external PCAPs)
  configured: LabConfiguration | null

  // What was observed in the capture
  observed: {
    protocol: ObservedProtocol
    starttls: ObservedStarttls
    tls: ObservedTls
    certificate: ObservedCertificate
  }

  // Configured vs Observed comparison
  configurationComparison: ConfigurationComparison | null

  // Deterministic analysis outputs
  findings: SecurityFinding[]
  anomalies: Anomaly[]
  securityScore: SecurityScore

  // AI assessment (may be unavailable)
  aiAssessment: AiAssessment

  // Top recommendations
  recommendations: string[]
}

// ─── Session stored on disk ───────────────────────────────────────────────

export interface StoredSession {
  id: string
  files: { originalName: string; storedName?: string; size: number }[]
  folder: string
  reconstruction: {
    status: string
    method: string
    sourceFiles: string[]
    sessionsReconstructed: number
    message: string
  }
  attachments?: { originalName: string; size: number }[]
  // New: analysis if already computed
  analysis?: CanonicalAnalysis
  // New: source type
  source?: 'email-lab' | 'upload'
}

// ─── Helper: derive PFS from key exchange ────────────────────────────────

export function deriveForwardSecrecy(
  keyExchange: KeyExchangeMechanism,
  tlsVersion: TlsVersion,
): boolean {
  // TLS 1.3 always has ephemeral key exchange
  if (tlsVersion === 'TLS1.3') return true
  // DHE and ECDHE provide PFS
  if (keyExchange === 'ECDHE' || keyExchange === 'DHE') return true
  // X25519 and X448 are ECDHE named groups — they provide PFS
  if (keyExchange === 'X25519' || keyExchange === 'X448') return true
  return false
}

// ─── Helper: TLS version label ────────────────────────────────────────────

export function tlsVersionLabel(v: TlsVersion): string {
  const labels: Record<TlsVersion, string> = {
    'TLS1.0': 'TLS 1.0',
    'TLS1.1': 'TLS 1.1',
    'TLS1.2': 'TLS 1.2',
    'TLS1.3': 'TLS 1.3',
    'None': 'None',
  }
  return labels[v] ?? v
}

export function isTlsDeprecated(v: TlsVersion): boolean {
  return v === 'TLS1.0' || v === 'TLS1.1'
}

// ─── Helper: grade from score ────────────────────────────────────────────

export function gradeFromScore(score: number): SecurityScore['grade'] {
  if (score >= 90) return 'A'
  if (score >= 75) return 'B'
  if (score >= 60) return 'C'
  if (score >= 45) return 'D'
  return 'F'
}

export function levelFromScore(score: number): SecurityScore['level'] {
  if (score >= 90) return 'Excellent'
  if (score >= 75) return 'Good'
  if (score >= 60) return 'Fair'
  if (score >= 45) return 'Poor'
  return 'Critical'
}
