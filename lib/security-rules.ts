/**
 * SecureMailScope Centralized Cryptographic Security Rules Engine
 *
 * Implements deterministic security assessments grounded in authoritative standards:
 *  - NIST SP 800-52 Rev. 2 (Guidelines for Selection, Configuration, and Use of TLS)
 *  - NIST SP 800-57 Part 1 Rev. 5 (Recommendation for Key Management: Cryptographic Strength)
 *  - RFC 8996 (Deprecating TLS 1.0 and TLS 1.1)
 *  - RFC 8446 (The TLS Protocol Version 1.3)
 *  - RFC 5246 (The TLS Protocol Version 1.2)
 *  - RFC 3207 (SMTP Service Extension for Secure SMTP over TLS)
 *  - RFC 2595 (Using TLS with IMAP, POP3 and ACAP)
 *  - CISA Guidance (Secure Communications & Email Security Directives)
 *  - CA/Browser Forum Baseline Requirements (Public Key & Certificate Validity Guidelines)
 */

import type {
  CanonicalAnalysis,
  LabConfiguration,
  ObservedCapture,
  ObservedProtocol,
  ObservedStarttls,
  ObservedTls,
  ObservedCertificate,
  ConfigurationComparison,
  FindingSeverity,
  TlsVersion,
} from './types'

export type RuleStatus = 'PASS' | 'WARNING' | 'FAIL' | 'NOT_OBSERVABLE'

export interface StandardsSource {
  name: string
  document: string
  section: string
  reference: string
}

export interface SecurityRuleDefinition {
  ruleId: string
  category: string
  title: string
  description: string
  severity: FindingSeverity
  source: StandardsSource
  condition: string
  recommendation: string
  scoreDeduction: number
}

export interface SecurityRuleResult {
  ruleId: string
  category: string
  title: string
  status: RuleStatus
  severity: FindingSeverity
  observed: string
  expected: string
  reason: string
  evidence: {
    source: string
    field: string
    value: string
  }
  standard: StandardsSource
  recommendation: string
  scoreImpact: number
}

export interface CryptoStrengthItem {
  component: string
  algorithm: string
  parameter: string
  estimatedSecurityStrength: string
  status: 'STRONG' | 'ACCEPTABLE' | 'LEGACY' | 'DEPRECATED' | 'NOT_OBSERVABLE'
  source: string
  notes: string
}

export interface ConfigAssessmentRow {
  parameter: string
  configured: string
  observed: string
  status: 'MATCH' | 'MISMATCH' | 'NOT_OBSERVABLE' | 'PASS' | 'FAIL' | 'WARNING'
  standardReference: string
  details?: string
}

export interface CategorySummary {
  category: string
  status: 'PASS' | 'WARNING' | 'FAIL' | 'NOT_OBSERVABLE'
  passedRules: number
  totalRules: number
  details: string
}

export type StarttlsState =
  | 'SECURE_UPGRADE'
  | 'PLAINTEXT_ONLY'
  | 'STARTTLS_ADVERTISED_NOT_USED'
  | 'STARTTLS_NOT_ADVERTISED'
  | 'NOT_OBSERVABLE'

// ─── Rule Definitions ─────────────────────────────────────────────────────────

export const SECURITY_RULES: SecurityRuleDefinition[] = [
  // 1. Protocol Security
  {
    ruleId: 'PROTO-001',
    category: 'Protocol Security',
    title: 'Secure Mail Transport Verification',
    description: 'Email protocols (SMTP, IMAP, POP3) must utilize transport encryption to protect credentials and message content from passive interception.',
    severity: 'CRITICAL',
    source: {
      name: 'NIST SP 800-52 Rev. 2',
      document: 'NIST SP 800-52 Rev. 2',
      section: 'Section 3.1',
      reference: 'https://csrc.nist.gov/pubs/sp/800/52/r2/final',
    },
    condition: 'Observed TLS handshake completed or plaintext observed',
    recommendation: 'Enforce TLS encryption on all mail transport hops (SMTPS, IMAPS, or mandatory STARTTLS).',
    scoreDeduction: 20,
  },

  // 2. TLS Version
  {
    ruleId: 'TLS-001',
    category: 'TLS Version',
    title: 'Deprecated TLS 1.0/1.1 Prohibition',
    description: 'TLS versions 1.0 and 1.1 are formally deprecated due to vulnerabilities to POODLE, BEAST, and lack of modern cryptographic constructs.',
    severity: 'HIGH',
    source: {
      name: 'RFC 8996',
      document: 'IETF BCP 195 / RFC 8996',
      section: 'Section 1 & 2',
      reference: 'https://www.rfc-editor.org/rfc/rfc8996',
    },
    condition: 'Observed TLS version is TLS 1.0 or TLS 1.1',
    recommendation: 'Disable TLS 1.0 and TLS 1.1 entirely. Configure server to support only TLS 1.2 and TLS 1.3.',
    scoreDeduction: 18,
  },
  {
    ruleId: 'TLS-002',
    category: 'TLS Version',
    title: 'Modern TLS Protocol Adoption',
    description: 'Agencies and secure organizations should prioritize TLS 1.3 while supporting TLS 1.2 with secure cipher suites.',
    severity: 'INFO',
    source: {
      name: 'NIST SP 800-52 Rev. 2',
      document: 'NIST SP 800-52 Rev. 2',
      section: 'Section 3.1.1',
      reference: 'https://csrc.nist.gov/pubs/sp/800/52/r2/final',
    },
    condition: 'Observed TLS version is TLS 1.2 or TLS 1.3',
    recommendation: 'Prefer TLS 1.3 for enhanced latency and cryptographic posture.',
    scoreDeduction: 0,
  },

  // 3. Cipher Suite
  {
    ruleId: 'CIPHER-001',
    category: 'Cipher Suite',
    title: 'Weak / Broken Cipher Suite Prohibition',
    description: 'Cipher suites employing 3DES, RC4, or CBC-mode ciphers without Encrypt-then-MAC are vulnerable to plaintext recovery attacks.',
    severity: 'HIGH',
    source: {
      name: 'NIST SP 800-52 Rev. 2',
      document: 'NIST SP 800-52 Rev. 2',
      section: 'Section 3.3.1',
      reference: 'https://csrc.nist.gov/pubs/sp/800/52/r2/final',
    },
    condition: 'Cipher suite uses 3DES or CBC mode without AEAD',
    recommendation: 'Replace legacy cipher suites with Authenticated Encryption with Associated Data (AEAD) ciphers (e.g. AES-GCM, ChaCha20-Poly1305).',
    scoreDeduction: 18,
  },

  // 4. Cryptographic Strength
  {
    ruleId: 'CRYPTO-001',
    category: 'Cryptographic Strength',
    title: 'Minimum 112-bit Security Strength Requirement',
    description: 'NIST SP 800-57 requires all symmetric and asymmetric cryptographic keys to provide at least 112 bits of security strength (128 bits recommended).',
    severity: 'HIGH',
    source: {
      name: 'NIST SP 800-57 Part 1 Rev. 5',
      document: 'NIST SP 800-57 Part 1 Rev. 5',
      section: 'Section 5.6.1 Table 2 & 4',
      reference: 'https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final',
    },
    condition: 'Cryptographic parameters offer < 112 bits of security strength',
    recommendation: 'Use key sizes: RSA >= 2048 bits (3072 recommended), ECC >= 256 bits, AES >= 128 bits (256 recommended).',
    scoreDeduction: 15,
  },

  // 5. Key Exchange
  {
    ruleId: 'KEX-001',
    category: 'Key Exchange',
    title: 'Ephemeral Key Exchange Mandate',
    description: 'Static RSA key exchange does not provide ephemeral session key derivation, allowing retrospective decryption if the private key is exposed.',
    severity: 'MEDIUM',
    source: {
      name: 'NIST SP 800-52 Rev. 2',
      document: 'NIST SP 800-52 Rev. 2',
      section: 'Section 3.3.2',
      reference: 'https://csrc.nist.gov/pubs/sp/800/52/r2/final',
    },
    condition: 'Key exchange mechanism is static RSA',
    recommendation: 'Disallow static RSA key exchange. Enable ECDHE or DHE key exchange.',
    scoreDeduction: 10,
  },

  // 6. Forward Secrecy
  {
    ruleId: 'PFS-001',
    category: 'Forward Secrecy',
    title: 'Perfect Forward Secrecy (PFS) Enforcement',
    description: 'Sessions must negotiate ephemeral Diffie-Hellman or ECDH key exchange to ensure future key compromises cannot decrypt past communications.',
    severity: 'MEDIUM',
    source: {
      name: 'CISA Guidance / NIST SP 800-52 Rev. 2',
      document: 'CISA Secure Email Architecture Guidance',
      section: 'Section 4.2',
      reference: 'https://www.cisa.gov/resources-tools/guidance',
    },
    condition: 'forwardSecrecy flag is false',
    recommendation: 'Configure TLS configurations to exclusively select PFS-enabled cipher suites.',
    scoreDeduction: 12,
  },

  // 7. Certificate Security
  {
    ruleId: 'CERT-001',
    category: 'Certificate Security',
    title: 'Server Certificate Presence & Authenticity',
    description: 'Mail servers must present a verifiable certificate issued by a recognized Certification Authority to establish server identity.',
    severity: 'HIGH',
    source: {
      name: 'CA/Browser Forum Baseline Requirements',
      document: 'CA/Browser Forum Baseline Requirements',
      section: 'Section 6.1.5',
      reference: 'https://cabforum.org/baseline-requirements-documents/',
    },
    condition: 'Certificate missing or self-signed in production mail exchange',
    recommendation: 'Install a trusted X.509 certificate issued by an audited public or private CA.',
    scoreDeduction: 12,
  },

  // 8. Certificate Chain
  {
    ruleId: 'CHAIN-001',
    category: 'Certificate Chain',
    title: 'Certificate Chain Integrity & Intermediate Trust',
    description: 'The server must supply a complete and valid certificate chain up to a trusted root, avoiding trust path failure on strict client validators.',
    severity: 'HIGH',
    source: {
      name: 'RFC 5246 / RFC 8446',
      document: 'RFC 8446 TLS 1.3',
      section: 'Section 4.4.2',
      reference: 'https://www.rfc-editor.org/rfc/rfc8446#section-4.4.2',
    },
    condition: 'chainValid is false',
    recommendation: 'Bundle all required intermediate CA certificates in the mail server TLS certificate chain file.',
    scoreDeduction: 12,
  },

  // 9. Certificate Expiration
  {
    ruleId: 'EXP-001',
    category: 'Certificate Expiration',
    title: 'Certificate Validity Window Compliance',
    description: 'Certificates must be evaluated against the current date/time to ensure they have not expired or are not yet valid.',
    severity: 'HIGH',
    source: {
      name: 'CA/Browser Forum Baseline Requirements',
      document: 'CA/Browser Forum Baseline Requirements',
      section: 'Section 6.3.2',
      reference: 'https://cabforum.org/baseline-requirements-documents/',
    },
    condition: 'Certificate expired or not yet valid',
    recommendation: 'Renew the certificate and implement automated certificate renewal (e.g. ACME protocol).',
    scoreDeduction: 15,
  },

  // 10. Public Key Algorithm
  {
    ruleId: 'PK-ALG-001',
    category: 'Public Key Algorithm',
    title: 'Approved Public Key Algorithm Assessment',
    description: 'Public key algorithms must be approved under NIST SP 800-57 (RSA, ECDSA with approved curves, or Ed25519).',
    severity: 'MEDIUM',
    source: {
      name: 'NIST SP 800-57 Part 1 Rev. 5',
      document: 'NIST SP 800-57 Part 1 Rev. 5',
      section: 'Section 5.6.1',
      reference: 'https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final',
    },
    condition: 'Public key algorithm is unapproved or weak',
    recommendation: 'Deploy RSA (>= 2048-bit) or ECDSA (secp256r1 / secp384r1) key pairs.',
    scoreDeduction: 8,
  },

  // 11. Public Key Length
  {
    ruleId: 'PK-LEN-001',
    category: 'Public Key Length',
    title: 'Sufficient Public Key Length (RSA >= 2048, ECC >= 256)',
    description: 'RSA keys shorter than 2048 bits provide fewer than 112 bits of security and are vulnerable to mathematical factorization.',
    severity: 'HIGH',
    source: {
      name: 'NIST SP 800-57 Part 1 Rev. 5',
      document: 'NIST SP 800-57 Part 1 Rev. 5',
      section: 'Section 5.6.1 Table 2',
      reference: 'https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final',
    },
    condition: 'RSA key length < 2048 bits or ECC key length < 256 bits',
    recommendation: 'Regenerate certificate private key with at least RSA 2048 bits or ECDSA P-256.',
    scoreDeduction: 12,
  },

  // 12. Signature Algorithm
  {
    ruleId: 'SIG-001',
    category: 'Signature Algorithm',
    title: 'Cryptographically Secure Signature Algorithm',
    description: 'Certificates signed with SHA-1 or MD5 are cryptographically vulnerable to collision attacks and must not be trusted.',
    severity: 'HIGH',
    source: {
      name: 'NIST SP 800-52 Rev. 2 / CA/B Forum',
      document: 'NIST SP 800-52 Rev. 2',
      section: 'Section 3.4.1',
      reference: 'https://csrc.nist.gov/pubs/sp/800/52/r2/final',
    },
    condition: 'Signature algorithm includes SHA-1, SHA1, or MD5',
    recommendation: 'Reissue certificates using SHA-256, SHA-384, or SHA-512 signature algorithms.',
    scoreDeduction: 10,
  },

  // 13. STARTTLS Security
  {
    ruleId: 'STARTTLS-001',
    category: 'STARTTLS Security',
    title: 'STARTTLS Negotiation & Enforcement',
    description: 'Mail agents advertising STARTTLS must complete the TLS upgrade without falling back to plaintext, preventing STARTTLS stripping attacks.',
    severity: 'HIGH',
    source: {
      name: 'RFC 3207',
      document: 'RFC 3207 SMTP over TLS',
      section: 'Section 4 & 5',
      reference: 'https://www.rfc-editor.org/rfc/rfc3207',
    },
    condition: 'STARTTLS advertised but handshake failed or unnegotiated',
    recommendation: 'Configure MTA with mandatory TLS encryption and monitor for active stripping.',
    scoreDeduction: 10,
  },

  // 14. Configuration Compliance
  {
    ruleId: 'COMP-001',
    category: 'Configuration Compliance',
    title: 'Observed Protocol Baseline Compliance',
    description: 'Observed cryptographic traffic must conform to baseline enterprise security policies and operational mandates.',
    severity: 'MEDIUM',
    source: {
      name: 'CISA Emergency Directive & Guidelines',
      document: 'CISA Secure Email Architecture Guidance',
      section: 'Section 3.1',
      reference: 'https://www.cisa.gov/resources-tools/guidance',
    },
    condition: 'Observed protocol lacks modern cryptographic safeguards',
    recommendation: 'Align mail server configurations with NIST and CISA security baselines.',
    scoreDeduction: 5,
  },

  // 15. Deprecated Cryptography
  {
    ruleId: 'DEP-001',
    category: 'Deprecated Cryptography',
    title: 'Absence of Deprecated Algorithms & Primitives',
    description: 'Ensure no deprecated algorithms (RC4, DES, 3DES, MD5, SHA-1, TLS 1.0, TLS 1.1) are actively negotiated in traffic.',
    severity: 'HIGH',
    source: {
      name: 'NIST SP 800-131A Rev. 2',
      document: 'NIST SP 800-131A Rev. 2',
      section: 'Section 3 & 4',
      reference: 'https://csrc.nist.gov/pubs/sp/800/131/a/r2/final',
    },
    condition: 'Deprecated cipher, hash, or protocol version observed',
    recommendation: 'Deprecate and remove legacy cryptographic suites from server configuration.',
    scoreDeduction: 15,
  },

  // 16. TLS Anomalies
  {
    ruleId: 'ANOM-001',
    category: 'TLS Anomalies',
    title: 'Anomalous Handshake & Downgrade Prevention',
    description: 'Detect unexpected protocol downgrade attempts, incomplete handshakes, or inconsistent TLS extensions.',
    severity: 'HIGH',
    source: {
      name: 'RFC 8446',
      document: 'RFC 8446 Appendix D (Downgrade Protection)',
      section: 'Appendix D',
      reference: 'https://www.rfc-editor.org/rfc/rfc8446#appendix-D',
    },
    condition: 'Downgrade signals or incomplete handshake detected in capture',
    recommendation: 'Enable TLS 1.3 downgrade protection sentinels and investigate network interference.',
    scoreDeduction: 10,
  },

  // 17. Configuration vs Observed mismatch
  {
    ruleId: 'MISMATCH-001',
    category: 'Configuration vs Observed mismatch',
    title: 'Lab / Policy Configuration Alignment',
    description: 'Observed network behavior must match the intended administrative policy. Discrepancies indicate misconfiguration or in-flight tampering.',
    severity: 'HIGH',
    source: {
      name: 'SecureMailScope Forensic Engine',
      document: 'SecureMailScope Cryptographic Verification Standard',
      section: 'Section 2.1',
      reference: 'Reference required',
    },
    condition: 'Comparison between configured policy and observed traffic indicates mismatch',
    recommendation: 'Investigate discrepancy between server policy and actual network observations.',
    scoreDeduction: 8,
  },
]

// ─── Evaluator Function ───────────────────────────────────────────────────────

export function evaluateSecurityRules(analysis: {
  configured: LabConfiguration | null
  observed: {
    protocol: ObservedProtocol
    starttls: ObservedStarttls
    tls: ObservedTls
    certificate: ObservedCertificate
  }
  configurationComparison: ConfigurationComparison | null
  capture: ObservedCapture
}): {
  results: SecurityRuleResult[]
  categorySummaries: CategorySummary[]
  cryptoStrength: CryptoStrengthItem[]
  configAssessment: ConfigAssessmentRow[]
  starttlsAssessment: { state: StarttlsState; label: string; description: string; reference: string }
} {
  const { configured, observed, configurationComparison: comp, capture } = analysis
  const results: SecurityRuleResult[] = []

  // 1. Protocol Security
  const protoEncrypted = observed.tls.handshakeComplete || (observed.starttls.advertised && observed.starttls.negotiated)
  const isPlaintext = observed.tls.version === 'None' || (!observed.tls.handshakeComplete && observed.starttls.plaintextPhaseObserved && !observed.starttls.negotiated)
  
  if (isPlaintext) {
    results.push(buildResult(
      findRule('PROTO-001'),
      'FAIL',
      'Plaintext unencrypted transmission',
      'Mandatory TLS transport',
      'All email data was transmitted in plaintext with no TLS encryption.',
      { source: 'PCAP', field: 'protocol.security', value: 'PLAINTEXT' },
      20
    ))
  } else {
    results.push(buildResult(
      findRule('PROTO-001'),
      'PASS',
      'Encrypted transport active',
      'Mandatory TLS transport',
      'Session successfully established cryptographic transport.',
      { source: 'PCAP', field: 'protocol.security', value: `${observed.protocol.detected} with ${observed.tls.version}` },
      0
    ))
  }

  // 2. TLS Version
  const tlsVer = observed.tls.version
  if (tlsVer === 'TLS1.0' || tlsVer === 'TLS1.1') {
    results.push(buildResult(
      findRule('TLS-001'),
      'FAIL',
      tlsVer,
      'TLS 1.2 or TLS 1.3',
      `${tlsVer} is deprecated by RFC 8996 and forbidden by NIST SP 800-52 Rev. 2.`,
      { source: 'PCAP', field: 'tls.version', value: tlsVer },
      tlsVer === 'TLS1.0' ? 18 : 14
    ))
  } else if (tlsVer === 'None') {
    results.push(buildResult(
      findRule('TLS-001'),
      'FAIL',
      'No TLS',
      'TLS 1.2 or TLS 1.3',
      'No TLS layer was initiated.',
      { source: 'PCAP', field: 'tls.version', value: 'None' },
      20
    ))
  } else {
    results.push(buildResult(
      findRule('TLS-001'),
      'PASS',
      tlsVer,
      'TLS 1.2 or TLS 1.3',
      `Modern TLS protocol version ${tlsVer} observed.`,
      { source: 'PCAP', field: 'tls.version', value: tlsVer },
      0
    ))
  }

  if (tlsVer === 'TLS1.3') {
    results.push(buildResult(
      findRule('TLS-002'),
      'PASS',
      'TLS 1.3',
      'TLS 1.3 preferred',
      'Optimal modern protocol version TLS 1.3 is actively negotiated.',
      { source: 'PCAP', field: 'tls.version', value: 'TLS 1.3' },
      0
    ))
  } else if (tlsVer === 'TLS1.2') {
    results.push(buildResult(
      findRule('TLS-002'),
      'WARNING',
      'TLS 1.2',
      'TLS 1.3 preferred',
      'TLS 1.2 is compliant but lacks TLS 1.3 zero-RTT and mandatory ephemeral key exchange.',
      { source: 'PCAP', field: 'tls.version', value: 'TLS 1.2' },
      4
    ))
  }

  // 3. Cipher Suite
  const cipher = observed.tls.cipherSuite || 'unknown'
  const isWeak = cipher.includes('3DES') || cipher.includes('RC4') || cipher === 'AES128-SHA' || cipher === 'AES256-SHA'
  if (isWeak) {
    results.push(buildResult(
      findRule('CIPHER-001'),
      'FAIL',
      cipher,
      'AEAD Ciphers (AES-GCM, ChaCha20-Poly1305)',
      `Weak/legacy cipher suite ${cipher} detected without authenticated encryption.`,
      { source: 'PCAP', field: 'tls.cipherSuite', value: cipher },
      18
    ))
  } else if (cipher === 'unknown' || cipher === 'not_observable') {
    results.push(buildResult(
      findRule('CIPHER-001'),
      'NOT_OBSERVABLE',
      'not_observable',
      'AEAD Ciphers',
      'Cipher suite could not be observed in the capture.',
      { source: 'PCAP', field: 'tls.cipherSuite', value: 'unknown' },
      0
    ))
  } else {
    results.push(buildResult(
      findRule('CIPHER-001'),
      'PASS',
      cipher,
      'AEAD Ciphers (AES-GCM, ChaCha20-Poly1305)',
      `Strong modern AEAD cipher suite ${cipher} negotiated.`,
      { source: 'PCAP', field: 'tls.cipherSuite', value: cipher },
      0
    ))
  }

  // 4. Cryptographic Strength
  let cryptoStatus: RuleStatus = 'PASS'
  let cryptoReason = 'Cryptographic parameters meet NIST SP 800-57 >= 112 bits requirement.'
  let cryptoDeduction = 0
  const pkLen = observed.certificate.publicKeyLength
  const pkAlg = observed.certificate.publicKeyAlgorithm

  if (pkAlg === 'RSA' && pkLen < 2048) {
    cryptoStatus = 'FAIL'
    cryptoReason = `RSA key length of ${pkLen} bits provides < 80 bits of security (NIST SP 800-57 Disallowed).`
    cryptoDeduction = 15
  } else if (isWeak) {
    cryptoStatus = 'FAIL'
    cryptoReason = `Cipher suite provides inadequate security strength.`
    cryptoDeduction = 12
  }

  results.push(buildResult(
    findRule('CRYPTO-001'),
    cryptoStatus,
    pkLen > 0 ? `${pkAlg}-${pkLen}, ${cipher}` : cipher,
    '>= 112 bits security strength (RSA >= 2048, AES >= 128)',
    cryptoReason,
    { source: 'PCAP', field: 'crypto.strength', value: `${pkAlg}-${pkLen}` },
    cryptoDeduction
  ))

  // 5. Key Exchange
  const kex = observed.tls.keyExchange || 'unknown'
  if (kex === 'RSA') {
    results.push(buildResult(
      findRule('KEX-001'),
      'FAIL',
      'Static RSA Key Exchange',
      'Ephemeral ECDHE or DHE',
      'Static RSA key exchange does not provide ephemeral forward secrecy.',
      { source: 'PCAP', field: 'tls.keyExchange', value: 'RSA' },
      10
    ))
  } else if (kex === 'ECDHE' || kex === 'DHE' || kex === 'X25519' || kex === 'X448' || tlsVer === 'TLS1.3') {
    results.push(buildResult(
      findRule('KEX-001'),
      'PASS',
      kex === 'unknown' && tlsVer === 'TLS1.3' ? 'ECDHE (TLS 1.3)' : kex,
      'Ephemeral ECDHE or DHE',
      'Ephemeral key exchange observed, protecting past communications.',
      { source: 'PCAP', field: 'tls.keyExchange', value: kex },
      0
    ))
  } else {
    results.push(buildResult(
      findRule('KEX-001'),
      'NOT_OBSERVABLE',
      kex,
      'Ephemeral ECDHE or DHE',
      'Key exchange parameters not directly observable in handshake.',
      { source: 'PCAP', field: 'tls.keyExchange', value: kex },
      0
    ))
  }

  // 6. Forward Secrecy
  const pfs = observed.tls.forwardSecrecy
  if (!pfs && tlsVer !== 'None') {
    results.push(buildResult(
      findRule('PFS-001'),
      'FAIL',
      'Forward Secrecy Disabled',
      'Forward Secrecy (PFS) Enabled',
      'Compromise of the server private key allows retroactive decryption of captured traffic.',
      { source: 'PCAP', field: 'tls.forwardSecrecy', value: 'false' },
      12
    ))
  } else {
    results.push(buildResult(
      findRule('PFS-001'),
      'PASS',
      'Forward Secrecy Enabled',
      'Forward Secrecy (PFS) Enabled',
      'Perfect Forward Secrecy is guaranteed by ephemeral key exchange.',
      { source: 'PCAP', field: 'tls.forwardSecrecy', value: 'true' },
      0
    ))
  }

  // 7. Certificate Security
  if (!observed.certificate.present) {
    results.push(buildResult(
      findRule('CERT-001'),
      'NOT_OBSERVABLE',
      'No certificate presented',
      'Valid X.509 Certificate',
      'No X.509 certificate was observed in this capture session.',
      { source: 'PCAP', field: 'certificate.present', value: 'false' },
      10
    ))
  } else if (observed.certificate.selfSigned) {
    results.push(buildResult(
      findRule('CERT-001'),
      'WARNING',
      `Self-Signed Certificate (${observed.certificate.commonName})`,
      'CA-Signed Certificate',
      'Self-signed certificate cannot be authenticated against trusted public root trust stores.',
      { source: 'PCAP', field: 'certificate.selfSigned', value: 'true' },
      10
    ))
  } else {
    results.push(buildResult(
      findRule('CERT-001'),
      'PASS',
      `CA-Issued: ${observed.certificate.commonName} by ${observed.certificate.issuer}`,
      'CA-Signed Certificate',
      'Certificate is signed by a recognized Certificate Authority.',
      { source: 'PCAP', field: 'certificate.issuer', value: observed.certificate.issuer },
      0
    ))
  }

  // 8. Certificate Chain
  if (observed.certificate.present) {
    if (!observed.certificate.chainValid) {
      results.push(buildResult(
        findRule('CHAIN-001'),
        'FAIL',
        'Invalid or incomplete certificate chain',
        'Complete valid trust chain',
        'The certificate chain is incomplete or failed validation.',
        { source: 'PCAP', field: 'certificate.chainValid', value: 'false' },
        12
      ))
    } else {
      results.push(buildResult(
        findRule('CHAIN-001'),
        'PASS',
        'Valid chain',
        'Complete valid trust chain',
        'Complete verifiable certificate chain observed.',
        { source: 'PCAP', field: 'certificate.chainValid', value: 'true' },
        0
      ))
    }
  }

  // 9. Certificate Expiration
  if (observed.certificate.present) {
    if (observed.certificate.expired) {
      results.push(buildResult(
        findRule('EXP-001'),
        'FAIL',
        `Expired on ${observed.certificate.validUntil}`,
        'Valid date range (validFrom <= now <= validUntil)',
        `Certificate expired on ${observed.certificate.validUntil}.`,
        { source: 'PCAP', field: 'certificate.validUntil', value: observed.certificate.validUntil },
        15
      ))
    } else if (observed.certificate.notYetValid) {
      results.push(buildResult(
        findRule('EXP-001'),
        'FAIL',
        `Not valid until ${observed.certificate.validFrom}`,
        'Valid date range',
        `Certificate validity start date is in the future: ${observed.certificate.validFrom}.`,
        { source: 'PCAP', field: 'certificate.validFrom', value: observed.certificate.validFrom },
        12
      ))
    } else {
      results.push(buildResult(
        findRule('EXP-001'),
        'PASS',
        `Valid until ${observed.certificate.validUntil}`,
        'Valid date range',
        'Certificate is within its active validity period.',
        { source: 'PCAP', field: 'certificate.validity', value: `${observed.certificate.validFrom} to ${observed.certificate.validUntil}` },
        0
      ))
    }
  }

  // 10. Public Key Algorithm
  if (observed.certificate.present) {
    const alg = observed.certificate.publicKeyAlgorithm
    if (alg === 'RSA' || alg === 'ECDSA' || alg === 'Ed25519') {
      results.push(buildResult(
        findRule('PK-ALG-001'),
        'PASS',
        alg,
        'NIST-Approved (RSA, ECDSA, Ed25519)',
        `Algorithm ${alg} is approved under NIST SP 800-57.`,
        { source: 'PCAP', field: 'certificate.publicKeyAlgorithm', value: alg },
        0
      ))
    } else {
      results.push(buildResult(
        findRule('PK-ALG-001'),
        'WARNING',
        alg,
        'Approved Algorithm',
        `Algorithm ${alg} may not conform to standard NIST specifications.`,
        { source: 'PCAP', field: 'certificate.publicKeyAlgorithm', value: alg },
        6
      ))
    }
  }

  // 11. Public Key Length
  if (observed.certificate.present) {
    if (pkAlg === 'RSA' && pkLen < 2048) {
      results.push(buildResult(
        findRule('PK-LEN-001'),
        'FAIL',
        `RSA ${pkLen}-bit`,
        'RSA >= 2048-bit (3072-bit recommended)',
        `RSA ${pkLen}-bit key is below the NIST SP 800-57 minimum of 2048 bits.`,
        { source: 'PCAP', field: 'certificate.publicKeyLength', value: `${pkLen}` },
        12
      ))
    } else if (pkAlg === 'RSA' && pkLen === 2048) {
      results.push(buildResult(
        findRule('PK-LEN-001'),
        'PASS',
        `RSA 2048-bit`,
        'RSA >= 2048-bit',
        'RSA 2048-bit meets current NIST 112-bit security requirements (acceptable through 2030).',
        { source: 'PCAP', field: 'certificate.publicKeyLength', value: `${pkLen}` },
        0
      ))
    } else if (pkAlg === 'RSA' && pkLen >= 3072) {
      results.push(buildResult(
        findRule('PK-LEN-001'),
        'PASS',
        `RSA ${pkLen}-bit (Strong)`,
        'RSA >= 2048-bit',
        `RSA ${pkLen}-bit provides 128+ bits of security strength.`,
        { source: 'PCAP', field: 'certificate.publicKeyLength', value: `${pkLen}` },
        0
      ))
    } else if (pkAlg === 'ECDSA' && pkLen >= 256) {
      results.push(buildResult(
        findRule('PK-LEN-001'),
        'PASS',
        `ECDSA ${pkLen}-bit`,
        'ECC >= 256-bit',
        `ECDSA ${pkLen}-bit provides >= 128 bits of security strength.`,
        { source: 'PCAP', field: 'certificate.publicKeyLength', value: `${pkLen}` },
        0
      ))
    }
  }

  // 12. Signature Algorithm
  if (observed.certificate.present) {
    const sig = observed.certificate.signatureAlgorithm
    if (sig.includes('SHA1') || sig.includes('MD5')) {
      results.push(buildResult(
        findRule('SIG-001'),
        'FAIL',
        sig,
        'SHA-256 or stronger (SHA-384, SHA-512)',
        `Weak signature algorithm ${sig} vulnerable to cryptographic collision attacks.`,
        { source: 'PCAP', field: 'certificate.signatureAlgorithm', value: sig },
        10
      ))
    } else {
      results.push(buildResult(
        findRule('SIG-001'),
        'PASS',
        sig,
        'SHA-256 or stronger',
        `Cryptographically secure signature algorithm ${sig} observed.`,
        { source: 'PCAP', field: 'certificate.signatureAlgorithm', value: sig },
        0
      ))
    }
  }

  // 13. STARTTLS Security
  const stls = observed.starttls
  if (stls.advertised && stls.negotiated) {
    results.push(buildResult(
      findRule('STARTTLS-001'),
      'PASS',
      'STARTTLS Advertised & Negotiated',
      'STARTTLS Upgrade Successful',
      'STARTTLS capability advertised and TLS upgrade completed seamlessly.',
      { source: 'PCAP', field: 'starttls.negotiated', value: 'true' },
      0
    ))
  } else if (stls.advertised && !stls.negotiated) {
    results.push(buildResult(
      findRule('STARTTLS-001'),
      'FAIL',
      'STARTTLS Advertised but Not Negotiated',
      'STARTTLS Upgrade Successful',
      'STARTTLS capability was advertised in EHLO response, but TLS handshake was never completed (possible downgrade/stripping).',
      { source: 'PCAP', field: 'starttls.negotiated', value: 'false' },
      10
    ))
  } else if (!stls.advertised && observed.protocol.detected === 'SMTP') {
    results.push(buildResult(
      findRule('STARTTLS-001'),
      'WARNING',
      'STARTTLS Not Advertised',
      'STARTTLS Supported',
      'The SMTP server did not advertise STARTTLS in response to EHLO.',
      { source: 'PCAP', field: 'starttls.advertised', value: 'false' },
      6
    ))
  } else {
    results.push(buildResult(
      findRule('STARTTLS-001'),
      'NOT_OBSERVABLE',
      'Direct TLS / Non-STARTTLS Port',
      'STARTTLS or Direct TLS',
      'Connection initiated via direct TLS port or non-SMTP protocol.',
      { source: 'PCAP', field: 'starttls.advertised', value: 'N/A' },
      0
    ))
  }

  // 14. Configuration Compliance
  const hasComplianceIssue = isWeak || tlsVer === 'TLS1.0' || tlsVer === 'TLS1.1' || !observed.tls.forwardSecrecy
  if (hasComplianceIssue) {
    results.push(buildResult(
      findRule('COMP-001'),
      'FAIL',
      'Non-compliant baseline configurations detected',
      'NIST & CISA baseline compliance',
      'Observed cryptographic features fall below minimum security baselines.',
      { source: 'PCAP', field: 'compliance.status', value: 'NON_COMPLIANT' },
      8
    ))
  } else {
    results.push(buildResult(
      findRule('COMP-001'),
      'PASS',
      'Compliant with NIST & CISA baselines',
      'NIST & CISA baseline compliance',
      'All observable cryptographic settings satisfy federal security baselines.',
      { source: 'PCAP', field: 'compliance.status', value: 'COMPLIANT' },
      0
    ))
  }

  // 15. Deprecated Cryptography
  const deprecatedItems: string[] = []
  if (tlsVer === 'TLS1.0' || tlsVer === 'TLS1.1') deprecatedItems.push(tlsVer)
  if (isWeak) deprecatedItems.push(cipher)
  if (observed.certificate.present && (observed.certificate.signatureAlgorithm.includes('SHA1') || observed.certificate.signatureAlgorithm.includes('MD5'))) {
    deprecatedItems.push(observed.certificate.signatureAlgorithm)
  }

  if (deprecatedItems.length > 0) {
    results.push(buildResult(
      findRule('DEP-001'),
      'FAIL',
      deprecatedItems.join(', '),
      'No deprecated cryptography',
      `Deprecated primitives actively utilized in session: ${deprecatedItems.join(', ')}.`,
      { source: 'PCAP', field: 'crypto.deprecated', value: deprecatedItems.join(', ') },
      15
    ))
  } else {
    results.push(buildResult(
      findRule('DEP-001'),
      'PASS',
      'None detected',
      'No deprecated cryptography',
      'No deprecated or retired cryptographic primitives observed in the capture.',
      { source: 'PCAP', field: 'crypto.deprecated', value: 'NONE' },
      0
    ))
  }

  // 16. TLS Anomalies
  const anomaliesCount = (comp?.mismatches.length || 0) + (stls.advertised && !stls.negotiated ? 1 : 0)
  if (anomaliesCount > 0) {
    results.push(buildResult(
      findRule('ANOM-001'),
      'WARNING',
      `${anomaliesCount} anomaly pattern(s) identified`,
      'Zero anomalous downgrade signals',
      'Anomalous traffic patterns or discrepancies observed between session intent and capture execution.',
      { source: 'PCAP', field: 'anomalies.count', value: String(anomaliesCount) },
      10
    ))
  } else {
    results.push(buildResult(
      findRule('ANOM-001'),
      'PASS',
      'No anomalies detected',
      'Zero anomalous downgrade signals',
      'Clean TLS handshake and execution profile observed.',
      { source: 'PCAP', field: 'anomalies.count', value: '0' },
      0
    ))
  }

  // 17. Configuration vs Observed mismatch
  if (comp) {
    if (comp.mismatches.length > 0) {
      results.push(buildResult(
        findRule('MISMATCH-001'),
        'FAIL',
        `${comp.mismatches.length} mismatch(es): ${comp.mismatches.join(', ')}`,
        'Configured parameters equal observed parameters',
        `Administrative configuration does not match wire capture: ${comp.mismatches.join(', ')}.`,
        { source: 'Manifest vs PCAP', field: 'mismatches', value: comp.mismatches.join(', ') },
        8
      ))
    } else {
      results.push(buildResult(
        findRule('MISMATCH-001'),
        'PASS',
        'Full alignment (0 mismatches)',
        'Configured parameters equal observed parameters',
        'Configured parameters verified identical to wire-level packet captures.',
        { source: 'Manifest vs PCAP', field: 'mismatches', value: 'NONE' },
        0
      ))
    }
  } else {
    results.push(buildResult(
      findRule('MISMATCH-001'),
      'NOT_OBSERVABLE',
      'No lab configuration metadata embedded in capture',
      'Comparison against policy',
      'External PCAP file without embedded SecureMailScope lab configuration metadata.',
      { source: 'PCAP', field: 'metadata.integrity', value: 'missing' },
      0
    ))
  }

  // ── Category Summaries ──────────────────────────────────────────────────────
  const categoryNames = [
    'Protocol Security',
    'TLS Version',
    'Cipher Suite',
    'Cryptographic Strength',
    'Key Exchange',
    'Forward Secrecy',
    'Certificate Security',
    'Certificate Chain',
    'Certificate Expiration',
    'Public Key Algorithm',
    'Public Key Length',
    'Signature Algorithm',
    'STARTTLS Security',
    'Configuration Compliance',
    'Deprecated Cryptography',
    'TLS Anomalies',
    'Configuration vs Observed mismatch',
  ]

  const categorySummaries: CategorySummary[] = categoryNames.map((cat) => {
    const catRules = results.filter((r) => r.category === cat)
    if (!catRules.length) {
      return { category: cat, status: 'NOT_OBSERVABLE', passedRules: 0, totalRules: 0, details: 'Not observable in capture' }
    }
    const hasFail = catRules.some((r) => r.status === 'FAIL')
    const hasWarning = catRules.some((r) => r.status === 'WARNING')
    const status: RuleStatus = hasFail ? 'FAIL' : hasWarning ? 'WARNING' : 'PASS'
    const passed = catRules.filter((r) => r.status === 'PASS').length
    const details = catRules.map((r) => r.reason).join(' ')
    return {
      category: cat,
      status,
      passedRules: passed,
      totalRules: catRules.length,
      details,
    }
  })

  // ── Cryptographic Strength (NIST SP 800-57) ──────────────────────────────────
  const cryptoStrength: CryptoStrengthItem[] = [
    {
      component: 'Public Key',
      algorithm: pkAlg || 'Not observable',
      parameter: pkLen ? `${pkLen}-bit` : 'N/A',
      estimatedSecurityStrength: pkAlg === 'RSA'
        ? pkLen < 2048 ? '< 80 bits (Disallowed)' : pkLen === 2048 ? '112 bits (Acceptable through 2030)' : '128+ bits (Strong)'
        : pkAlg === 'ECDSA' ? '>= 128 bits (Strong)' : 'Not observable',
      status: pkAlg === 'RSA'
        ? pkLen < 2048 ? 'DEPRECATED' : pkLen === 2048 ? 'ACCEPTABLE' : 'STRONG'
        : pkAlg === 'ECDSA' ? 'STRONG' : 'NOT_OBSERVABLE',
      source: 'NIST SP 800-57 Part 1 Rev. 5 Section 5.6.1 Table 2',
      notes: pkAlg === 'RSA' && pkLen < 2048 ? 'Factorable by well-resourced adversaries' : 'Complies with NIST recommendations',
    },
    {
      component: 'Bulk Encryption',
      algorithm: cipher.includes('AES_256') || cipher.includes('AES256') ? 'AES-256' : cipher.includes('AES_128') || cipher.includes('AES128') ? 'AES-128' : cipher.includes('3DES') ? '3DES' : cipher,
      parameter: cipher.includes('256') ? '256-bit key' : cipher.includes('128') ? '128-bit key' : 'Legacy key size',
      estimatedSecurityStrength: cipher.includes('256') ? '256 bits' : cipher.includes('128') ? '128 bits' : '< 80 bits (Disallowed)',
      status: cipher.includes('256') ? 'STRONG' : cipher.includes('128') ? 'ACCEPTABLE' : cipher.includes('3DES') ? 'DEPRECATED' : 'NOT_OBSERVABLE',
      source: 'NIST SP 800-57 Part 1 Rev. 5 Section 5.6.1 Table 2',
      notes: cipher.includes('GCM') || cipher.includes('POLY1305') ? 'AEAD mode provides integrity and confidentiality' : 'Lacks modern AEAD authentication',
    },
    {
      component: 'Key Exchange Group',
      algorithm: observed.tls.keyExchange || (tlsVer === 'TLS1.3' ? 'ECDHE' : 'RSA'),
      parameter: observed.tls.namedGroup !== 'unknown' ? observed.tls.namedGroup : (tlsVer === 'TLS1.3' ? 'X25519' : 'Standard Group'),
      estimatedSecurityStrength: observed.tls.namedGroup === 'X25519' || observed.tls.namedGroup === 'secp256r1' ? '128 bits' : tlsVer === 'TLS1.3' ? '128 bits' : observed.tls.keyExchange === 'RSA' ? '0 bits (Static)' : '112+ bits',
      status: observed.tls.forwardSecrecy ? 'STRONG' : 'DEPRECATED',
      source: 'NIST SP 800-57 Part 1 Rev. 5 Section 5.6.1 Table 2',
      notes: observed.tls.forwardSecrecy ? 'Provides Perfect Forward Secrecy' : 'Static key exchange lacks forward secrecy',
    },
    {
      component: 'Signature Hash',
      algorithm: observed.certificate.signatureAlgorithm || 'Not observable',
      parameter: observed.certificate.signatureAlgorithm.includes('SHA256') ? 'SHA-256 (256-bit)' : observed.certificate.signatureAlgorithm.includes('SHA384') ? 'SHA-384 (384-bit)' : 'Legacy digest',
      estimatedSecurityStrength: observed.certificate.signatureAlgorithm.includes('SHA256') ? '128 bits' : observed.certificate.signatureAlgorithm.includes('SHA384') ? '192 bits' : '< 80 bits (Broken)',
      status: observed.certificate.signatureAlgorithm.includes('SHA1') || observed.certificate.signatureAlgorithm.includes('MD5') ? 'DEPRECATED' : observed.certificate.present ? 'STRONG' : 'NOT_OBSERVABLE',
      source: 'NIST SP 800-57 Part 1 Rev. 5 Section 5.6.1 Table 3',
      notes: observed.certificate.signatureAlgorithm.includes('SHA1') ? 'SHA-1 collision attacks practical' : 'Collision resistant',
    },
  ]

  // ── Cryptographic Configuration Assessment ──────────────────────────────────
  const cfg = configured
  const configAssessment: ConfigAssessmentRow[] = [
    {
      parameter: 'Protocol',
      configured: cfg?.email.protocol ?? 'N/A',
      observed: observed.protocol.detected,
      status: cfg ? (cfg.email.protocol === observed.protocol.detected ? 'MATCH' : 'MISMATCH') : 'NOT_OBSERVABLE',
      standardReference: 'RFC 5321 / RFC 9051',
    },
    {
      parameter: 'Port',
      configured: cfg ? String(cfg.email.port) : 'N/A',
      observed: String(observed.protocol.port),
      status: cfg ? (cfg.email.port === observed.protocol.port ? 'MATCH' : 'MISMATCH') : 'NOT_OBSERVABLE',
      standardReference: 'RFC 8314',
    },
    {
      parameter: 'STARTTLS',
      configured: cfg ? (cfg.email.starttls ? 'Enabled' : 'Disabled') : 'N/A',
      observed: observed.starttls.advertised ? 'Advertised' : 'Not Advertised',
      status: cfg ? ((cfg.email.starttls === observed.starttls.advertised) ? 'MATCH' : 'MISMATCH') : 'NOT_OBSERVABLE',
      standardReference: 'RFC 3207 Section 4',
    },
    {
      parameter: 'TLS Version',
      configured: cfg?.tls.version ?? 'N/A',
      observed: observed.tls.version,
      status: cfg ? (cfg.tls.version === observed.tls.version ? 'MATCH' : 'MISMATCH') : 'NOT_OBSERVABLE',
      standardReference: 'NIST SP 800-52 Rev. 2 / RFC 8996',
    },
    {
      parameter: 'Cipher Suite',
      configured: cfg?.tls.cipherSuite ?? 'N/A',
      observed: observed.tls.cipherSuite,
      status: cfg ? (cfg.tls.cipherSuite === observed.tls.cipherSuite ? 'MATCH' : 'MISMATCH') : 'NOT_OBSERVABLE',
      standardReference: 'NIST SP 800-52 Rev. 2 Section 3.3.1',
    },
    {
      parameter: 'Key Exchange',
      configured: cfg?.tls.keyExchange ?? 'N/A',
      observed: observed.tls.keyExchange,
      status: cfg ? (cfg.tls.keyExchange === observed.tls.keyExchange ? 'MATCH' : 'MISMATCH') : 'NOT_OBSERVABLE',
      standardReference: 'NIST SP 800-52 Rev. 2 Section 3.3.2',
    },
    {
      parameter: 'Named Group',
      configured: cfg?.tls.namedGroup ?? 'N/A',
      observed: observed.tls.namedGroup,
      status: cfg ? (cfg.tls.namedGroup === observed.tls.namedGroup ? 'MATCH' : 'MISMATCH') : 'NOT_OBSERVABLE',
      standardReference: 'RFC 8446 Section 4.2.7',
    },
    {
      parameter: 'Forward Secrecy',
      configured: cfg ? (cfg.tls.forwardSecrecy ? 'Enforced' : 'None') : 'N/A',
      observed: observed.tls.forwardSecrecy ? 'Enforced' : 'None',
      status: cfg ? (cfg.tls.forwardSecrecy === observed.tls.forwardSecrecy ? 'MATCH' : 'MISMATCH') : 'NOT_OBSERVABLE',
      standardReference: 'CISA Guidance Section 4.2',
    },
    {
      parameter: 'Certificate Present',
      configured: cfg?.certificate.enabled ? 'Yes' : 'N/A',
      observed: observed.certificate.present ? 'Yes' : 'No',
      status: observed.certificate.present ? 'PASS' : 'FAIL',
      standardReference: 'CA/B Forum Baseline Requirements Section 6.1.5',
    },
    {
      parameter: 'Certificate Validity',
      configured: cfg?.certificate.scenario === 'expired' ? 'Expired' : 'Valid',
      observed: observed.certificate.expired ? 'Expired' : observed.certificate.notYetValid ? 'Not Yet Valid' : 'Valid',
      status: observed.certificate.expired || observed.certificate.notYetValid ? 'FAIL' : 'PASS',
      standardReference: 'CA/B Forum Baseline Requirements Section 6.3.2',
    },
    {
      parameter: 'Certificate Chain',
      configured: cfg?.certificate.chainValid ? 'Valid' : 'Invalid',
      observed: observed.certificate.chainValid ? 'Valid' : 'Invalid',
      status: observed.certificate.chainValid ? 'PASS' : 'FAIL',
      standardReference: 'RFC 8446 Section 4.4.2',
    },
    {
      parameter: 'Public Key Algorithm',
      configured: cfg?.certificate.publicKeyAlgorithm ?? 'N/A',
      observed: observed.certificate.publicKeyAlgorithm,
      status: cfg ? (cfg.certificate.publicKeyAlgorithm === observed.certificate.publicKeyAlgorithm ? 'MATCH' : 'MISMATCH') : 'PASS',
      standardReference: 'NIST SP 800-57 Section 5.6.1',
    },
    {
      parameter: 'Public Key Length',
      configured: cfg ? `${cfg.certificate.publicKeyLength} bits` : 'N/A',
      observed: observed.certificate.publicKeyLength ? `${observed.certificate.publicKeyLength} bits` : 'N/A',
      status: observed.certificate.publicKeyLength >= 2048 ? 'PASS' : (observed.certificate.publicKeyLength > 0 ? 'FAIL' : 'NOT_OBSERVABLE'),
      standardReference: 'NIST SP 800-57 Table 2',
    },
    {
      parameter: 'Signature Algorithm',
      configured: cfg?.certificate.signatureAlgorithm ?? 'N/A',
      observed: observed.certificate.signatureAlgorithm,
      status: observed.certificate.signatureAlgorithm.includes('SHA1') ? 'FAIL' : 'PASS',
      standardReference: 'NIST SP 800-52 Rev. 2 Section 3.4.1',
    },
  ]

  // ── STARTTLS State Assessment (Section 12) ──────────────────────────────────
  let starttlsState: StarttlsState = 'NOT_OBSERVABLE'
  let starttlsLabel = 'Not Observable'
  let starttlsDesc = 'STARTTLS negotiation was not observable in the captured stream.'

  if (stls.advertised && stls.negotiated) {
    starttlsState = 'SECURE_UPGRADE'
    starttlsLabel = 'SECURE UPGRADE'
    starttlsDesc = 'STARTTLS command executed and successfully upgraded plaintext channel to encrypted TLS session.'
  } else if (stls.advertised && !stls.negotiated) {
    starttlsState = 'STARTTLS_ADVERTISED_NOT_USED'
    starttlsLabel = 'STARTTLS ADVERTISED BUT NOT USED'
    starttlsDesc = 'Server offered STARTTLS capability in EHLO response, but client did not initiate or complete TLS upgrade (vulnerable to downgrade).'
  } else if (!stls.advertised && isPlaintext) {
    starttlsState = 'PLAINTEXT_ONLY'
    starttlsLabel = 'PLAINTEXT ONLY'
    starttlsDesc = 'No STARTTLS capability advertised or negotiated; complete email transaction occurred in unencrypted plaintext.'
  } else if (!stls.advertised && observed.protocol.detected === 'SMTP') {
    starttlsState = 'STARTTLS_NOT_ADVERTISED'
    starttlsLabel = 'STARTTLS NOT ADVERTISED'
    starttlsDesc = 'The mail server did not include 250-STARTTLS in its EHLO response capabilities.'
  }

  return {
    results,
    categorySummaries,
    cryptoStrength,
    configAssessment,
    starttlsAssessment: {
      state: starttlsState,
      label: starttlsLabel,
      description: starttlsDesc,
      reference: 'RFC 3207 / NIST SP 800-52 Rev. 2',
    },
  }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function findRule(ruleId: string): SecurityRuleDefinition {
  const rule = SECURITY_RULES.find((r) => r.ruleId === ruleId)
  if (!rule) {
    throw new Error(`Security rule definition not found for ruleId: ${ruleId}`)
  }
  return rule
}

function buildResult(
  rule: SecurityRuleDefinition,
  status: RuleStatus,
  observedVal: string,
  expectedVal: string,
  reason: string,
  evidence: { source: string; field: string; value: string },
  scoreImpact: number
): SecurityRuleResult {
  return {
    ruleId: rule.ruleId,
    category: rule.category,
    title: rule.title,
    status,
    severity: rule.severity,
    observed: observedVal,
    expected: expectedVal,
    reason,
    evidence,
    standard: rule.source,
    recommendation: rule.recommendation,
    scoreImpact,
  }
}
