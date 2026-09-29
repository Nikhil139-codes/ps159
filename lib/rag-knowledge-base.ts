/**
 * SecureMailScope RAG Knowledge Base & Retrieval Engine
 *
 * Implements:
 * 1. Structured Knowledge Base of Authoritative Security Standards:
 *    - NIST SP 800-52 Rev. 2 (Selection, Configuration, and Use of TLS)
 *    - NIST SP 800-57 Part 1 Rev. 5 (Recommendation for Key Management)
 *    - RFC 8996 (Deprecating TLS 1.0 and TLS 1.1)
 *    - RFC 8446 (The TLS Protocol Version 1.3)
 *    - RFC 5246 (The TLS Protocol Version 1.2)
 *    - RFC 3207 (SMTP Service Extension for Secure SMTP over TLS)
 *    - RFC 2595 (Using TLS with IMAP, POP3)
 *    - CISA Guidance (Secure Communications & Email Architecture)
 *    - CA/Browser Forum Baseline Requirements (X.509 Certificate Validity)
 *    - NIST SP 800-131A Rev. 2 (Transitioning Cryptographic Algorithms)
 *
 * 2. Canonical Analysis Context Construction
 * 3. Question Understanding & Relevant Context Retrieval
 * 4. Context Assembly for LLM
 * 5. Deterministic Analysis-Grounded Response Generator (Groq fallback)
 */

import type {
  CanonicalAnalysis,
  SecurityFinding,
  SecurityScore,
  ObservedCapture,
  ObservedProtocol,
  ObservedStarttls,
  ObservedTls,
  ObservedCertificate,
  ConfigurationComparison,
} from './types'
import { evaluateSecurityRules } from './security-rules'

// ─── Standards Knowledge Document Chunk ──────────────────────────────────────

export interface StandardKnowledgeDoc {
  id: string
  standard: string
  title: string
  section: string
  reference: string
  content: string
  keywords: string[]
  category: string
}

export const KNOWLEDGE_BASE_DOCS: StandardKnowledgeDoc[] = [
  {
    id: 'RFC-8996-DEPRECATION',
    standard: 'RFC 8996 / BCP 195',
    title: 'Deprecating TLS 1.0 and TLS 1.1',
    section: 'Section 1 & 2',
    reference: 'https://www.rfc-editor.org/rfc/rfc8996',
    category: 'TLS Version',
    keywords: ['tls 1.0', 'tls 1.1', 'deprecated', 'deprecation', 'poodle', 'beast', 'downgrade', 'legacy', 'insecure', 'protocol version'],
    content: `RFC 8996 formally deprecates Transport Layer Security (TLS) versions 1.0 (RFC 2246) and 1.1 (RFC 4366). These versions lack support for modern authenticated encryption with associated data (AEAD) cipher suites, rely on weak initialization vector (IV) derivations that permit CBC-mode chosen-plaintext attacks (BEAST, POODLE), and utilize legacy SHA-1 and MD5 hashes in signatures and handshake message verification. RFC 8996 mandates that clients and servers MUST NOT negotiate TLS 1.0 or TLS 1.1. Any mail server offering or negotiating TLS 1.0 or 1.1 fails baseline compliance and exposes traffic to active downgrade interception.`,
  },
  {
    id: 'NIST-800-52-TLS-VERSIONS',
    standard: 'NIST SP 800-52 Rev. 2',
    title: 'Selection, Configuration, and Use of TLS: Protocol Versions',
    section: 'Section 3.1.1',
    reference: 'https://csrc.nist.gov/pubs/sp/800/52/r2/final',
    category: 'TLS Version',
    keywords: ['nist', 'sp 800-52', 'tls 1.2', 'tls 1.3', 'version', 'government', 'compliance', 'guidance'],
    content: `NIST SP 800-52 Rev. 2 mandates that government and secure enterprise TLS servers SHALL be configured to support TLS 1.2 and SHOULD be configured to support TLS 1.3. Servers SHALL NOT be configured to use TLS 1.0 or TLS 1.1. Servers configured for TLS 1.3 achieve reduced handshake latency, mandatory Perfect Forward Secrecy (PFS), and exclusive use of AEAD ciphers, eliminating obsolete cryptographic mechanisms including static RSA key exchange and custom finite-field Diffie-Hellman parameters.`,
  },
  {
    id: 'NIST-800-52-CIPHER-SUITES',
    standard: 'NIST SP 800-52 Rev. 2',
    title: 'Cipher Suite Selection & AEAD Requirements',
    section: 'Section 3.3.1',
    reference: 'https://csrc.nist.gov/pubs/sp/800/52/r2/final',
    category: 'Cipher Suite',
    keywords: ['cipher', 'ciphersuite', 'aead', 'aes-gcm', 'chacha20', '3des', 'cbc', 'rc4', 'weak cipher', 'encrypt-then-mac'],
    content: `NIST SP 800-52 Rev. 2 specifies that TLS servers SHALL use AEAD cipher suites when TLS 1.2 or TLS 1.3 is negotiated. Preferred suites include TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, and ECDHE-RSA/ECDSA-AES-GCM. Cipher suites using 3DES (Triple-DES) are strictly forbidden due to 64-bit block size Sweet32 collision attacks. CBC-mode cipher suites without Encrypt-then-MAC extension are vulnerable to padding oracle attacks (Lucky Thirteen) and should be disabled.`,
  },
  {
    id: 'NIST-800-57-KEY-STRENGTH',
    standard: 'NIST SP 800-57 Part 1 Rev. 5',
    title: 'Cryptographic Security Strengths and Key Sizes',
    section: 'Section 5.6.1 Table 2 & 4',
    reference: 'https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final',
    category: 'Cryptographic Strength',
    keywords: ['rsa', 'rsa 2048', 'rsa 1024', 'key size', 'bits of security', '112-bit', '128-bit', 'ecc', 'ecdsa', 'curve', 'p-256', 'nist sp 800-57'],
    content: `NIST SP 800-57 Part 1 Rev. 5 establishes cryptographic security strength equivalencies. As of 2014, keys providing less than 112 bits of security strength are disallowed for all cryptographic protections. RSA 1024-bit keys offer only ~80 bits of security strength and are deemed cracked/insecure. RSA 2048-bit provides 112 bits of security (acceptable for legacy compatibility, acceptable through 2030). RSA 3072-bit and ECC P-256 provide 128 bits of security strength, which is the current recommended minimum for secure enterprise communications. Symmetric ciphers must use AES-128 or AES-256 (128/256 bits).`,
  },
  {
    id: 'NIST-800-52-KEY-EXCHANGE-PFS',
    standard: 'NIST SP 800-52 Rev. 2',
    title: 'Ephemeral Key Exchange and Forward Secrecy Mandate',
    section: 'Section 3.3.2',
    reference: 'https://csrc.nist.gov/pubs/sp/800/52/r2/final',
    category: 'Forward Secrecy',
    keywords: ['pfs', 'forward secrecy', 'ephemeral', 'ecdhe', 'dhe', 'static rsa', 'key exchange', 'retrospective decryption', 'private key'],
    content: `NIST SP 800-52 Rev. 2 Section 3.3.2 mandates ephemeral Diffie-Hellman key agreement (ECDHE or DHE) for TLS connections to achieve Perfect Forward Secrecy (PFS). In static RSA key exchange (where the client encrypts a premaster secret with the server public key), compromise of the server long-term private key allows retrospective decryption of all historically recorded encrypted traffic. PFS ensures that session keys are generated dynamically and discarded immediately after session termination, preventing retroactive eavesdropping.`,
  },
  {
    id: 'RFC-3207-STARTTLS-SECURITY',
    standard: 'RFC 3207',
    title: 'SMTP Service Extension for Secure SMTP over TLS',
    section: 'Section 4 & 5',
    reference: 'https://www.rfc-editor.org/rfc/rfc3207',
    category: 'STARTTLS Security',
    keywords: ['starttls', 'smtp', 'stripping', 'downgrade', 'ehlo', 'plaintext', 'rfc 3207', 'mandatory tls', 'mitm'],
    content: `RFC 3207 defines STARTTLS for SMTP. Because SMTP begins over a plaintext socket, an active adversary performing a Man-in-the-Middle (MITM) attack can intercept the 250-STARTTLS advertisement and strip it from the EHLO response. This causes the client to believe TLS is unsupported and fall back to transmitting email credentials and message bodies in cleartext. To prevent STARTTLS stripping, organizations must enforce mandatory TLS (rejecting delivery if STARTTLS cannot be negotiated) and deploy MTA-STS (RFC 8461) or DANE (RFC 7672) policy pinning.`,
  },
  {
    id: 'CABF-CERTIFICATE-REQUIREMENTS',
    standard: 'CA/Browser Forum Baseline Requirements',
    title: 'X.509 Certificate Validity and Key Requirements',
    section: 'Section 6.1.5 & 6.3.2',
    reference: 'https://cabforum.org/baseline-requirements-documents/',
    category: 'Certificate Security',
    keywords: ['certificate', 'cert', 'expired', 'validity', 'ca/b forum', 'baseline requirements', 'self-signed', 'chain', 'intermediate', 'sha-1', 'sha-256'],
    content: `The CA/Browser Forum Baseline Requirements specify that publicly trusted certificates must not have a validity period exceeding 398 days (Section 6.3.2). Certificates must be issued by an audited Certification Authority; self-signed certificates or untrusted chains cause strict TLS clients to abort the handshake or present security warnings that encourage insecure user bypass. Subscriber certificates must use RSA keys of at least 2048 bits or ECC curves NIST P-256, P-384, or P-521. Signatures must use SHA-256 or stronger; SHA-1 and MD5 are strictly prohibited due to collision attacks.`,
  },
  {
    id: 'CISA-EMAIL-SECURITY-GUIDANCE',
    standard: 'CISA Secure Email Architecture Guidance',
    title: 'Securing Federal and Critical Enterprise Email Communications',
    section: 'Section 3 & 4',
    reference: 'https://www.cisa.gov/resources-tools/guidance',
    category: 'Protocol Security',
    keywords: ['cisa', 'email security', 'directive', 'bod 18-01', 'mta-sts', 'dane', 'smtp', 'imap', 'pop3', 'transport security'],
    content: `CISA Email Security Guidance (and Binding Operational Directive BOD 18-01) mandates that all email communications entering or leaving an organization must enforce transport encryption. Mail transfer agents must disable insecure legacy protocols (TLS 1.0, TLS 1.1, SSLv3), reject plain unencrypted POP3/IMAP/SMTP authentication, mandate STARTTLS on port 587/25, and implement DNS-based Authentication of Named Entities (DANE) or Mail Transfer Agent Strict Transport Security (MTA-STS) to authenticate mail exchange partners.`,
  },
  {
    id: 'RFC-8446-TLS13-ARCHITECTURE',
    standard: 'RFC 8446',
    title: 'The Transport Layer Security (TLS) Protocol Version 1.3',
    section: 'Section 4.4 & Appendix D',
    reference: 'https://www.rfc-editor.org/rfc/rfc8446',
    category: 'TLS Anomalies',
    keywords: ['tls 1.3', 'rfc 8446', 'handshake', 'downgrade protection', 'sentinel', '0-rtt', 'encrypted extensions', 'anti-downgrade'],
    content: `RFC 8446 defines TLS 1.3. A core architectural improvement is embedded anti-downgrade sentinels: when a TLS 1.3-capable server falls back to TLS 1.2 or below due to client negotiation, it overwrites the last 8 bytes of the ServerHello.random with a deterministic sentinel string ('DOWNGRD\x01' or 'DOWNGRD\x00'). If a modern client observes a downgraded version but detects the sentinel, it knows a network attacker interfered with the ClientHello and terminates the connection with an illegal_parameter alert.`,
  },
  {
    id: 'NIST-800-131A-DEPRECATED-CRYPTO',
    standard: 'NIST SP 800-131A Rev. 2',
    title: 'Transitioning the Use of Cryptographic Algorithms and Key Lengths',
    section: 'Section 3 & 4',
    reference: 'https://csrc.nist.gov/pubs/sp/800/131/a/r2/final',
    category: 'Deprecated Cryptography',
    keywords: ['nist sp 800-131a', 'sha-1', 'md5', 'rc4', '3des', 'des', 'deprecated cryptography', 'algorithm transition'],
    content: `NIST SP 800-131A Rev. 2 establishes the formal deprecation and transition schedule for federal cryptographic algorithms. SHA-1 for digital signatures was disallowed after 2013; Triple-DES (3DES) usage for encryption was restricted and transitioned to disallowed due to SWEET32 vulnerabilities; key lengths under 2048-bit RSA or 224-bit ECC are completely disallowed. Primitives not meeting current security strengths must not be used in production communications.`,
  },
]

// ─── Canonical Analysis RAG Context ──────────────────────────────────────────

export interface AnalysisRAGContext {
  capture: {
    filename: string
    format: string
    packetCount: number
    durationSeconds: number
    sourceIp: string
    destinationIp: string
    sourcePort: number
    destinationPort: number
    metadataIntegrity: string
  }
  protocolAnalysis: {
    protocol: string
    port: number
    confidence: string
    starttlsAdvertised: boolean
    starttlsNegotiated: boolean
    starttlsRequired: boolean
    plaintextPhaseObserved: boolean
  }
  tlsAnalysis: {
    version: string
    cipherSuite: string
    keyExchange: string
    namedGroup: string
    forwardSecrecy: boolean
    handshakeComplete: boolean
  }
  certificateAnalysis: {
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
  cryptographicAnalysis: {
    strengthSummary: string
    categoriesEvaluated: number
  }
  configuration: Record<string, unknown> | null
  observed: Record<string, unknown>
  comparison: Record<string, unknown> | null
  securityScore: {
    total: number
    grade: string
    level: string
    deductions: Array<{ reason: string; severity: string; points: number }>
    breakdown: Record<string, number>
  }
  findings: Array<{
    id: string
    category: string
    severity: string
    title: string
    description: string
    evidence: string
    impact: string
    recommendation: string
    deduction: number
  }>
  anomalies: Array<{
    type: string
    severity: string
    evidence: string
    configured?: string
    observed?: string
  }>
  recommendations: string[]
  references: Array<{ name: string; document: string; section: string; reference: string }>
}

/**
 * Builds the canonical structured context object from a CanonicalAnalysis.
 * This guarantees no raw PCAP binary data is ever transmitted.
 */
export function buildAnalysisRAGContext(analysis: CanonicalAnalysis): AnalysisRAGContext {
  const evaluated = evaluateSecurityRules({
    configured: analysis.configured,
    observed: analysis.observed,
    configurationComparison: analysis.configurationComparison,
    capture: analysis.capture,
  })

  const mappedFindings = analysis.findings.map((f) => ({
    id: f.id,
    category: f.category,
    severity: f.severity,
    title: f.title,
    description: f.description,
    evidence:
      typeof f.evidence === 'string'
        ? f.evidence
        : JSON.stringify(f.evidence),
    impact: f.impact,
    recommendation: f.recommendation,
    deduction: f.deduction,
  }))

  const mappedAnomalies = analysis.anomalies.map((a) => ({
    type: a.type,
    severity: a.severity,
    evidence: a.evidence,
    configured: a.configured,
    observed: a.observed,
  }))

  const standardsReferences = [
    {
      name: 'NIST SP 800-52 Rev. 2',
      document: 'Guidelines for the Selection, Configuration, and Use of TLS',
      section: 'Section 3.1 - 3.4',
      reference: 'https://csrc.nist.gov/pubs/sp/800/52/r2/final',
    },
    {
      name: 'NIST SP 800-57 Part 1 Rev. 5',
      document: 'Recommendation for Key Management: Cryptographic Security Strengths',
      section: 'Section 5.6.1 Table 2 & 4',
      reference: 'https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final',
    },
    {
      name: 'RFC 8996',
      document: 'Deprecating TLS 1.0 and TLS 1.1 (BCP 195)',
      section: 'Sections 1 - 2',
      reference: 'https://www.rfc-editor.org/rfc/rfc8996',
    },
    {
      name: 'RFC 8446',
      document: 'The Transport Layer Security (TLS) Protocol Version 1.3',
      section: 'Section 4.4 & Appendix D',
      reference: 'https://www.rfc-editor.org/rfc/rfc8446',
    },
    {
      name: 'RFC 3207',
      document: 'SMTP Service Extension for Secure SMTP over TLS',
      section: 'Sections 4 & 5',
      reference: 'https://www.rfc-editor.org/rfc/rfc3207',
    },
    {
      name: 'CISA Guidance',
      document: 'CISA Secure Email Architecture Guidance',
      section: 'Section 4.2',
      reference: 'https://www.cisa.gov/resources-tools/guidance',
    },
    {
      name: 'CA/Browser Forum',
      document: 'Baseline Requirements for Publicly-Trusted Certificates',
      section: 'Section 6.1.5 & 6.3.2',
      reference: 'https://cabforum.org/baseline-requirements-documents/',
    },
  ]

  return {
    capture: {
      filename: analysis.capture.filename,
      format: analysis.capture.format,
      packetCount: analysis.capture.packetCount,
      durationSeconds: analysis.capture.durationSeconds,
      sourceIp: analysis.capture.sourceIp,
      destinationIp: analysis.capture.destinationIp,
      sourcePort: analysis.capture.sourcePort,
      destinationPort: analysis.capture.destinationPort,
      metadataIntegrity: analysis.capture.metadataIntegrity,
    },
    protocolAnalysis: {
      protocol: analysis.observed.protocol.detected,
      port: analysis.observed.protocol.port,
      confidence: analysis.observed.protocol.confidence,
      starttlsAdvertised: analysis.observed.starttls.advertised,
      starttlsNegotiated: analysis.observed.starttls.negotiated,
      starttlsRequired: analysis.observed.starttls.required,
      plaintextPhaseObserved: analysis.observed.starttls.plaintextPhaseObserved,
    },
    tlsAnalysis: {
      version: analysis.observed.tls.version,
      cipherSuite: analysis.observed.tls.cipherSuite,
      keyExchange: analysis.observed.tls.keyExchange,
      namedGroup: analysis.observed.tls.namedGroup,
      forwardSecrecy: analysis.observed.tls.forwardSecrecy,
      handshakeComplete: analysis.observed.tls.handshakeComplete,
    },
    certificateAnalysis: {
      present: analysis.observed.certificate.present,
      commonName: analysis.observed.certificate.commonName,
      issuer: analysis.observed.certificate.issuer,
      validFrom: analysis.observed.certificate.validFrom,
      validUntil: analysis.observed.certificate.validUntil,
      expired: analysis.observed.certificate.expired,
      notYetValid: analysis.observed.certificate.notYetValid,
      selfSigned: analysis.observed.certificate.selfSigned,
      publicKeyAlgorithm: analysis.observed.certificate.publicKeyAlgorithm,
      publicKeyLength: analysis.observed.certificate.publicKeyLength,
      signatureAlgorithm: analysis.observed.certificate.signatureAlgorithm,
      chainValid: analysis.observed.certificate.chainValid,
    },
    cryptographicAnalysis: {
      strengthSummary: evaluated.cryptoStrength.map((c) => `${c.component}: ${c.algorithm} (${c.estimatedSecurityStrength} strength, ${c.status})`).join('; '),
      categoriesEvaluated: evaluated.categorySummaries.length,
    },
    configuration: analysis.configured ? {
      scenario: analysis.configured.testScenario,
      expectedProtocol: analysis.configured.email.protocol,
      expectedTls: analysis.configured.tls.version,
      expectedCipher: analysis.configured.tls.cipherSuite,
      starttlsMode: analysis.configured.email.starttlsMode,
    } : null,
    observed: {
      protocol: analysis.observed.protocol,
      starttls: analysis.observed.starttls,
      tls: analysis.observed.tls,
      certificate: analysis.observed.certificate,
    },
    comparison: analysis.configurationComparison ? {
      overallStatus: analysis.configurationComparison.overallStatus,
      mismatches: analysis.configurationComparison.mismatches,
    } : null,
    securityScore: {
      total: analysis.securityScore.total,
      grade: analysis.securityScore.grade,
      level: analysis.securityScore.level,
      deductions: analysis.securityScore.deductions.map((d) => ({
        reason: d.reason,
        severity: d.severity,
        points: d.points,
      })),
      breakdown: analysis.securityScore.breakdown,
    },
    findings: mappedFindings,
    anomalies: mappedAnomalies,
    recommendations: analysis.recommendations,
    references: standardsReferences,
  }
}

// ─── Retrieval Engine ────────────────────────────────────────────────────────

export interface RetrievedContext {
  relevantDocs: StandardKnowledgeDoc[]
  relevantFindings: AnalysisRAGContext['findings']
  relevantScoreInfo?: string
  relevantAnalysisSections: Record<string, unknown>
  sources: string[]
}

/**
 * Searches knowledge base documents matching query terms.
 */
export function searchKnowledgeBase(query: string, limit = 3): StandardKnowledgeDoc[] {
  const q = query.toLowerCase()
  const terms = q.split(/[\s,?.!:;]+/).filter((t) => t.length > 2)

  const scored = KNOWLEDGE_BASE_DOCS.map((doc) => {
    let score = 0
    // Check keywords
    for (const kw of doc.keywords) {
      if (q.includes(kw.toLowerCase())) score += 10
      for (const term of terms) {
        if (kw.toLowerCase().includes(term)) score += 3
      }
    }
    // Check title & standard
    if (doc.title.toLowerCase().includes(q)) score += 15
    if (doc.standard.toLowerCase().includes(q)) score += 15
    for (const term of terms) {
      if (doc.title.toLowerCase().includes(term)) score += 2
      if (doc.content.toLowerCase().includes(term)) score += 1
    }
    return { doc, score }
  })

  scored.sort((a, b) => b.score - a.score)
  return scored.filter((s) => s.score > 0).slice(0, limit).map((s) => s.doc)
}

/**
 * Retrieves relevant analysis context based on the user question.
 */
export function retrieveAnalysisContext(
  question: string,
  context: AnalysisRAGContext
): RetrievedContext {
  const q = question.toLowerCase()
  const relevantDocs = searchKnowledgeBase(question, 3)
  const sources: string[] = []

  // Check matching findings
  const relevantFindings = context.findings.filter((f) => {
    const titleMatch = f.title.toLowerCase().split(' ').some((w) => w.length > 3 && q.includes(w))
    const catMatch = q.includes(f.category.toLowerCase())
    const sevMatch = (q.includes('high') || q.includes('critical') || q.includes('severe')) && (f.severity === 'CRITICAL' || f.severity === 'HIGH')
    const generalWeakness = (q.includes('weakness') || q.includes('vulnerability') || q.includes('fix first') || q.includes('priority')) && (f.severity === 'CRITICAL' || f.severity === 'HIGH' || f.severity === 'MEDIUM')
    return titleMatch || catMatch || sevMatch || generalWeakness
  })

  const relevantAnalysisSections: Record<string, unknown> = {}

  // Include TLS analysis if relevant
  if (q.includes('tls') || q.includes('version') || q.includes('protocol') || q.includes('handshake') || q.includes('cipher') || q.includes('pfs') || q.includes('forward secrecy')) {
    relevantAnalysisSections.tlsAnalysis = context.tlsAnalysis
    sources.push(`Observed TLS (${context.tlsAnalysis.version || 'None'})`)
  }

  // Include Certificate analysis if relevant
  if (q.includes('cert') || q.includes('certificate') || q.includes('expire') || q.includes('issuer') || q.includes('rsa') || q.includes('chain')) {
    relevantAnalysisSections.certificateAnalysis = context.certificateAnalysis
    sources.push(`Observed Certificate (${context.certificateAnalysis.commonName || 'No CN'})`)
  }

  // Include STARTTLS analysis if relevant
  if (q.includes('starttls') || q.includes('upgrade') || q.includes('plaintext') || q.includes('smtp') || q.includes('strip')) {
    relevantAnalysisSections.protocolAnalysis = context.protocolAnalysis
    sources.push('Observed STARTTLS State')
  }

  // Include Score if relevant
  if (q.includes('score') || q.includes('grade') || q.includes('deduct') || q.includes('posture') || q.includes('62') || q.includes('drop') || q.includes('why')) {
    relevantAnalysisSections.securityScore = context.securityScore
    sources.push(`Security Score (${context.securityScore.total}/100 Grade ${context.securityScore.grade})`)
  }

  // Include Config vs Observed if comparison requested
  if (q.includes('compare') || q.includes('configured') || q.includes('mismatch') || q.includes('policy')) {
    relevantAnalysisSections.configuration = context.configuration
    relevantAnalysisSections.comparison = context.comparison
    sources.push('Configuration vs Observed Comparison')
  }

  // Add document sources
  for (const doc of relevantDocs) {
    sources.push(`${doc.standard} (${doc.section})`)
  }

  // If no specific section matched, include general capture summary and findings
  if (Object.keys(relevantAnalysisSections).length === 0) {
    relevantAnalysisSections.capture = context.capture
    relevantAnalysisSections.tlsAnalysis = context.tlsAnalysis
    relevantAnalysisSections.securityScore = context.securityScore
    sources.push('Current Capture Summary')
  }

  return {
    relevantDocs,
    relevantFindings: relevantFindings.length > 0 ? relevantFindings : context.findings.slice(0, 3),
    relevantAnalysisSections,
    sources: Array.from(new Set(sources)),
  }
}

// ─── Deterministic Analysis-Grounded Response Generator (Groq Fallback) ───────

/**
 * Builds a deterministic answer directly from retrieved analysis & standards.
 * Used when Groq is unavailable, guaranteeing no crash and 100% evidentiary truth.
 */
export function generateDeterministicGroundedAnswer(
  question: string,
  context: AnalysisRAGContext,
  retrieved: RetrievedContext
): { answer: string; sources: string[] } {
  const q = question.toLowerCase()
  const { tlsAnalysis, certificateAnalysis, protocolAnalysis, securityScore } = context

  // 1. Weakness / Highest risk / Fix first
  if (q.includes('weakness') || q.includes('highest-risk') || q.includes('fix first') || q.includes('priority') || q.includes('critical') || q.includes('severe')) {
    const topFindings = context.findings.filter((f) => f.severity === 'CRITICAL' || f.severity === 'HIGH')
    const primary = topFindings[0] || context.findings[0]

    if (!primary) {
      return {
        answer: `Answer\nNo critical or high-severity vulnerabilities were identified in this session. The capture demonstrates compliant cryptographic practices with a security score of ${securityScore.total}/100 (Grade ${securityScore.grade}).\n\nEvidence from Current Analysis\nAll examined cryptographic parameters (TLS version ${tlsAnalysis.version}, cipher ${tlsAnalysis.cipherSuite}, certificate validity) meet configured baselines.\n\nSecurity Impact\nNegligible risk of transport-layer interception under current observations.\n\nApplicable Standard\nNIST SP 800-52 Rev. 2 / RFC 8446.\n\nRecommendation\nMaintain routine certificate lifecycle management and automated TLS posture verification.`,
        sources: ['Security Score & Findings Engine', 'NIST SP 800-52 Rev. 2'],
      }
    }

    const doc = retrieved.relevantDocs[0] || KNOWLEDGE_BASE_DOCS[0]
    return {
      answer: `Answer\nThe primary security weakness identified in this capture is "${primary.title}" (${primary.severity} severity), resulting in a -${primary.deduction} point deduction to the security score.\n\nEvidence from Current Analysis\n${primary.evidence}\nObserved Protocol: ${protocolAnalysis.protocol} on port ${protocolAnalysis.port}, TLS Version: ${tlsAnalysis.version}, Cipher Suite: ${tlsAnalysis.cipherSuite}.\n\nSecurity Impact\n${primary.impact}\n\nApplicable Standard\n${doc.standard} (${doc.section}): ${doc.title}. ${doc.content.slice(0, 240)}...\n\nRecommendation\n${primary.recommendation}`,
      sources: [primary.id, doc.standard, 'Current Capture Evidence'],
    }
  }

  // 2. Security Score explanation
  if (q.includes('score') || q.includes('grade') || q.includes('deduct') || q.includes('drop') || /\b\d{1,3}\b/.test(q)) {
    const deductionsList = securityScore.deductions.map((d) => `• ${d.reason}: -${d.points} pts (${d.severity})`).join('\n') || '• No point deductions recorded.'
    return {
      answer: `Answer\nThe security score is ${securityScore.total}/100, corresponding to Grade ${securityScore.grade} (${securityScore.level} security posture). The score is calculated deterministically across 17 security categories evaluating protocol security, cipher strength, key exchange, certificate validity, and STARTTLS behavior.\n\nEvidence from Current Analysis\nScore deductions:\n${deductionsList}\nTLS Version: ${tlsAnalysis.version} | Cipher: ${tlsAnalysis.cipherSuite} | Certificate: ${certificateAnalysis.present ? (certificateAnalysis.expired ? 'Expired' : 'Valid') : 'Missing'}.\n\nSecurity Impact\nDeductions reflect deviation from secure email transport baselines, increasing vulnerability to eavesdropping or protocol downgrade.\n\nApplicable Standard\nNIST SP 800-52 Rev. 2 (TLS Guidelines) & NIST SP 800-57 Part 1 Rev. 5 (Key Management).\n\nRecommendation\nRemediate the highest deduction items first: ${securityScore.deductions[0]?.reason || 'Maintain modern TLS 1.3 configuration'}.`,
      sources: ['Security Score Engine', 'NIST SP 800-52 Rev. 2'],
    }
  }

  // 3. TLS Version / Deprecation / "What would happen if TLS 1.0 is enabled"
  if (q.includes('tls 1.0') || q.includes('tls 1.1') || q.includes('tls version') || q.includes('downgrade') || q.includes('deprecat')) {
    const doc = KNOWLEDGE_BASE_DOCS.find((d) => d.id === 'RFC-8996-DEPRECATION') || KNOWLEDGE_BASE_DOCS[0]
    return {
      answer: `Answer\nTLS 1.0 and TLS 1.1 are cryptographically broken and formally deprecated. If TLS 1.0 is enabled, attackers positioned on the network path can manipulate negotiation handshakes to force clients into negotiating TLS 1.0, exposing sessions to known attacks including BEAST and POODLE, as well as weak cipher suites lacking forward secrecy.\n\nEvidence from Current Analysis\nObserved TLS version in wire capture: ${tlsAnalysis.version}. Cipher suite: ${tlsAnalysis.cipherSuite}. Handshake status: ${tlsAnalysis.handshakeComplete ? 'Completed' : 'Incomplete'}.\n\nSecurity Impact\nAllows passive or active Man-in-the-Middle (MITM) adversaries to decrypt sensitive email communications, harvest authentication credentials, and bypass modern cryptographic integrity controls.\n\nApplicable Standard\n${doc.standard} (${doc.section}): ${doc.title}. ${doc.content}\n\nRecommendation\nDisable TLS 1.0 and TLS 1.1 completely across all mail transfer agents (MTAs) and submission endpoints. Enforce TLS 1.2 and TLS 1.3 only.`,
      sources: ['RFC 8996', 'NIST SP 800-52 Rev. 2 Section 3.1.1', 'Capture TLS Analysis'],
    }
  }

  // 4. Cipher Suite / Cryptographic Strength
  if (q.includes('cipher') || q.includes('key size') || q.includes('rsa') || q.includes('strength') || q.includes('3des') || q.includes('cbc') || q.includes('aes')) {
    const doc = KNOWLEDGE_BASE_DOCS.find((d) => d.id === 'NIST-800-57-KEY-STRENGTH') || KNOWLEDGE_BASE_DOCS[2]
    return {
      answer: `Answer\nCryptographic security depends on modern cipher primitives (AEAD ciphers such as AES-GCM or ChaCha20-Poly1305) and sufficient key lengths providing at least 112 bits of security strength (128 bits recommended).\n\nEvidence from Current Analysis\nObserved Cipher Suite: ${tlsAnalysis.cipherSuite}.\nKey Exchange: ${tlsAnalysis.keyExchange} (Named Group: ${tlsAnalysis.namedGroup || 'None'}).\nForward Secrecy: ${tlsAnalysis.forwardSecrecy ? 'Active (PFS Enabled)' : 'Disabled (Static Key Exchange)'}.\nCertificate Public Key: ${certificateAnalysis.publicKeyAlgorithm} ${certificateAnalysis.publicKeyLength} bits.\n\nSecurity Impact\nLegacy ciphers (e.g. 3DES, RC4, CBC without Encrypt-then-MAC) permit plaintext recovery via block collision or padding oracle attacks. Short key sizes (< 2048-bit RSA) are vulnerable to mathematical factorization.\n\nApplicable Standard\n${doc.standard} (${doc.section}): ${doc.title}.\n\nRecommendation\nConfigure MTAs to prioritize TLS_AES_256_GCM_SHA384 and ECDHE-RSA-AES256-GCM-SHA384. Decommission all non-AEAD and static RSA suites.`,
      sources: ['NIST SP 800-57 Part 1 Rev. 5', 'NIST SP 800-52 Rev. 2 Section 3.3.1'],
    }
  }

  // 5. Certificate analysis
  if (q.includes('cert') || q.includes('certificate') || q.includes('expire') || q.includes('trust') || q.includes('issuer') || q.includes('chain')) {
    const doc = KNOWLEDGE_BASE_DOCS.find((d) => d.id === 'CABF-CERTIFICATE-REQUIREMENTS') || KNOWLEDGE_BASE_DOCS[5]
    return {
      answer: `Answer\nThe server certificate was analyzed for validity window compliance, cryptographic key strength, signature algorithm, and CA trust chain integrity. Present in capture: ${certificateAnalysis.present ? 'Yes' : 'No'}.\n\nEvidence from Current Analysis\nCommon Name: "${certificateAnalysis.commonName}"\nIssuer: "${certificateAnalysis.issuer}"\nValidity: ${certificateAnalysis.validFrom} to ${certificateAnalysis.validUntil}\nExpired Status: ${certificateAnalysis.expired ? 'EXPIRED' : 'Valid'}\nTrust Chain: ${certificateAnalysis.chainValid ? 'Trusted' : 'Untrusted / Incomplete'}\nAlgorithm: ${certificateAnalysis.publicKeyAlgorithm} (${certificateAnalysis.publicKeyLength} bits), Signature: ${certificateAnalysis.signatureAlgorithm}.\n\nSecurity Impact\nAn expired, self-signed, or chain-broken certificate prevents mail clients from authenticating the destination server, opening mail delivery to Man-in-the-Middle impersonation or causing delivery rejection by strict MTAs.\n\nApplicable Standard\n${doc.standard} (${doc.section}): ${doc.title}.\n\nRecommendation\nDeploy a valid X.509 certificate from a trusted public CA with RSA >= 2048 bits or ECDSA P-256, and bundle intermediate CA certificates.`,
      sources: ['CA/Browser Forum Baseline Requirements', 'NIST SP 800-52 Rev. 2 Section 3.4'],
    }
  }

  // 6. STARTTLS issue
  if (q.includes('starttls') || q.includes('strip') || q.includes('plaintext') || q.includes('upgrade')) {
    const doc = KNOWLEDGE_BASE_DOCS.find((d) => d.id === 'RFC-3207-STARTTLS-SECURITY') || KNOWLEDGE_BASE_DOCS[4]
    return {
      answer: `Answer\nSTARTTLS upgrades an initial plaintext SMTP connection to TLS. If STARTTLS is offered but not completed, or if plaintext mail transmission occurs before encryption, traffic is vulnerable to opportunistic downgrade and interception.\n\nEvidence from Current Analysis\nSTARTTLS Advertised: ${protocolAnalysis.starttlsAdvertised ? 'Yes' : 'No'}\nSTARTTLS Negotiated: ${protocolAnalysis.starttlsNegotiated ? 'Yes' : 'No'}\nPlaintext Phase Observed: ${protocolAnalysis.plaintextPhaseObserved ? 'Yes (Cleartext observed)' : 'No'}\nEnforcement Required: ${protocolAnalysis.starttlsRequired ? 'Yes' : 'No'}.\n\nSecurity Impact\nSTARTTLS stripping allows a network adversary to remove the 250-STARTTLS capability from the EHLO greeting, compelling the client to send email headers, bodies, and credentials in cleartext.\n\nApplicable Standard\n${doc.standard} (${doc.section}): ${doc.title}.\n\nRecommendation\nConfigure mandatory TLS enforcement and implement MTA-STS (RFC 8461) to guarantee encryption on mail delivery.`,
      sources: ['RFC 3207', 'CISA Secure Email Guidance'],
    }
  }

  // 7. Configured vs Observed comparison
  if (q.includes('compare') || q.includes('configured') || q.includes('observed') || q.includes('mismatch')) {
    const mismatches = (context.comparison as Record<string, unknown>)?.mismatches as string[] || []
    return {
      answer: `Answer\nComparison between administrative configuration and wire-level packet capture reveals ${mismatches.length > 0 ? `discrepancies: ${mismatches.join(', ')}` : 'consistent alignment between configured policy and observed traffic'}.\n\nEvidence from Current Analysis\nConfigured Scenario: ${(context.configuration as Record<string, unknown>)?.scenario || 'External PCAP'}\nConfigured Protocol: ${(context.configuration as Record<string, unknown>)?.expectedProtocol || 'N/A'} → Observed: ${protocolAnalysis.protocol}\nConfigured TLS: ${(context.configuration as Record<string, unknown>)?.expectedTls || 'N/A'} → Observed: ${tlsAnalysis.version}\nConfigured Cipher: ${(context.configuration as Record<string, unknown>)?.expectedCipher || 'N/A'} → Observed: ${tlsAnalysis.cipherSuite}.\n\nSecurity Impact\nMismatches indicate policy bypass, server misconfiguration, or active wire manipulation where negotiated parameters fall below intended security controls.\n\nApplicable Standard\nSecureMailScope Cryptographic Verification Standard & NIST SP 800-52 Rev. 2.\n\nRecommendation\nAlign server configuration files (e.g. Postfix / Dovecot / Exim) to enforce the intended cipher suite and TLS protocol minimums.`,
      sources: ['Configuration Comparison Engine', 'Capture Metadata'],
    }
  }

  // 8. General / Fallback Question
  const topFinding = context.findings[0]
  const doc = retrieved.relevantDocs[0] || KNOWLEDGE_BASE_DOCS[0]
  return {
    answer: `Answer\nBased on the analysis of capture "${context.capture.filename}", the mail session utilized ${protocolAnalysis.protocol} on port ${protocolAnalysis.port}, negotiating ${tlsAnalysis.version} with cipher ${tlsAnalysis.cipherSuite}. The overall security score is ${securityScore.total}/100 (Grade ${securityScore.grade}).\n\nEvidence from Current Analysis\nPacket count: ${context.capture.packetCount} packets over ${context.capture.durationSeconds.toFixed(1)}s.\nHandshake complete: ${tlsAnalysis.handshakeComplete ? 'Yes' : 'No'}.\nForward Secrecy: ${tlsAnalysis.forwardSecrecy ? 'Active' : 'Disabled'}.\n${topFinding ? `Primary finding: [${topFinding.severity}] ${topFinding.title} (Deduction: -${topFinding.deduction} pts).` : 'No security defects detected.'}\n\nSecurity Impact\n${topFinding ? topFinding.impact : 'Compliant transport encryption protects email against eavesdropping and message modification.'}\n\nApplicable Standard\n${doc.standard} (${doc.section}): ${doc.title}.\n\nRecommendation\n${topFinding ? topFinding.recommendation : 'Continue routine cryptographic auditing and adopt TLS 1.3.'}`,
    sources: [doc.standard, 'Capture Analysis'],
  }
}
