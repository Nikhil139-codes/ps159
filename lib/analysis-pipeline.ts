/**
 * SecureMailScope Analysis Pipeline
 *
 * Takes a raw PCAPNG buffer and an optional session ID,
 * runs the complete analysis pipeline, and returns a CanonicalAnalysis object.
 *
 * Pipeline:
 *  PCAPNG Buffer
 *  → parsePcapng (extract packets + SecureMailScope metadata)
 *  → decryptConfig (recover LabConfiguration)
 *  → buildObserved (map packet observations to typed interfaces)
 *  → buildComparison (compare configured vs observed)
 *  → calculateSecurityScore
 *  → generateFindings + detectAnomalies
 *  → callGroq (optional AI assessment)
 *  → CanonicalAnalysis
 */

import { parsePcapng, decryptConfig } from './pcapng-generator'
import { calculateSecurityScore, deriveObservedPFS } from './scoring-engine'
import { generateFindings, detectAnomalies } from './findings-engine'
import { SCHEMA_VERSION, GENERATOR_VERSION } from './types'
import { getGroqApiKey } from './env'
import type {
  CanonicalAnalysis,
  LabConfiguration,
  ObservedCapture,
  ObservedProtocol,
  ObservedStarttls,
  ObservedTls,
  ObservedCertificate,
  ConfigurationComparison,
  ComparisonField,
  ObservableStatus,
  AiAssessment,
  TlsVersion,
  EmailProtocol,
} from './types'

// ─── Groq AI client (optional) ────────────────────────────────────────────────

async function callGroq(featureJson: object): Promise<AiAssessment> {
  const apiKey = getGroqApiKey()

  if (!apiKey) {
    return {
      available: false,
      provider: 'none',
      executiveSummary: 'AI analysis unavailable — rule-based assessment used.',
      riskNarrative: '',
      prioritizedFindings: [],
      recommendations: [],
      anomalyExplanations: [],
      fallbackReason: 'GROQ_API_KEY environment variable not set.',
    }
  }

  try {
    const prompt = `You are a cryptographic security analyst reviewing email security posture data.
    
Analyze the following security features extracted from a mail server capture and provide:
1. A brief executive summary (2-3 sentences)
2. A risk narrative
3. Top 3 prioritized findings
4. Top 3 recommendations
5. Any anomaly explanations

Respond ONLY with a JSON object with keys: executiveSummary, riskNarrative, prioritizedFindings (array), recommendations (array), anomalyExplanations (array).

Feature data:
${JSON.stringify(featureJson, null, 2)}`

    const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        model: 'llama3-8b-8192',
        messages: [{ role: 'user', content: prompt }],
        temperature: 0.3,
        max_tokens: 1024,
      }),
    })

    if (!response.ok) {
      throw new Error(`Groq API error: ${response.status}`)
    }

    const data = await response.json()
    const text = data.choices?.[0]?.message?.content ?? ''
    // Extract JSON from the response
    const jsonMatch = text.match(/\{[\s\S]*\}/)
    if (!jsonMatch) throw new Error('No JSON in Groq response')
    const parsed = JSON.parse(jsonMatch[0])

    return {
      available: true,
      provider: 'groq',
      executiveSummary: parsed.executiveSummary ?? '',
      riskNarrative: parsed.riskNarrative ?? '',
      prioritizedFindings: parsed.prioritizedFindings ?? [],
      recommendations: parsed.recommendations ?? [],
      anomalyExplanations: parsed.anomalyExplanations ?? [],
    }
  } catch (err) {
    return {
      available: false,
      provider: 'none',
      executiveSummary: 'AI analysis unavailable — rule-based assessment used.',
      riskNarrative: '',
      prioritizedFindings: [],
      recommendations: [],
      anomalyExplanations: [],
      fallbackReason: err instanceof Error ? err.message : 'Groq call failed',
    }
  }
}

// ─── Comparison helper ────────────────────────────────────────────────────────

function compareField(
  configuredValue: string,
  observedValue: string,
  notObservable: boolean = false,
): ComparisonField {
  if (notObservable) {
    return { configured: configuredValue, observed: 'not_observable', status: 'not_observable' }
  }
  const status: ObservableStatus = configuredValue === observedValue ? 'match' : 'mismatch'
  return { configured: configuredValue, observed: observedValue, status }
}

// ─── Main analysis function ───────────────────────────────────────────────────

export interface AnalysisOptions {
  pcapBuffer: Buffer
  sessionId: string
  captureFilename: string
  source: 'email-lab' | 'upload'
  runAi?: boolean
}

export async function runAnalysis(options: AnalysisOptions): Promise<CanonicalAnalysis> {
  const { pcapBuffer, sessionId, captureFilename, source } = options
  const runAi = options.runAi ?? true

  // ── Step 1: Parse PCAPNG ──────────────────────────────────────────────────
  const parsed = parsePcapng(pcapBuffer)

  // ── Step 2: Recover configured values (decrypt manifest) ─────────────────
  let configured: LabConfiguration | null = null
  let metadataIntegrity: ObservedCapture['metadataIntegrity'] = 'missing'

  if (parsed.isSecureMailScope && parsed.manifest) {
    const decryptResult = decryptConfig(parsed.manifest)
    if ('error' in decryptResult) {
      metadataIntegrity = 'decryption_failed'
    } else {
      configured = decryptResult.config
      metadataIntegrity = decryptResult.hashValid ? 'valid' : 'hash_mismatch'
    }
  }

  // ── Step 3: Build ObservedCapture ────────────────────────────────────────
  const now = new Date().toISOString()
  const capture: ObservedCapture = {
    filename: captureFilename,
    format: parsed.hasSHB ? 'PCAPNG' : 'PCAP',
    timestamp: now,
    packetCount: parsed.packetCount,
    durationSeconds: Math.max(1, parsed.packetCount * 0.05),
    sourceIp: '172.30.0.2',
    destinationIp: '172.30.0.3',
    sourcePort: 50000,
    destinationPort: configured?.email.port ?? 587,
    hasSecureMailScopeMetadata: parsed.isSecureMailScope,
    metadataIntegrity,
  }

  // ── Step 4: Build ObservedProtocol ────────────────────────────────────────
  const detectedProtocol: EmailProtocol = configured?.email.protocol ?? 'SMTP'
  const observedProtocol: ObservedProtocol = {
    detected: detectedProtocol,
    port: capture.destinationPort,
    confidence: configured ? 'high' : 'medium',
  }

  // ── Step 5: Build ObservedStarttls ───────────────────────────────────────
  const observedStarttls: ObservedStarttls = {
    advertised: parsed.smtpStarttlsAdvertised,
    negotiated: parsed.smtpStarttlsNegotiated,
    required: configured?.email.starttlsMode === 'enabled_required',
    plaintextPhaseObserved: parsed.plaintextSMTP,
    encryptedPhaseObserved: parsed.smtpStarttlsNegotiated || parsed.tlsServerHello !== null,
  }

  // ── Step 6: Build ObservedTls ────────────────────────────────────────────
  let tlsVersion: TlsVersion = 'unknown' as TlsVersion
  let cipherSuite = 'unknown'
  let keyExchange = 'unknown'
  let namedGroup = 'unknown'
  let handshakeComplete = false
  let clientHelloObserved = false
  let serverHelloObserved = false

  if (parsed.tlsClientHello) {
    tlsVersion = parsed.tlsClientHello.version
    cipherSuite = parsed.tlsClientHello.cipherSuites[0] ?? 'unknown'
    namedGroup = parsed.tlsClientHello.namedGroups[0] ?? 'unknown'
    clientHelloObserved = true
  }
  if (parsed.tlsServerHello) {
    tlsVersion = parsed.tlsServerHello.version // ServerHello is authoritative
    cipherSuite = parsed.tlsServerHello.selectedCipher
    serverHelloObserved = true
    handshakeComplete = true
  }

  // Derive key exchange from cipher suite or named group
  if (keyExchange === 'unknown') {
    if (cipherSuite.startsWith('ECDHE')) keyExchange = 'ECDHE'
    else if (cipherSuite.startsWith('DHE')) keyExchange = 'DHE'
    else if (cipherSuite.startsWith('AES') || cipherSuite.startsWith('TLS_RSA')) keyExchange = 'RSA'
    else if (cipherSuite.startsWith('TLS_AES') || cipherSuite.startsWith('TLS_CHA')) keyExchange = 'ECDHE' // TLS 1.3 always ECDHE
    else if (namedGroup !== 'unknown') keyExchange = 'ECDHE'
  }

  const forwardSecrecy = deriveObservedPFS(keyExchange, tlsVersion as TlsVersion)

  const observedTls: ObservedTls = {
    version: tlsVersion as TlsVersion,
    cipherSuite,
    keyExchange,
    namedGroup,
    forwardSecrecy,
    handshakeComplete,
    clientHelloObserved,
    serverHelloObserved,
  }

  // ── Step 7: Build ObservedCertificate ─────────────────────────────────────
  let observedCert: ObservedCertificate
  if (parsed.certificateData) {
    const certData = parsed.certificateData
    const now_ = new Date()
    const validFrom = new Date(certData.validFrom)
    const validUntil = new Date(certData.validUntil)
    const expired = now_ > validUntil
    const notYetValid = now_ < validFrom
    const selfSigned = certData.issuer === certData.commonName || certData.scenario === 'self_signed'

    observedCert = {
      present: true,
      commonName: certData.commonName,
      issuer: certData.issuer,
      validFrom: certData.validFrom,
      validUntil: certData.validUntil,
      expired,
      notYetValid,
      selfSigned,
      publicKeyAlgorithm: certData.publicKeyAlgorithm,
      publicKeyLength: certData.publicKeyLength,
      signatureAlgorithm: certData.signatureAlgorithm,
      chainValid: certData.chainValid,
    }
  } else {
    observedCert = {
      present: false,
      commonName: 'not_observable',
      issuer: 'not_observable',
      validFrom: 'not_observable',
      validUntil: 'not_observable',
      expired: false,
      notYetValid: false,
      selfSigned: false,
      publicKeyAlgorithm: 'not_observable',
      publicKeyLength: 0,
      signatureAlgorithm: 'not_observable',
      chainValid: false,
    }
  }

  // ── Step 8: Configuration comparison ─────────────────────────────────────
  let comparison: ConfigurationComparison | null = null
  if (configured) {
    const mismatches: string[] = []
    const cfgTlsVer = configured.tls.version
    const obsTlsVer = observedTls.version

    const tlsVersionComp = compareField(cfgTlsVer, obsTlsVer)
    const cipherComp = compareField(configured.tls.cipherSuite, observedTls.cipherSuite)
    const kexComp = compareField(configured.tls.keyExchange, observedTls.keyExchange)
    const groupComp = compareField(configured.tls.namedGroup, observedTls.namedGroup)
    const pfsComp = compareField(
      configured.tls.forwardSecrecy ? 'yes' : 'no',
      observedTls.forwardSecrecy ? 'yes' : 'no',
    )
    const starttlsComp = compareField(
      configured.email.starttls ? 'enabled' : 'disabled',
      observedStarttls.advertised ? 'enabled' : 'disabled',
    )
    const starttlsRequiredComp = compareField(
      configured.email.starttlsMode === 'enabled_required' ? 'required' : 'optional',
      observedStarttls.required ? 'required' : 'optional',
    )
    const certExpiredComp = compareField(
      configured.certificate.scenario === 'expired' ? 'expired' : 'valid',
      observedCert.expired ? 'expired' : (observedCert.notYetValid ? 'not_yet_valid' : 'valid'),
    )
    const certChainComp = compareField(
      configured.certificate.chainValid ? 'valid' : 'invalid',
      observedCert.chainValid ? 'valid' : 'invalid',
    )
    const certCNComp = observedCert.present
      ? compareField(configured.certificate.commonName, observedCert.commonName)
      : { configured: configured.certificate.commonName, observed: 'not_observable', status: 'not_observable' as ObservableStatus }
    const pubKeyComp = observedCert.present
      ? compareField(configured.certificate.publicKeyAlgorithm, observedCert.publicKeyAlgorithm)
      : { configured: configured.certificate.publicKeyAlgorithm, observed: 'not_observable', status: 'not_observable' as ObservableStatus }
    const sigAlgComp = observedCert.present
      ? compareField(configured.certificate.signatureAlgorithm, observedCert.signatureAlgorithm)
      : { configured: configured.certificate.signatureAlgorithm, observed: 'not_observable', status: 'not_observable' as ObservableStatus }

    if (tlsVersionComp.status === 'mismatch') mismatches.push('tlsVersion')
    if (cipherComp.status === 'mismatch') mismatches.push('cipherSuite')
    if (starttlsComp.status === 'mismatch') mismatches.push('starttls')
    if (certExpiredComp.status === 'mismatch') mismatches.push('certExpiry')
    if (certChainComp.status === 'mismatch') mismatches.push('certChain')

    comparison = {
      tlsVersion: tlsVersionComp,
      cipherSuite: cipherComp,
      keyExchange: kexComp,
      namedGroup: groupComp,
      forwardSecrecy: pfsComp,
      starttls: starttlsComp,
      starttlsRequired: starttlsRequiredComp,
      certExpired: certExpiredComp,
      certChainValid: certChainComp,
      certCommonName: certCNComp,
      publicKeyAlgorithm: pubKeyComp,
      signatureAlgorithm: sigAlgComp,
      overallStatus: mismatches.length > 0 ? 'configuration_mismatch' : 'consistent',
      mismatches,
    }
  }

  // ── Step 9: Score + Findings + Anomalies ──────────────────────────────────
  const scoringInput = {
    configured,
    observedTls,
    observedCert,
    observedStarttls,
    observedProtocol,
    comparison,
  }

  const securityScore = calculateSecurityScore(scoringInput)

  const findingsInput = {
    configured,
    observedTls,
    observedCert,
    observedStarttls,
    comparison,
    sessionId,
  }

  const findings = generateFindings(findingsInput)
  const anomalies = detectAnomalies(findingsInput)

  // ── Step 10: AI Assessment (Groq) ────────────────────────────────────────
  // Build feature JSON for AI (structured, not raw PCAP)
  const featureJson = {
    capture: { filename: captureFilename, packetCount: capture.packetCount, format: capture.format },
    protocol: { detected: observedProtocol.detected, port: observedProtocol.port },
    starttls: observedStarttls,
    tls: {
      version: observedTls.version,
      cipherSuite: observedTls.cipherSuite,
      keyExchange: observedTls.keyExchange,
      forwardSecrecy: observedTls.forwardSecrecy,
    },
    certificate: {
      present: observedCert.present,
      commonName: observedCert.commonName,
      expired: observedCert.expired,
      selfSigned: observedCert.selfSigned,
      chainValid: observedCert.chainValid,
    },
    securityScore: securityScore.total,
    grade: securityScore.grade,
    findingCount: findings.length,
    criticalCount: findings.filter(f => f.severity === 'CRITICAL').length,
    highCount: findings.filter(f => f.severity === 'HIGH').length,
    anomalyCount: anomalies.length,
    configurationComparison: comparison ? {
      overallStatus: comparison.overallStatus,
      mismatches: comparison.mismatches,
    } : null,
  }

  let aiAssessment: AiAssessment
  if (runAi) {
    aiAssessment = await callGroq(featureJson)
  } else {
    aiAssessment = {
      available: false,
      provider: 'none',
      executiveSummary: 'AI analysis skipped for this request.',
      riskNarrative: '',
      prioritizedFindings: [],
      recommendations: [],
      anomalyExplanations: [],
    }
  }

  // ── Step 11: Compile recommendations ─────────────────────────────────────
  const recommendations = [
    ...new Set(findings.map(f => f.recommendation)),
  ].slice(0, 8)

  // ── Step 12: Assemble canonical analysis ──────────────────────────────────
  const analysis: CanonicalAnalysis = {
    schemaVersion: SCHEMA_VERSION,
    analysisTimestamp: now,
    session: {
      id: sessionId,
      source,
      captureFile: captureFilename,
    },
    capture,
    configured,
    observed: {
      protocol: observedProtocol,
      starttls: observedStarttls,
      tls: observedTls,
      certificate: observedCert,
    },
    configurationComparison: comparison,
    findings,
    anomalies,
    securityScore,
    aiAssessment,
    recommendations,
  }

  return analysis
}

// ─── Export for use in API routes ─────────────────────────────────────────────
export type { CanonicalAnalysis }
