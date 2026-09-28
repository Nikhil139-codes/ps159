/**
 * SecureMailScope Findings Engine
 *
 * Generates structured SecurityFinding objects from observed analysis data.
 * Every finding is backed by evidence extracted from the capture.
 * No findings are generated without evidence.
 */

import type {
  SecurityFinding,
  FindingCategory,
  FindingSeverity,
  ObservedTls,
  ObservedCertificate,
  ObservedStarttls,
  LabConfiguration,
  ConfigurationComparison,
  Anomaly,
  AnomalyType,
  TlsVersion,
} from './types'
import { isWeakCipher, isLegacyCipher, isWeakPublicKey, isWeakSignatureAlgorithm } from './scoring-engine'

let findingCounter = 0
function nextId(category: string): string {
  return `${category}-${String(++findingCounter).padStart(3, '0')}`
}

export interface FindingsInput {
  configured: LabConfiguration | null
  observedTls: ObservedTls
  observedCert: ObservedCertificate
  observedStarttls: ObservedStarttls
  comparison: ConfigurationComparison | null
  sessionId: string
}

export function generateFindings(input: FindingsInput): SecurityFinding[] {
  findingCounter = 0
  const findings: SecurityFinding[] = []

  // ── TLS Version findings ───────────────────────────────────────────────────
  const tlsVer = input.observedTls.version
  if (tlsVer === 'None') {
    findings.push(finding('TLS', 'CRITICAL', nextId('NO-TLS'),
      'No TLS encryption detected',
      'The capture shows email traffic with no TLS encryption. All data is transmitted in plaintext, exposing credentials, message content, and metadata.',
      { observed: 'No TLS' },
      'All email content and credentials are exposed to network eavesdroppers.',
      'Enable STARTTLS or use a TLS-protected port (SMTPS/465, IMAPS/993).',
      'pcap-analysis', 20
    ))
  } else if (tlsVer === 'TLS1.0') {
    findings.push(finding('TLS', 'HIGH', nextId('TLS-DEPRECATED'),
      'TLS 1.0 detected — deprecated protocol',
      'TLS 1.0 is deprecated (RFC 8996) and is vulnerable to BEAST, POODLE, and related attacks. PCI DSS and NIST require disabling TLS 1.0.',
      { observed: 'TLS1.0' },
      'Sessions may be vulnerable to protocol downgrade attacks and known exploits.',
      'Upgrade to TLS 1.2 or preferably TLS 1.3. Disable TLS 1.0 on all mail servers.',
      'pcap-analysis', 18
    ))
  } else if (tlsVer === 'TLS1.1') {
    findings.push(finding('TLS', 'HIGH', nextId('TLS-DEPRECATED'),
      'TLS 1.1 detected — deprecated protocol',
      'TLS 1.1 is deprecated (RFC 8996). It lacks modern cryptographic primitives and is susceptible to multiple protocol-level attacks.',
      { observed: 'TLS1.1' },
      'Deprecated protocol increases attack surface for protocol downgrade attacks.',
      'Upgrade to TLS 1.2 or TLS 1.3. Disable TLS 1.1 support on mail servers.',
      'pcap-analysis', 14
    ))
  } else if (tlsVer === 'TLS1.2') {
    findings.push(finding('TLS', 'INFO', nextId('TLS-INFO'),
      'TLS 1.2 in use — consider upgrading to TLS 1.3',
      'TLS 1.2 is currently acceptable but TLS 1.3 offers improved security through mandatory forward secrecy and a simplified handshake.',
      { observed: 'TLS1.2' },
      'Minimal — TLS 1.2 with strong cipher suites is secure for most deployments.',
      'Consider upgrading to TLS 1.3 for enhanced security and performance.',
      'pcap-analysis', 4
    ))
  }

  // ── Cipher suite findings ─────────────────────────────────────────────────
  const cipher = input.observedTls.cipherSuite
  if (cipher && cipher !== 'unknown') {
    if (isWeakCipher(cipher)) {
      findings.push(finding('Cipher', 'HIGH', nextId('WEAK-CIPHER'),
        `Weak cipher suite detected: ${cipher}`,
        `The cipher suite "${cipher}" provides inadequate security. This cipher is susceptible to cryptographic attacks and should not be used in production email infrastructure.`,
        { observed: cipher },
        'Encrypted communications may be decryptable by a capable attacker.',
        'Replace with ECDHE-RSA-AES256-GCM-SHA384 or TLS_AES_256_GCM_SHA384 (TLS 1.3).',
        'pcap-analysis', 18
      ))
    } else if (isLegacyCipher(cipher)) {
      findings.push(finding('Cipher', 'MEDIUM', nextId('LEGACY-CIPHER'),
        `Legacy cipher suite in use: ${cipher}`,
        `The cipher suite "${cipher}" is functional but a 128-bit AES variant. For sensitive email communications, 256-bit AES provides additional margin.`,
        { observed: cipher },
        'Slightly reduced cryptographic margin compared to 256-bit AES variants.',
        'Prefer ECDHE-RSA-AES256-GCM-SHA384 or TLS_AES_256_GCM_SHA384.',
        'pcap-analysis', 8
      ))
    }
  }

  // ── Key exchange / PFS findings ────────────────────────────────────────────
  if (!input.observedTls.forwardSecrecy && tlsVer !== 'TLS1.3' && tlsVer !== 'None') {
    findings.push(finding('PFS', 'MEDIUM', nextId('NO-PFS'),
      'No Perfect Forward Secrecy (PFS)',
      'The observed key exchange does not provide Perfect Forward Secrecy. If the server\'s private key is compromised in the future, all past session recordings can be decrypted.',
      { observed: input.observedTls.keyExchange || 'RSA' },
      'Past and future sessions become decryptable if the server private key is compromised.',
      'Configure ECDHE or DHE key exchange. Prefer TLS 1.3 which mandates ephemeral key exchange.',
      'pcap-analysis', 12
    ))
  }

  if (input.observedTls.keyExchange === 'RSA') {
    findings.push(finding('KeyExchange', 'MEDIUM', nextId('RSA-KEX'),
      'Static RSA key exchange in use',
      'RSA key exchange does not provide forward secrecy. Session keys are derived from the server\'s long-term private key.',
      { observed: 'RSA key exchange' },
      'Historical session traffic becomes decryptable if server private key is later compromised.',
      'Switch to ECDHE key exchange with a modern named group (X25519 or secp256r1).',
      'pcap-analysis', 8
    ))
  }

  // ── STARTTLS findings ─────────────────────────────────────────────────────
  if (!input.observedStarttls.advertised) {
    if (input.configured?.email.starttls) {
      findings.push(finding('STARTTLS', 'HIGH', nextId('STARTTLS-NOT-ADVERTISED'),
        'STARTTLS configured but not advertised in capture',
        'The configuration specifies STARTTLS should be offered, but the observed SMTP EHLO response does not include the STARTTLS capability.',
        { configured: 'STARTTLS enabled', observed: 'STARTTLS not in EHLO response' },
        'Clients cannot initiate TLS upgrade — connections may remain unencrypted.',
        'Verify Postfix/mail server STARTTLS configuration and TLS certificate setup.',
        'configuration-check', 10
      ))
    } else {
      findings.push(finding('STARTTLS', 'MEDIUM', nextId('STARTTLS-DISABLED'),
        'STARTTLS not offered',
        'The SMTP server does not advertise STARTTLS capability, allowing clients to connect without TLS encryption.',
        { observed: 'STARTTLS not advertised' },
        'Unencrypted email transmission exposed to network interception.',
        'Enable STARTTLS on the mail server. For higher security, require STARTTLS (smtpd_tls_security_level = encrypt).',
        'pcap-analysis', 6
      ))
    }
  } else if (input.observedStarttls.advertised && !input.observedStarttls.negotiated) {
    findings.push(finding('STARTTLS', 'HIGH', nextId('STARTTLS-NOT-NEGOTIATED'),
      'STARTTLS advertised but TLS upgrade not completed',
      'The server advertised STARTTLS capability in the EHLO response, but the TLS handshake was not successfully completed. This may indicate a configuration error or active downgrade attempt.',
      { observed: 'STARTTLS advertised, handshake not completed' },
      'Email traffic may be transmitted in plaintext despite STARTTLS being offered.',
      'Investigate server TLS certificate configuration. Ensure no STARTTLS stripping is occurring.',
      'anomaly-detection', 8
    ))
  }

  // ── Certificate findings ──────────────────────────────────────────────────
  if (input.observedCert.present) {
    if (input.observedCert.expired) {
      findings.push(finding('Certificate', 'HIGH', nextId('CERT-EXPIRED'),
        'Certificate is expired',
        `The server certificate expired on ${input.observedCert.validUntil}. Clients may reject the certificate or display warnings, degrading email delivery reliability.`,
        { observed: `expired: validUntil=${input.observedCert.validUntil}` },
        'Certificate expiration may cause TLS handshake failures and email delivery disruption.',
        'Renew the server certificate immediately and establish a certificate rotation schedule.',
        'pcap-analysis', 15
      ))
    }

    if (input.observedCert.notYetValid) {
      findings.push(finding('Certificate', 'HIGH', nextId('CERT-NOT-VALID-YET'),
        'Certificate is not yet valid',
        `The server certificate has a validity start date of ${input.observedCert.validFrom} which is in the future.`,
        { observed: `not_yet_valid: validFrom=${input.observedCert.validFrom}` },
        'TLS connections may be rejected by clients enforcing strict certificate validation.',
        'Investigate certificate issuance — ensure system clock is correct and certificate dates are properly set.',
        'pcap-analysis', 12
      ))
    }

    if (input.observedCert.selfSigned) {
      findings.push(finding('Certificate', 'MEDIUM', nextId('CERT-SELF-SIGNED'),
        'Self-signed certificate detected',
        'The server is using a self-signed certificate. Without a trusted CA signature, clients cannot verify the server\'s authenticity.',
        { observed: `issuer=${input.observedCert.issuer}, subject=${input.observedCert.commonName}` },
        'Clients may reject the connection or users may bypass certificate warnings, enabling man-in-the-middle attacks.',
        'Replace with a certificate issued by a trusted CA (Let\'s Encrypt, commercial CA).',
        'pcap-analysis', 10
      ))
    }

    if (!input.observedCert.chainValid) {
      findings.push(finding('Certificate', 'HIGH', nextId('CERT-CHAIN-INVALID'),
        'Certificate chain is invalid or incomplete',
        'The certificate chain cannot be verified. Intermediate certificates may be missing or the chain leads to an untrusted root.',
        { observed: 'chainValid=false' },
        'TLS connections may fail for clients performing strict chain validation.',
        'Ensure the full certificate chain (server + intermediates) is served by the mail server.',
        'pcap-analysis', 12
      ))
    }

    if (isWeakPublicKey(input.observedCert.publicKeyAlgorithm, input.observedCert.publicKeyLength)) {
      findings.push(finding('Certificate', 'HIGH', nextId('WEAK-PUBKEY'),
        `Weak public key: ${input.observedCert.publicKeyAlgorithm} ${input.observedCert.publicKeyLength}-bit`,
        `The certificate uses a ${input.observedCert.publicKeyLength}-bit ${input.observedCert.publicKeyAlgorithm} key. This key size is considered insufficient by current cryptographic standards.`,
        { observed: `${input.observedCert.publicKeyAlgorithm} ${input.observedCert.publicKeyLength}-bit` },
        'Weak keys can be factored by dedicated attackers, compromising server identity verification.',
        'Replace with RSA-2048 minimum (RSA-3072 recommended) or ECDSA P-256.',
        'pcap-analysis', 10
      ))
    }

    if (isWeakSignatureAlgorithm(input.observedCert.signatureAlgorithm)) {
      findings.push(finding('Certificate', 'HIGH', nextId('WEAK-SIG-ALG'),
        `Weak certificate signature algorithm: ${input.observedCert.signatureAlgorithm}`,
        `The certificate is signed with ${input.observedCert.signatureAlgorithm}. SHA-1 and MD5 signatures are cryptographically broken and should not be used.`,
        { observed: input.observedCert.signatureAlgorithm },
        'Certificate signatures may be forged, enabling man-in-the-middle attacks.',
        'Reissue the certificate with SHA-256 or SHA-384 signature algorithm.',
        'pcap-analysis', 8
      ))
    }
  }

  // ── Configuration comparison findings ────────────────────────────────────
  if (input.comparison && input.comparison.mismatches.length > 0) {
    findings.push(finding('Configuration', 'HIGH', nextId('CONFIG-MISMATCH'),
      'Configuration vs observed values mismatch',
      `${input.comparison.mismatches.length} field(s) differ between the configured Email Lab settings and the values observed in the capture: ${input.comparison.mismatches.join(', ')}.`,
      { mismatches: input.comparison.mismatches },
      'The capture does not reflect the intended security configuration. Security controls may not be functioning as intended.',
      'Review server configuration. Ensure all TLS and certificate settings are correctly applied.',
      'configuration-check', input.comparison.mismatches.length * 3
    ))
  }

  return findings
}

// ─── Anomaly detection ────────────────────────────────────────────────────────

export function detectAnomalies(input: FindingsInput): Anomaly[] {
  const anomalies: Anomaly[] = []

  if (!input.comparison) return anomalies

  const comp = input.comparison

  // TLS version mismatch
  if (comp.tlsVersion.status === 'mismatch') {
    anomalies.push({
      anomaly: true,
      type: 'TLS_DOWNGRADE',
      severity: 'HIGH',
      evidence: `Configured: ${comp.tlsVersion.configured} | Observed: ${comp.tlsVersion.observed}`,
      configured: comp.tlsVersion.configured,
      observed: comp.tlsVersion.observed,
    })
  }

  // Cipher downgrade
  if (comp.cipherSuite.status === 'mismatch') {
    anomalies.push({
      anomaly: true,
      type: 'CIPHER_DOWNGRADE',
      severity: 'MEDIUM',
      evidence: `Configured: ${comp.cipherSuite.configured} | Observed: ${comp.cipherSuite.observed}`,
      configured: comp.cipherSuite.configured,
      observed: comp.cipherSuite.observed,
    })
  }

  // STARTTLS not negotiated
  if (
    input.observedStarttls.advertised &&
    !input.observedStarttls.negotiated
  ) {
    anomalies.push({
      anomaly: true,
      type: 'STARTTLS_NOT_NEGOTIATED',
      severity: 'HIGH',
      evidence: 'STARTTLS advertised in EHLO but TLS handshake not completed in capture',
    })
  }

  // Certificate expired when it shouldn't be
  if (comp.certExpired.status === 'mismatch') {
    anomalies.push({
      anomaly: true,
      type: 'CERT_EXPIRED',
      severity: 'HIGH',
      evidence: `Certificate expired — configured validUntil: ${comp.certExpired.configured}, observed: ${comp.certExpired.observed}`,
    })
  }

  // Unexpected weak params
  if (
    isWeakCipher(input.observedTls.cipherSuite) &&
    input.configured &&
    !isWeakCipher(input.configured.tls.cipherSuite)
  ) {
    anomalies.push({
      anomaly: true,
      type: 'WEAK_PARAMS_OBSERVED',
      severity: 'HIGH',
      evidence: `Configured strong cipher: ${input.configured.tls.cipherSuite}, but observed weak cipher: ${input.observedTls.cipherSuite}`,
    })
  }

  return anomalies
}

// ─── Helper ───────────────────────────────────────────────────────────────────

function finding(
  category: FindingCategory,
  severity: FindingSeverity,
  id: string,
  title: string,
  description: string,
  evidence: Record<string, unknown>,
  impact: string,
  recommendation: string,
  source: SecurityFinding['source'],
  deduction: number,
): SecurityFinding {
  return { id, category, severity, title, description, evidence, impact, recommendation, source, deduction }
}
