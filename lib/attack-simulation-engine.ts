/**
 * SecureMailScope Attack Simulation Engine
 *
 * Cybersecurity training and demonstration engine for theoretical vulnerability simulation.
 *
 * SAFETY MANDATE:
 * - Operates strictly as a simulated, sandboxed model.
 * - Does NOT execute real destructive network attacks.
 * - Does NOT connect to real arbitrary hosts or inject packets into user networks.
 * - All terminal executions, logs, and attack paths are simulated evaluations grounded
 *   in the current passive PCAP analysis report.
 */

import type { CanonicalAnalysis, FindingSeverity, SecurityFinding } from './types'

export type SimulationScenarioId =
  | 'tls-downgrade'
  | 'starttls-downgrade'
  | 'weak-cipher'
  | 'certificate-failure'
  | 'expired-cert'
  | 'no-pfs'
  | 'legacy-protocol'
  | 'metadata-exposure'
  | 'credential-exposure'
  | 'dos-impact'

export interface AttackPathNode {
  step: number
  title: string
  stage: string
  description: string
  status: 'OBSERVED' | 'SIMULATED' | 'PREDICTED'
}

export interface SimulationStageProgress {
  timeSec: number
  stage: string
  status: 'pending' | 'active' | 'completed'
  label: string
  description: string
}

export interface AttackSimulationObject {
  simulationId: string
  scenario: SimulationScenarioId
  scenarioTitle: string
  simulationOnly: true

  triggerFinding: {
    id: string
    title: string
    severity: FindingSeverity
    category: string
  }

  evidence: string[]

  stages: SimulationStageProgress[]

  commands: Array<{
    command: string
    purpose: string
    whatItSimulates: string
    whySelected: string
    relatedFinding: string
    expectedImpact: string
    evidence: string
    severity: FindingSeverity
    applicableStandard: string
    remediation: string
  }>

  impact: {
    summary: string
    confidentiality: string
    integrity: string
    availability: string
    simulatedOutcome: string
    affectedAssets: string[]
  }

  attackPath: AttackPathNode[]

  rootCause: {
    control: string
    failure: string
    configuration: string
    evidence: string
    impact: string
  }

  remediation: {
    immediateFix: string
    recommendedConfig: string
    longTermHardening: string
    reference: string
  }

  references: string[]

  aiExplanation?: {
    narrative: string
    mitigationPlan: string
    attackerTactics: string
  }
}

export interface ScenarioDefinition {
  id: SimulationScenarioId
  name: string
  command: string
  description: string
  category: string
  isApplicable: (analysis: CanonicalAnalysis) => { applicable: boolean; finding?: SecurityFinding; evidence?: string }
}

export const SIMULATION_SCENARIOS: ScenarioDefinition[] = [
  {
    id: 'tls-downgrade',
    name: 'TLS Downgrade Simulation',
    command: 'simulate --scenario tls-downgrade',
    description: 'Simulates an adversary manipulating ClientHello/ServerHello to coerce negotiation down to deprecated TLS 1.0/1.1.',
    category: 'TLS Version',
    isApplicable: (analysis) => {
      const v = analysis.observed.tls.version
      const finding = analysis.findings.find(
        (f) => f.category === 'TLS' || f.title.toLowerCase().includes('tls 1.0') || f.title.toLowerCase().includes('tls 1.1') || f.title.toLowerCase().includes('deprecated')
      )
      if (v === 'TLS1.0' || v === 'TLS1.1' || finding) {
        return { applicable: true, finding, evidence: `Observed TLS version: ${v}` }
      }
      return { applicable: false }
    },
  },
  {
    id: 'starttls-downgrade',
    name: 'STARTTLS Downgrade / Strip Simulation',
    command: 'simulate --scenario starttls-downgrade',
    description: 'Simulates an on-path attacker intercepting SMTP EHLO responses and stripping the STARTTLS capability keyword.',
    category: 'STARTTLS',
    isApplicable: (analysis) => {
      const s = analysis.observed.starttls
      const finding = analysis.findings.find(
        (f) => f.category === 'STARTTLS' || f.title.toLowerCase().includes('starttls') || f.description.toLowerCase().includes('plaintext')
      )
      if ((s.advertised && !s.negotiated) || s.plaintextPhaseObserved || !s.required || finding) {
        return {
          applicable: true,
          finding,
          evidence: s.plaintextPhaseObserved
            ? 'Plaintext SMTP commands observed before TLS negotiation'
            : 'STARTTLS advertised but secure upgrade not enforced',
        }
      }
      return { applicable: false }
    },
  },
  {
    id: 'weak-cipher',
    name: 'Weak Cipher Exploitation Simulation',
    command: 'simulate --scenario weak-cipher',
    description: 'Simulates theoretical ciphertext recovery against legacy ciphers (3DES Sweet32 collision or CBC padding oracle).',
    category: 'Cipher',
    isApplicable: (analysis) => {
      const cipher = analysis.observed.tls.cipherSuite.toLowerCase()
      const finding = analysis.findings.find(
        (f) => f.category === 'Cipher' || f.title.toLowerCase().includes('cipher') || f.title.toLowerCase().includes('3des') || f.title.toLowerCase().includes('cbc')
      )
      if (cipher.includes('3des') || cipher.includes('cbc') || cipher.includes('rc4') || cipher.includes('sha1') || finding) {
        return { applicable: true, finding, evidence: `Observed cipher suite: ${analysis.observed.tls.cipherSuite}` }
      }
      return { applicable: false }
    },
  },
  {
    id: 'certificate-failure',
    name: 'Certificate Validation Failure Simulation',
    command: 'simulate --scenario certificate-failure',
    description: 'Simulates strict client abort or bypass when presented with untrusted or self-signed certificates.',
    category: 'Certificate',
    isApplicable: (analysis) => {
      const cert = analysis.observed.certificate
      const finding = analysis.findings.find(
        (f) => f.category === 'Certificate' && (f.title.toLowerCase().includes('chain') || f.title.toLowerCase().includes('self-signed') || f.title.toLowerCase().includes('trust'))
      )
      if (!cert.chainValid || cert.selfSigned || finding) {
        return {
          applicable: true,
          finding,
          evidence: cert.selfSigned ? 'Self-signed certificate observed' : 'Certificate chain validation failed',
        }
      }
      return { applicable: false }
    },
  },
  {
    id: 'expired-cert',
    name: 'Expired Certificate Trust Simulation',
    command: 'simulate --scenario expired-cert',
    description: 'Simulates MTA delivery rejection or fraudulent interception against a server presenting an expired certificate.',
    category: 'Certificate',
    isApplicable: (analysis) => {
      const cert = analysis.observed.certificate
      const finding = analysis.findings.find(
        (f) => f.category === 'Certificate' && (f.title.toLowerCase().includes('expired') || f.title.toLowerCase().includes('validity'))
      )
      if (cert.expired || finding) {
        return {
          applicable: true,
          finding,
          evidence: `Certificate expired on ${cert.validUntil} (Common Name: "${cert.commonName}")`,
        }
      }
      return { applicable: false }
    },
  },
  {
    id: 'no-pfs',
    name: 'No-Forward-Secrecy Exposure Simulation',
    command: 'simulate --scenario no-pfs',
    description: 'Simulates passive traffic recording followed by retroactive decryption upon hypothetical private key exposure.',
    category: 'PFS',
    isApplicable: (analysis) => {
      const pfs = analysis.observed.tls.forwardSecrecy
      const finding = analysis.findings.find(
        (f) => f.category === 'PFS' || f.category === 'KeyExchange' || f.title.toLowerCase().includes('forward secrecy') || f.title.toLowerCase().includes('static rsa')
      )
      if (!pfs || finding) {
        return {
          applicable: true,
          finding,
          evidence: `Forward Secrecy flag: false. Key exchange mechanism: ${analysis.observed.tls.keyExchange || 'Static RSA'}`,
        }
      }
      return { applicable: false }
    },
  },
  {
    id: 'legacy-protocol',
    name: 'Legacy Protocol Exposure Simulation',
    command: 'simulate --scenario legacy-protocol',
    description: 'Simulates unencrypted cleartext mail session exposure on non-standard or legacy transport ports.',
    category: 'Protocol',
    isApplicable: (analysis) => {
      const proto = analysis.observed.protocol
      const finding = analysis.findings.find(
        (f) => f.category === 'Protocol' || f.title.toLowerCase().includes('unencrypted') || f.title.toLowerCase().includes('plaintext')
      )
      if (!analysis.observed.tls.handshakeComplete || finding) {
        return { applicable: true, finding, evidence: `Unencrypted mail transport observed on port ${proto.port}` }
      }
      return { applicable: false }
    },
  },
  {
    id: 'metadata-exposure',
    name: 'Metadata Exposure Simulation',
    command: 'simulate --scenario metadata-exposure',
    description: 'Simulates passive inspection of cleartext envelope metadata, sender/recipient addresses, and message IDs.',
    category: 'Protocol',
    isApplicable: (analysis) => {
      const starttls = analysis.observed.starttls
      const finding = analysis.findings.find(
        (f) => f.title.toLowerCase().includes('metadata') || f.title.toLowerCase().includes('plaintext') || f.category === 'Protocol'
      )
      if (starttls.plaintextPhaseObserved || !analysis.observed.tls.handshakeComplete || finding) {
        return {
          applicable: true,
          finding,
          evidence: 'Plaintext EHLO / MAIL FROM command headers observable prior to cryptographic session establishment',
        }
      }
      return { applicable: false }
    },
  },
  {
    id: 'credential-exposure',
    name: 'Credential Exposure Scenario',
    command: 'simulate --scenario credential-exposure',
    description: 'Simulates credential harvesting attack when AUTH PLAIN or AUTH LOGIN commands are sent across unencrypted channels.',
    category: 'Protocol',
    isApplicable: (analysis) => {
      const finding = analysis.findings.find(
        (f) => f.title.toLowerCase().includes('auth') || f.title.toLowerCase().includes('credential') || f.title.toLowerCase().includes('password')
      )
      const unencrypted = !analysis.observed.tls.handshakeComplete || analysis.observed.starttls.plaintextPhaseObserved
      if (finding || unencrypted) {
        return {
          applicable: true,
          finding,
          evidence: finding?.description || 'Plaintext authentication phase vulnerable to local network sniffing',
        }
      }
      return { applicable: false }
    },
  },
  {
    id: 'dos-impact',
    name: 'Denial-of-Service Impact Simulation',
    command: 'simulate --scenario dos-impact',
    description: 'Simulates mail queue congestion and handshake timeout exhaustion without generating real packet flooding.',
    category: 'Anomaly',
    isApplicable: (analysis) => {
      const hasAnomaly = analysis.anomalies.length > 0
      const finding = analysis.findings.find(
        (f) => f.category === 'Anomaly' || f.title.toLowerCase().includes('handshake') || f.title.toLowerCase().includes('timeout')
      )
      if (hasAnomaly || finding || !analysis.observed.tls.handshakeComplete) {
        return {
          applicable: true,
          finding,
          evidence: `Simulated MTA handshake stall based on ${analysis.anomalies.length} observed anomaly indicators`,
        }
      }
      return { applicable: false }
    },
  },
]

// ─── 40-Second Simulation Stage Timeline Definition ─────────────────────────

export const SIMULATION_STAGES: Array<{
  stage: string
  timeSec: number
  label: string
  description: string
}> = [
  { stage: 'report_analysis', timeSec: 0, label: 'Loading security report', description: 'Parsing canonical assessment and extracting observed cryptographic parameters.' },
  { stage: 'control_identification', timeSec: 5, label: 'Identifying vulnerable control', description: 'Cross-referencing finding deductions against NIST SP 800-52 / RFC standards.' },
  { stage: 'sandbox_prep', timeSec: 10, label: 'Preparing isolated simulation', description: 'Initializing secure educational simulation environment (no live network egress).' },
  { stage: 'attacker_step', timeSec: 15, label: 'Simulating attacker initial step', description: 'Simulating adversary positioning on mail transfer route.' },
  { stage: 'control_failure', timeSec: 20, label: 'Simulating security-control failure', description: 'Evaluating simulated bypass of target defensive control.' },
  { stage: 'impact_simulation', timeSec: 25, label: 'Simulating impact', description: 'Computing theoretical confidentiality and integrity compromise metrics.' },
  { stage: 'asset_analysis', timeSec: 30, label: 'Analyzing affected assets', description: 'Mapping affected email domains, submission ports, and user data streams.' },
  { stage: 'threat_prediction', timeSec: 35, label: 'Predicting next attacker step', description: 'Forecasting adversary lateral movement and post-compromise objectives.' },
  { stage: 'remediation_generation', timeSec: 38, label: 'Generating remediation', description: 'Formulating prioritized immediate fixes and long-term hardening standards.' },
  { stage: 'complete', timeSec: 40, label: 'Simulation Complete', description: 'Simulated assessment finalized with comprehensive evidentiary report.' },
]

// ─── Build Canonical Simulation Object ───────────────────────────────────────

export function buildAttackSimulation(
  analysis: CanonicalAnalysis,
  scenarioId: SimulationScenarioId,
  overrideFindingId?: string
): AttackSimulationObject {
  const scenarioDef = SIMULATION_SCENARIOS.find((s) => s.id === scenarioId) || SIMULATION_SCENARIOS[0]
  const check = scenarioDef.isApplicable(analysis)

  let finding: SecurityFinding | undefined = check.finding
  if (overrideFindingId) {
    const specific = analysis.findings.find((f) => f.id === overrideFindingId)
    if (specific) finding = specific
  }

  // Fallback trigger finding if none directly matched
  const triggerFinding = {
    id: finding?.id || `SIM-${scenarioDef.id.toUpperCase()}`,
    title: finding?.title || `${scenarioDef.name} Weakness`,
    severity: (finding?.severity || 'HIGH') as FindingSeverity,
    category: finding?.category || scenarioDef.category,
  }

  const evidenceList: string[] = []
  if (check.evidence) evidenceList.push(check.evidence)
  if (finding?.evidence) {
    evidenceList.push(
      typeof finding.evidence === 'string'
        ? finding.evidence
        : JSON.stringify(finding.evidence)
    )
  }
  evidenceList.push(`Analyzed Capture: "${analysis.capture.filename}" (Port ${analysis.observed.protocol.port}, ${analysis.observed.protocol.detected})`)

  // 1. Dynamic Attack Path
  const attackPath: AttackPathNode[] = buildDynamicAttackPath(scenarioId, triggerFinding, analysis)

  // 2. Command Details
  const commandDetail = buildCommandDetail(scenarioDef, triggerFinding, evidenceList[0] || 'Observed wire parameters')

  // 3. Root Cause
  const rootCause = buildRootCause(scenarioId, triggerFinding, analysis)

  // 4. Remediation
  const remediation = buildRemediation(scenarioId, analysis)

  // 5. Impact Metrics
  const impact = buildImpactMetrics(scenarioId, analysis)

  return {
    simulationId: `SIM-${Date.now().toString(36)}-${scenarioId}`,
    scenario: scenarioId,
    scenarioTitle: scenarioDef.name,
    simulationOnly: true,
    triggerFinding,
    evidence: evidenceList,
    stages: SIMULATION_STAGES.map((s) => ({
      ...s,
      status: 'pending',
    })),
    commands: [commandDetail],
    impact,
    attackPath,
    rootCause,
    remediation,
    references: [
      remediation.reference,
      'NIST SP 800-52 Rev. 2 Section 3',
      'SecureMailScope Forensic Assessment Standard',
    ],
  }
}

// ─── Dynamic Attack Path Generator ──────────────────────────────────────────

function buildDynamicAttackPath(
  scenarioId: SimulationScenarioId,
  trigger: AttackSimulationObject['triggerFinding'],
  analysis: CanonicalAnalysis
): AttackPathNode[] {
  switch (scenarioId) {
    case 'tls-downgrade':
      return [
        { step: 1, title: 'Network Reconnaissance', stage: 'Initial Observation', description: `Adversary observes TLS handshake negotiation offering ${analysis.observed.tls.version}.`, status: 'OBSERVED' },
        { step: 2, title: 'Identify Protocol Weakness', stage: 'Vulnerability Analysis', description: `Server permits deprecated TLS 1.0/1.1 negotiation without mandatory anti-downgrade sentinels.`, status: 'OBSERVED' },
        { step: 3, title: 'Simulate Handshake Tampering', stage: 'Simulated Exploit', description: 'Simulated adversary modifies ClientHello.cipher_suites to strip modern TLS 1.2/1.3 proposals.', status: 'SIMULATED' },
        { step: 4, title: 'Weak Protocol Negotiation', stage: 'Simulated Exploit', description: 'Server accepts legacy handshake, falling back to CBC ciphers and weak key exchange.', status: 'SIMULATED' },
        { step: 5, title: 'Potential Cryptographic Exposure', stage: 'Impact Projection', description: 'Simulated exploitation of BEAST or POODLE attack vectors allows plaintext block recovery.', status: 'PREDICTED' },
        { step: 6, title: 'Lateral Credential Harvesting', stage: 'Post-Exploitation', description: 'Adversary leverages recovered session tokens to authenticate against webmail interfaces.', status: 'PREDICTED' },
      ]

    case 'starttls-downgrade':
      return [
        { step: 1, title: 'Initial SMTP Interception', stage: 'Initial Access', description: `Adversary monitors cleartext port ${analysis.observed.protocol.port} connection before TLS initiation.`, status: 'OBSERVED' },
        { step: 2, title: 'Identify STARTTLS Weakness', stage: 'Vulnerability Analysis', description: 'STARTTLS is either un-enforced or plaintext phase transmits credentials opportunistically.', status: 'OBSERVED' },
        { step: 3, title: 'Simulate STARTTLS Stripping', stage: 'Simulated Exploit', description: 'Simulated adversary intercepts EHLO greeting and removes "250-STARTTLS" response line.', status: 'SIMULATED' },
        { step: 4, title: 'Plaintext Session Exposure', stage: 'Simulated Impact', description: 'Mail client assumes server lacks TLS capability and continues in cleartext.', status: 'SIMULATED' },
        { step: 5, title: 'Credential / Message Harvesting', stage: 'Impact Projection', description: 'Sender, recipient, AUTH PLAIN credentials, and email contents captured in cleartext.', status: 'PREDICTED' },
        { step: 6, title: 'Account Hijack & Phishing', stage: 'Post-Exploitation', description: 'Captured sender credentials used to launch spear-phishing campaigns from authentic domains.', status: 'PREDICTED' },
      ]

    case 'weak-cipher':
      return [
        { step: 1, title: 'Cipher Suite Enumeration', stage: 'Observation', description: `Observed cipher ${analysis.observed.tls.cipherSuite} accepted during ServerHello.`, status: 'OBSERVED' },
        { step: 2, title: 'Identify Primitive Weakness', stage: 'Vulnerability Analysis', description: 'Cipher relies on 64-bit blocks (3DES) or non-AEAD CBC mode vulnerable to padding oracles.', status: 'OBSERVED' },
        { step: 3, title: 'Simulate Traffic Capture', stage: 'Simulated Exploit', description: 'Adversary records large volumes of encrypted email exchanges (~32GB for Sweet32).', status: 'SIMULATED' },
        { step: 4, title: 'Collision / Padding Attack', stage: 'Simulated Impact', description: 'Simulated block collision recovery reveals target authentication cookies or tokens.', status: 'SIMULATED' },
        { step: 5, title: 'Session Impersonation', stage: 'Impact Projection', description: 'Recovered session authentication used to impersonate internal employees.', status: 'PREDICTED' },
      ]

    case 'certificate-failure':
    case 'expired-cert':
      return [
        { step: 1, title: 'Certificate Inspection', stage: 'Observation', description: `Server presents certificate for "${analysis.observed.certificate.commonName}" (${analysis.observed.certificate.expired ? 'Expired' : 'Chain untrusted'}).`, status: 'OBSERVED' },
        { step: 2, title: 'Identify Trust Weakness', stage: 'Vulnerability Analysis', description: 'Lack of valid trusted CA chain or expired validity window causes client validation warnings.', status: 'OBSERVED' },
        { step: 3, title: 'Simulate Rogue Proxy Insertion', stage: 'Simulated Exploit', description: 'Adversary deploys proxy with self-signed certificate, exploiting user certificate override.', status: 'SIMULATED' },
        { step: 4, title: 'Simulated MITM Interception', stage: 'Simulated Impact', description: 'Client accepts rogue proxy; simulated decrypted session stream captured.', status: 'SIMULATED' },
        { step: 5, title: 'Message Tampering & Eavesdropping', stage: 'Impact Projection', description: 'Adversary injects malicious payload links into in-flight emails.', status: 'PREDICTED' },
      ]

    case 'no-pfs':
      return [
        { step: 1, title: 'Passive Encrypted Capture', stage: 'Observation', description: `Traffic negotiated static key exchange (${analysis.observed.tls.keyExchange || 'RSA'}) without PFS.`, status: 'OBSERVED' },
        { step: 2, title: 'Identify PFS Absence', stage: 'Vulnerability Analysis', description: 'Absence of ephemeral Diffie-Hellman keys means session keys derive from long-term RSA key.', status: 'OBSERVED' },
        { step: 3, title: 'Long-Term Key Compromise Scenario', stage: 'Simulated Exploit', description: 'Adversary hypothetical compromise of server private key via host intrusion or insider.', status: 'SIMULATED' },
        { step: 4, title: 'Retroactive Decryption Simulation', stage: 'Simulated Impact', description: 'All historically archived PCAP traffic decrypted in bulk using recovered private key.', status: 'SIMULATED' },
        { step: 5, title: 'Historic Data Breach', stage: 'Impact Projection', description: 'Months or years of archived proprietary communications exposed simultaneously.', status: 'PREDICTED' },
      ]

    default:
      return [
        { step: 1, title: 'Protocol Observation', stage: 'Observation', description: `Observed mail transport parameter: ${trigger.title}.`, status: 'OBSERVED' },
        { step: 2, title: 'Weakness Identification', stage: 'Vulnerability Analysis', description: 'Defensive control does not meet modern cryptographic standards.', status: 'OBSERVED' },
        { step: 3, title: 'Simulated Exploitation Step', stage: 'Simulated Exploit', description: 'Simulated adversary probes protocol boundaries and error handling.', status: 'SIMULATED' },
        { step: 4, title: 'Control Failure Simulated', stage: 'Simulated Impact', description: 'Target security boundary bypassed in simulation environment.', status: 'SIMULATED' },
        { step: 5, title: 'Projected Enterprise Risk', stage: 'Impact Projection', description: 'Theoretical exposure of mail transmission data or system integrity.', status: 'PREDICTED' },
      ]
  }
}

// ─── Helpers: Command, Root Cause, Remediation, Impact ───────────────────────

function buildCommandDetail(
  scenario: ScenarioDefinition,
  trigger: AttackSimulationObject['triggerFinding'],
  evidence: string
) {
  const map: Record<SimulationScenarioId, { purpose: string; what: string; impact: string; standard: string; fix: string }> = {
    'tls-downgrade': {
      purpose: 'Simulates active tampering with ClientHello to force negotiation down to deprecated TLS 1.0.',
      what: 'Simulates interception and manipulation of protocol version advertisement packets.',
      impact: 'Allows exploitation of legacy CBC vulnerabilities and exposes session data to plaintext decryption.',
      standard: 'RFC 8996 (Deprecating TLS 1.0/1.1) & NIST SP 800-52 Rev. 2 Section 3.1',
      fix: 'Disable TLS 1.0 and TLS 1.1 in mail server configuration; require TLS 1.2 minimum.',
    },
    'starttls-downgrade': {
      purpose: 'Simulates an adversary stripping the 250-STARTTLS capability from cleartext SMTP greetings.',
      what: 'Simulates on-path modification of SMTP server response banners.',
      impact: 'Forces mail client to transmit credentials and messages in unencrypted cleartext.',
      standard: 'RFC 3207 Section 4 & CISA Secure Email Architecture Guidance',
      fix: 'Enforce mandatory STARTTLS and deploy MTA-STS / DANE DNS security policies.',
    },
    'weak-cipher': {
      purpose: 'Simulates theoretical ciphertext recovery against weak 3DES or non-AEAD CBC ciphers.',
      what: 'Simulates known plaintext collision and padding oracle attacks in a safe isolated model.',
      impact: 'Enables partial or full plaintext recovery without discovering the server private key.',
      standard: 'NIST SP 800-52 Rev. 2 Section 3.3.1 & NIST SP 800-131A Rev. 2',
      fix: 'Disallow 3DES, RC4, and CBC suites. Require AEAD ciphers (AES-GCM, ChaCha20-Poly1305).',
    },
    'certificate-failure': {
      purpose: 'Simulates Man-in-the-Middle traffic redirection against a server with invalid certificate chain.',
      what: 'Simulates certificate validation bypass and rogue CA presentation.',
      impact: 'Clients may unknowingly connect to an attacker-controlled mail proxy.',
      standard: 'CA/Browser Forum Baseline Requirements Section 6.1.5',
      fix: 'Install complete CA bundle containing all intermediate certificates up to a trusted root.',
    },
    'expired-cert': {
      purpose: 'Simulates trust rejection and opportunistic interception of an expired certificate.',
      what: 'Simulates automated MTA delivery failure and user security warning bypass.',
      impact: 'Loss of email delivery availability or exposure to active interception.',
      standard: 'CA/Browser Forum Baseline Requirements Section 6.3.2',
      fix: 'Renew certificate immediately and implement automated renewal (e.g. ACME/Certbot).',
    },
    'no-pfs': {
      purpose: 'Simulates retrospective bulk decryption of recorded traffic following private key exposure.',
      what: 'Simulates passive recording followed by offline decryption of static RSA key exchange.',
      impact: 'All historically captured traffic can be decrypted if server private key is ever exposed.',
      standard: 'NIST SP 800-52 Rev. 2 Section 3.3.2 (Mandatory Ephemeral Key Exchange)',
      fix: 'Enable ECDHE or DHE key exchange to enforce Perfect Forward Secrecy on all sessions.',
    },
    'legacy-protocol': {
      purpose: 'Simulates unencrypted traffic sniffing on legacy mail ports (port 25/110/143).',
      what: 'Simulates passive packet capture of unencrypted SMTP/POP3/IMAP streams.',
      impact: 'Complete exposure of email bodies, headers, and authentication credentials.',
      standard: 'NIST SP 800-52 Rev. 2 Section 3.1 & CISA Guidance',
      fix: 'Require transport encryption on all listening ports (SMTPS, IMAPS, mandatory STARTTLS).',
    },
    'metadata-exposure': {
      purpose: 'Simulates passive harvesting of cleartext email headers, sender addresses, and recipients.',
      what: 'Simulates metadata extraction from unencrypted protocol greeting phases.',
      impact: 'Facilitates targeted social engineering, organizational mapping, and spear phishing.',
      standard: 'RFC 3207 & CISA Secure Email Architecture Guidance',
      fix: 'Transition to implicit TLS ports (e.g. Port 465) or enforce mandatory STARTTLS.',
    },
    'credential-exposure': {
      purpose: 'Simulates harvesting of base64-encoded AUTH credentials sent across cleartext channels.',
      what: 'Simulates extraction and decoding of AUTH PLAIN and AUTH LOGIN streams.',
      impact: 'Direct compromise of user mail accounts and unauthorized email sending.',
      standard: 'RFC 4954 Section 4 & NIST SP 800-52 Rev. 2',
      fix: 'Disable cleartext authentication unless TLS encryption has completed successfully.',
    },
    'dos-impact': {
      purpose: 'Simulates resource exhaustion caused by incomplete handshakes or slow negotiation.',
      what: 'Simulates connection queue starvation inside internal software limits without network flooding.',
      impact: 'Valid email messages cannot be delivered, causing mail queue backlog and delivery delays.',
      standard: 'RFC 8446 Appendix D & CISA Guidance',
      fix: 'Tune MTA connection rate limits, enforce aggressive handshake timeouts, and deploy TLS 1.3.',
    },
  }

  const info = map[scenario.id] || map['tls-downgrade']

  return {
    command: scenario.command,
    purpose: info.purpose,
    whatItSimulates: info.what,
    whySelected: `Current security analysis identified ${trigger.title} (${trigger.severity} severity).`,
    relatedFinding: trigger.id,
    expectedImpact: info.impact,
    evidence,
    severity: trigger.severity,
    applicableStandard: info.standard,
    remediation: info.fix,
  }
}

function buildRootCause(
  scenarioId: SimulationScenarioId,
  trigger: AttackSimulationObject['triggerFinding'],
  analysis: CanonicalAnalysis
) {
  switch (scenarioId) {
    case 'tls-downgrade':
      return {
        control: 'TLS Version Policy & Protocol Negotiation',
        failure: `Deprecated TLS version (${analysis.observed.tls.version}) actively permitted by server configuration.`,
        configuration: 'Server TLS configuration lacks version floor directive (e.g. ssl_protocols TLSv1.2 TLSv1.3 missing).',
        evidence: `Observed TLS version = ${analysis.observed.tls.version} in capture "${analysis.capture.filename}".`,
        impact: 'Permits protocol downgrade attacks, leaving session vulnerable to BEAST and POODLE exploits.',
      }
    case 'starttls-downgrade':
      return {
        control: 'STARTTLS Enforcement & Upgrade Mandate',
        failure: 'Opportunistic or un-enforced STARTTLS configuration permits plaintext fallback.',
        configuration: 'MTA configured with opportunistic TLS instead of mandatory TLS encryption for sensitive relays.',
        evidence: analysis.observed.starttls.plaintextPhaseObserved
          ? 'Plaintext SMTP commands detected on wire prior to TLS handshake'
          : 'STARTTLS advertised but handshake was not observed or required',
        impact: 'Allows active network adversaries to strip STARTTLS and inspect sensitive mail in plaintext.',
      }
    case 'weak-cipher':
      return {
        control: 'Cryptographic Cipher Suite Selection',
        failure: `Legacy or non-AEAD cipher suite negotiated (${analysis.observed.tls.cipherSuite}).`,
        configuration: 'Cipher suite preference string contains deprecated CBC-mode or 3DES algorithms.',
        evidence: `Negotiated cipher suite = ${analysis.observed.tls.cipherSuite}.`,
        impact: 'Vulnerability to Sweet32 collision attacks or padding oracle attacks resulting in plaintext recovery.',
      }
    case 'certificate-failure':
    case 'expired-cert':
      return {
        control: 'X.509 Certificate Lifecycle & Trust Chain Verification',
        failure: analysis.observed.certificate.expired
          ? `Certificate expired on ${analysis.observed.certificate.validUntil}.`
          : 'Certificate chain is incomplete or self-signed.',
        configuration: 'Automated certificate renewal absent or intermediate CA bundle not concatenated to certificate file.',
        evidence: `CN: "${analysis.observed.certificate.commonName}", Expired: ${analysis.observed.certificate.expired}, ChainValid: ${analysis.observed.certificate.chainValid}.`,
        impact: 'MTA-to-MTA delivery failure, strict client aborts, or client acceptance of rogue spoofed certificates.',
      }
    case 'no-pfs':
      return {
        control: 'Perfect Forward Secrecy (Key Exchange)',
        failure: 'Static RSA key exchange used without ephemeral Diffie-Hellman parameters.',
        configuration: 'Cipher suites prioritizing TLS_RSA_* instead of ECDHE-* or TLS 1.3.',
        evidence: `Key Exchange = ${analysis.observed.tls.keyExchange || 'Static RSA'}, ForwardSecrecy = false.`,
        impact: 'Past sessions recorded by adversaries can be decrypted if server private key is subsequently exposed.',
      }
    default:
      return {
        control: 'Transport Layer Security Baseline',
        failure: `Configuration deviation identified in ${trigger.title}.`,
        configuration: 'Server configuration does not conform to NIST SP 800-52 Rev. 2 guidance.',
        evidence: trigger.title,
        impact: 'Weakened cryptographic posture and compliance penalty.',
      }
  }
}

function buildRemediation(
  scenarioId: SimulationScenarioId,
  analysis: CanonicalAnalysis
) {
  switch (scenarioId) {
    case 'tls-downgrade':
      return {
        immediateFix: 'Disable TLS 1.0 and TLS 1.1 in MTA configuration files immediately.',
        recommendedConfig: 'Configure: ssl_protocols TLSv1.2 TLSv1.3 (or equivalent for Postfix / Exim / Dovecot).',
        longTermHardening: 'Adopt TLS 1.3 as primary protocol; implement automated configuration auditing and downgrade alert logging.',
        reference: 'RFC 8996 / NIST SP 800-52 Rev. 2 Section 3.1.1',
      }
    case 'starttls-downgrade':
      return {
        immediateFix: 'Enforce mandatory STARTTLS on mail submission ports (Port 587 / 465).',
        recommendedConfig: 'Deploy MTA-STS (RFC 8461) with mode: enforce and publish valid TLSA records for DANE (RFC 7672).',
        longTermHardening: 'Monitor MTA logs for stripping attempts; transition external submission to SMTPS (Port 465) with implicit TLS.',
        reference: 'RFC 3207 / RFC 8461 / CISA Secure Email Guidance',
      }
    case 'weak-cipher':
      return {
        immediateFix: 'Remove 3DES, RC4, and CBC-mode suites from server cipher configuration.',
        recommendedConfig: 'Prioritize AEAD suites: TLS_AES_256_GCM_SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384.',
        longTermHardening: 'Transition exclusively to TLS 1.3 cipher suites which mandate AEAD by design.',
        reference: 'NIST SP 800-52 Rev. 2 Section 3.3.1 / NIST SP 800-131A Rev. 2',
      }
    case 'certificate-failure':
    case 'expired-cert':
      return {
        immediateFix: 'Renew or re-issue server certificate with a valid CA signature and complete intermediate chain bundle.',
        recommendedConfig: 'Ensure fullchain.pem includes server cert + intermediate CA certificates. Key size >= RSA 2048 or ECDSA P-256.',
        longTermHardening: 'Deploy ACME-based automated renewal with pre-expiry alerting 30 days prior to certificate expiration.',
        reference: 'CA/Browser Forum Baseline Requirements Section 6.1.5 & 6.3.2',
      }
    case 'no-pfs':
      return {
        immediateFix: 'Disable static RSA cipher suites and configure ECDHE named curves (X25519, secp256r1).',
        recommendedConfig: 'Enable TLS 1.3 or configure ECDHE cipher suites exclusively for TLS 1.2.',
        longTermHardening: 'Enforce Perfect Forward Secrecy across all mail transfer boundaries to protect historical session privacy.',
        reference: 'NIST SP 800-52 Rev. 2 Section 3.3.2 / CISA Guidance',
      }
    default:
      return {
        immediateFix: 'Apply standard security baseline updates to mail transfer agents.',
        recommendedConfig: 'Align MTA configurations with NIST SP 800-52 Rev. 2 guidelines.',
        longTermHardening: 'Regularly perform passive PCAP forensic reviews with SecureMailScope.',
        reference: 'NIST SP 800-52 Rev. 2',
      }
  }
}

function buildImpactMetrics(
  scenarioId: SimulationScenarioId,
  analysis: CanonicalAnalysis
) {
  const isPlaintext = scenarioId === 'starttls-downgrade' || scenarioId === 'legacy-protocol' || scenarioId === 'credential-exposure'
  return {
    summary: isPlaintext
      ? 'High risk of plaintext data compromise across transport channel.'
      : 'Moderate to high risk of cryptographic degradation or authentication bypass.',
    confidentiality: isPlaintext
      ? 'CRITICAL (Simulated full exposure of message headers, contents, and authentication strings)'
      : 'ELEVATED (Simulated potential partial plaintext recovery or retrospective decryption)',
    integrity: isPlaintext
      ? 'COMPROMISED (Simulated adversary can modify message contents or inject payloads in transit)'
      : 'PROTECTED (TLS MAC / AEAD integrity remains intact until full session bypass)',
    availability: scenarioId === 'dos-impact' || scenarioId === 'expired-cert'
      ? 'IMPACTED (Simulated delivery failures or handshake timeouts)'
      : 'NORMAL (Transport connectivity maintained)',
    simulatedOutcome: `Simulated attack demonstration for ${scenarioId} completed in sandboxed training environment. No real packets were sent outside the simulator.`,
    affectedAssets: [
      `Target Port: ${analysis.observed.protocol.port} (${analysis.observed.protocol.detected})`,
      `Cryptographic Endpoint: ${analysis.capture.destinationIp || 'Mail Server'}:${analysis.observed.protocol.port}`,
      `Negotiated Protocol: ${analysis.observed.tls.version}`,
    ],
  }
}
