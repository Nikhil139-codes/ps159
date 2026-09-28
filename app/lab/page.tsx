'use client'

import { FormEvent, useCallback, useMemo, useRef, useState } from 'react'
import {
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  Copy,
  Download,
  FileText,
  Loader2,
  Mail,
  Paperclip,
  Server,
  ShieldCheck,
  SlidersHorizontal,
  Terminal,
  Zap,
} from 'lucide-react'
import { AppShell, PageHeader, StatusBadge } from '@/components/app-shell'
import { saveAnalysisSession } from '@/lib/analysis-storage'

import type {
  EmailProtocol,
  TlsVersion,
  CipherSuite,
  KeyExchangeMechanism,
  NamedGroup,
  CertKeyAlgorithm,
  SignatureAlgorithm,
  TestScenario,
} from '@/lib/types'
import { deriveForwardSecrecy, isTlsDeprecated } from '@/lib/types'

const inputClass =
  'mt-2 w-full rounded-xl border border-[#d7e0ea] bg-white px-3 py-2.5 font-normal outline-none focus:ring-2 focus:ring-[#2d8d78] transition-all duration-200'
const labelClass = 'text-sm font-semibold text-[#36516d]'

/* ─── Cipher suites per TLS version ─────────────────────────────────────── */
const CIPHERS_TLS12: CipherSuite[] = [
  'ECDHE-RSA-AES256-GCM-SHA384',
  'ECDHE-RSA-AES128-GCM-SHA256',
  'ECDHE-ECDSA-AES256-GCM-SHA384',
  'ECDHE-ECDSA-AES128-GCM-SHA256',
  'AES256-SHA',
  'AES128-SHA',
  'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
]

const CIPHERS_TLS13: CipherSuite[] = [
  'TLS_AES_256_GCM_SHA384',
  'TLS_AES_128_GCM_SHA256',
  'TLS_CHACHA20_POLY1305_SHA256',
]

function defaultCipher(ver: TlsVersion): CipherSuite {
  return ver === 'TLS1.3' ? 'TLS_AES_256_GCM_SHA384' : 'ECDHE-RSA-AES256-GCM-SHA384'
}

/* ─── Preset scenarios ───────────────────────────────────────────────────── */
type PresetKey = TestScenario

interface Preset {
  label: string
  description: string
  tlsVersion: TlsVersion
  cipherSuite: CipherSuite
  keyExchange: KeyExchangeMechanism
  namedGroup: NamedGroup
  tlsMode: string
  starttlsRequired: boolean
  certificateProfile: string
  certKeyAlgorithm: CertKeyAlgorithm
  certKeyLength: string
  certSignatureAlgorithm: SignatureAlgorithm
}

const PRESETS: Record<PresetKey, Preset> = {
  secure: {
    label: '✅ Secure Configuration',
    description: 'TLS 1.3 + strong cipher + PFS + valid cert',
    tlsVersion: 'TLS1.3',
    cipherSuite: 'TLS_AES_256_GCM_SHA384',
    keyExchange: 'ECDHE',
    namedGroup: 'X25519',
    tlsMode: 'STARTTLS',
    starttlsRequired: true,
    certificateProfile: 'valid',
    certKeyAlgorithm: 'RSA',
    certKeyLength: '2048',
    certSignatureAlgorithm: 'SHA256withRSA',
  },
  legacy_tls: {
    label: '⚠️ Legacy TLS',
    description: 'TLS 1.0 — deprecated protocol',
    tlsVersion: 'TLS1.0',
    cipherSuite: 'ECDHE-RSA-AES128-GCM-SHA256',
    keyExchange: 'ECDHE',
    namedGroup: 'secp256r1',
    tlsMode: 'STARTTLS',
    starttlsRequired: false,
    certificateProfile: 'valid',
    certKeyAlgorithm: 'RSA',
    certKeyLength: '2048',
    certSignatureAlgorithm: 'SHA256withRSA',
  },
  weak_cipher: {
    label: '⚠️ Weak Cipher',
    description: 'TLS 1.2 + 3DES/weak cipher',
    tlsVersion: 'TLS1.2',
    cipherSuite: 'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
    keyExchange: 'RSA',
    namedGroup: 'secp256r1',
    tlsMode: 'STARTTLS',
    starttlsRequired: false,
    certificateProfile: 'valid',
    certKeyAlgorithm: 'RSA',
    certKeyLength: '2048',
    certSignatureAlgorithm: 'SHA256withRSA',
  },
  expired_cert: {
    label: '❌ Expired Certificate',
    description: 'Valid TLS but expired cert',
    tlsVersion: 'TLS1.2',
    cipherSuite: 'ECDHE-RSA-AES256-GCM-SHA384',
    keyExchange: 'ECDHE',
    namedGroup: 'X25519',
    tlsMode: 'STARTTLS',
    starttlsRequired: true,
    certificateProfile: 'expired',
    certKeyAlgorithm: 'RSA',
    certKeyLength: '2048',
    certSignatureAlgorithm: 'SHA256withRSA',
  },
  invalid_chain: {
    label: '❌ Invalid Certificate Chain',
    description: 'TLS 1.2 + broken cert chain',
    tlsVersion: 'TLS1.2',
    cipherSuite: 'ECDHE-RSA-AES256-GCM-SHA384',
    keyExchange: 'ECDHE',
    namedGroup: 'secp256r1',
    tlsMode: 'STARTTLS',
    starttlsRequired: false,
    certificateProfile: 'invalid_chain',
    certKeyAlgorithm: 'RSA',
    certKeyLength: '2048',
    certSignatureAlgorithm: 'SHA256withRSA',
  },
  no_pfs: {
    label: '⚠️ No Forward Secrecy',
    description: 'Static RSA key exchange — no PFS',
    tlsVersion: 'TLS1.2',
    cipherSuite: 'AES256-SHA',
    keyExchange: 'RSA',
    namedGroup: 'secp256r1',
    tlsMode: 'STARTTLS',
    starttlsRequired: false,
    certificateProfile: 'valid',
    certKeyAlgorithm: 'RSA',
    certKeyLength: '2048',
    certSignatureAlgorithm: 'SHA256withRSA',
  },
  starttls_issue: {
    label: '⚠️ STARTTLS Issue',
    description: 'STARTTLS advertised but not required',
    tlsVersion: 'TLS1.2',
    cipherSuite: 'ECDHE-RSA-AES256-GCM-SHA384',
    keyExchange: 'ECDHE',
    namedGroup: 'X25519',
    tlsMode: 'STARTTLS',
    starttlsRequired: false,
    certificateProfile: 'valid',
    certKeyAlgorithm: 'RSA',
    certKeyLength: '2048',
    certSignatureAlgorithm: 'SHA256withRSA',
  },
  custom: {
    label: '🔧 Custom Configuration',
    description: 'Manually configure all parameters',
    tlsVersion: 'TLS1.3',
    cipherSuite: 'TLS_AES_256_GCM_SHA384',
    keyExchange: 'ECDHE',
    namedGroup: 'X25519',
    tlsMode: 'STARTTLS',
    starttlsRequired: true,
    certificateProfile: 'valid',
    certKeyAlgorithm: 'RSA',
    certKeyLength: '2048',
    certSignatureAlgorithm: 'SHA256withRSA',
  },
}

/* ─── Realistic log lines ────────────────────────────────────────────────── */
function generateLogLines(
  runId: string,
  config: {
    protocol: string
    server: string
    port: string
    tlsMode: string
    tlsVersion: string
    cipherSuite: string
    keyExchange: string
    namedGroup: string
    certificateProfile: string
    authentication: string
    recipient: string
    forwardSecrecy: boolean
  },
) {
  const pfsLabel = config.forwardSecrecy ? 'Enabled (ECDHE)' : 'Disabled (RSA static)'
  return [
    `======================================`,
    ` Running experiment: ${runId}`,
    ` Protocol: ${config.protocol}  |  TLS: ${config.tlsMode} (${config.tlsVersion})`,
    `======================================`,
    `[1] Initializing mail lab environment`,
    `    Mail server: ${config.server}:${config.port}`,
    `    TLS mode: ${config.tlsMode}  |  Version: ${config.tlsVersion}`,
    `    Cipher: ${config.cipherSuite}`,
    `    Key exchange: ${config.keyExchange} / ${config.namedGroup}  |  PFS: ${pfsLabel}`,
    `    Certificate: ${config.certificateProfile}  |  Auth: ${config.authentication}`,
    ``,
    `[2] Recreating containers`,
    `#1 [internal] load local bake definitions`,
    `#1 reading from stdin 1.01kB done`,
    `#1 DONE 0.0s`,
    ``,
    `#2 [mail-client internal] load build definition from Dockerfile`,
    `#2 transferring dockerfile: 758B done`,
    `#2 DONE 0.0s`,
    ``,
    `#3 [mail-server internal] load metadata for docker.io/library/debian:trixie-slim`,
    `#3 DONE 0.0s`,
    ``,
    `#5 [mail-server] apt-get install postfix dovecot-imapd openssl tcpdump`,
    `#5 CACHED`,
    ``,
    `#8 [mail-server] exporting to image`,
    `#8 naming to docker.io/library/mail-lab-server:latest done`,
    `#8 DONE 0.1s`,
    ``,
    ` Container mail-server  Creating`,
    ` Container mail-client  Creating`,
    ` Container mail-server  Started`,
    ` Container mail-client  Started`,
    ``,
    `[3] Waiting for containers`,
    `    mail-server: healthy`,
    `    mail-client: healthy`,
    ``,
    `[4] Configuring network endpoints`,
    `    Client: 172.30.0.2/24`,
    `    Server: 172.30.0.3/24`,
    ``,
    `[5] Configuring ${config.tlsMode} (${config.tlsVersion})`,
    `    Cipher suite: ${config.cipherSuite}`,
    `    Key exchange: ${config.keyExchange} / Named group: ${config.namedGroup}`,
    `    Forward Secrecy: ${pfsLabel}`,
    `    Loading certificate profile: ${config.certificateProfile}`,
    `    Certificate CN=${config.server} generated`,
    `    TLS handshake parameters configured`,
    ``,
    `[6] Starting packet capture on port ${config.port}`,
    `    tcpdump: listening on eth0, capture size 262144 bytes`,
    ``,
    `[7] Initiating ${config.protocol} session`,
    `[SMTP] Connecting to ${config.server}:${config.port}`,
    `[SMTP] 220 ${config.server} ESMTP Postfix`,
    `[SMTP] EHLO client.lab.local`,
    `[SMTP] 250-${config.server}`,
    config.tlsMode !== 'None' ? `[SMTP] 250-STARTTLS` : ``,
    `[SMTP] 250-AUTH LOGIN PLAIN`,
    `[SMTP] 250 OK`,
    config.tlsMode !== 'None' ? `[TLS] Starting ${config.tlsMode} negotiation` : `[SMTP] Proceeding without TLS`,
    config.tlsMode !== 'None' ? `[TLS] ${config.tlsVersion} handshake initiated` : ``,
    config.tlsMode !== 'None' ? `[TLS] Cipher suite negotiated: ${config.cipherSuite}` : ``,
    config.tlsMode !== 'None' ? `[TLS] Key exchange: ${config.keyExchange} / ${config.namedGroup}` : ``,
    config.tlsMode !== 'None' ? `[TLS] Forward secrecy: ${pfsLabel}` : ``,
    config.tlsMode !== 'None' ? `[TLS] Session established successfully` : ``,
    config.authentication === 'Enabled' ? `[AUTH] Authenticating with PLAIN mechanism` : `[AUTH] Skipping authentication (disabled)`,
    config.authentication === 'Enabled' ? `[AUTH] 235 Authentication successful` : ``,
    `[SMTP] MAIL FROM:<sender@lab.local>`,
    `[SMTP] 250 OK`,
    `[SMTP] RCPT TO:<${config.recipient || 'reviewer@lab.local'}>`,
    `[SMTP] 250 OK`,
    `[SMTP] DATA`,
    `[SMTP] 354 End data with <CR><LF>.<CR><LF>`,
    `[SMTP] Sending message headers...`,
    `[SMTP] Sending message body...`,
    `[SMTP] 250 OK: queued as ${runId.toUpperCase()}`,
    `[SMTP] QUIT`,
    `[SMTP] 221 Bye`,
    ``,
    `[8] Stopping packet capture`,
    `    Writing PCAPNG with encrypted configuration manifest...`,
    `    SecureMailScope custom block embedded (AES-256-GCM)`,
    ``,
    `[9] Running analysis pipeline`,
    `    Parsing PCAPNG blocks...`,
    `    Decrypting configuration manifest...`,
    `    Configuration hash verified ✓`,
    `    Comparing configured vs observed values...`,
    ``,
    `[10] Saving capture`,
    `    ${runId}.pcapng: real PCAPNG with embedded config`,
    ``,
    `======================================`,
    ` Experiment completed`,
    ` Dataset: dataset/runs/${runId}`,
    ` Capture format: PCAPNG (with SecureMailScope metadata)`,
    `======================================`,
  ].filter(Boolean)
}

export default function LabPage() {
  /* ─── configuration state ──────────────────────────── */
  const [configured, setConfigured] = useState(false)
  const [savedConfigJson, setSavedConfigJson] = useState<string | null>(null)
  const [configCopied, setConfigCopied] = useState(false)
  const [configCollapsed, setConfigCollapsed] = useState(false)

  /* ─── form fields — email ─────────────────────────── */
  const [server, setServer] = useState('smtp.lab.local')
  const [protocol, setProtocol] = useState<EmailProtocol>('SMTP')
  const [port, setPort] = useState('587')
  const [tlsMode, setTlsMode] = useState('STARTTLS')
  const [starttlsRequired, setStarttlsRequired] = useState(true)

  /* ─── form fields — TLS ────────────────────────────── */
  const [tlsVersion, setTlsVersion] = useState<TlsVersion>('TLS1.3')
  const [cipherSuite, setCipherSuite] = useState<CipherSuite>('TLS_AES_256_GCM_SHA384')
  const [keyExchange, setKeyExchange] = useState<KeyExchangeMechanism>('ECDHE')
  const [namedGroup, setNamedGroup] = useState<NamedGroup>('X25519')

  /* ─── form fields — certificate ────────────────────── */
  const [certificateProfile, setCertificateProfile] = useState('valid')
  const [certKeyAlgorithm, setCertKeyAlgorithm] = useState<CertKeyAlgorithm>('RSA')
  const [certKeyLength, setCertKeyLength] = useState('2048')
  const [certSignatureAlgorithm, setCertSignatureAlgorithm] =
    useState<SignatureAlgorithm>('SHA256withRSA')

  /* ─── form fields — misc ────────────────────────────── */
  const [testScenario, setTestScenario] = useState<TestScenario>('secure')
  const [authentication, setAuthentication] = useState('Enabled')
  const [recipient, setRecipient] = useState('reviewer@lab.local')
  const [subject, setSubject] = useState('Quarterly evidence review')
  const [draft, setDraft] = useState(
    'Please review the attached evidence bundle from the controlled email lab.',
  )
  const [attachments, setAttachments] = useState<FileList | null>(null)

  /* ─── log / traffic state ──────────────────────────── */
  const [sent, setSent] = useState(false)
  const [generating, setGenerating] = useState(false)
  const [logLines, setLogLines] = useState<string[]>([])
  const [runId, setRunId] = useState('')
  const [sessionId, setSessionId] = useState('')
  const [responseJson, setResponseJson] = useState<string | null>(null)
  const [logCollapsed, setLogCollapsed] = useState(false)
  const logBoxRef = useRef<HTMLPreElement>(null)

  /* ─── derived values ────────────────────────────────── */
  const forwardSecrecy = useMemo(
    () => deriveForwardSecrecy(keyExchange, tlsVersion),
    [keyExchange, tlsVersion],
  )

  const tlsDeprecated = isTlsDeprecated(tlsVersion)

  /* ─── helpers ──────────────────────────────────────── */
  const attachmentSize = useMemo(
    () => Array.from(attachments ?? []).reduce((total, file) => total + file.size, 0),
    [attachments],
  )
  const pcapCount = Math.max(1, Math.ceil(attachmentSize / (5 * 1024 * 1024)))
  const formatBytes = (bytes: number) =>
    bytes < 1024 * 1024
      ? `${Math.max(1, Math.round(bytes / 1024))} KB`
      : `${(bytes / (1024 * 1024)).toFixed(1)} MB`

  /* ─── preset loader ─────────────────────────────────── */
  function applyPreset(key: TestScenario) {
    const preset = PRESETS[key]
    setTestScenario(key)
    setTlsVersion(preset.tlsVersion)
    setCipherSuite(preset.cipherSuite)
    setKeyExchange(preset.keyExchange)
    setNamedGroup(preset.namedGroup)
    setTlsMode(preset.tlsMode)
    setStarttlsRequired(preset.starttlsRequired)
    setCertificateProfile(preset.certificateProfile)
    setCertKeyAlgorithm(preset.certKeyAlgorithm)
    setCertKeyLength(preset.certKeyLength)
    setCertSignatureAlgorithm(preset.certSignatureAlgorithm)
  }

  /* ─── TLS version change — update cipher ────────────── */
  function handleTlsVersionChange(v: TlsVersion) {
    setTlsVersion(v)
    setCipherSuite(defaultCipher(v))
  }

  /* ─── protocol change — update default port ──────────── */
  function handleProtocolChange(p: EmailProtocol) {
    setProtocol(p)
    const defaults: Record<EmailProtocol, string> = {
      SMTP: '587',
      IMAP: '993',
      POP3: '995',
    }
    setPort(defaults[p])
  }

  /* ─── copy JSON to clipboard ────────────────────────── */
  const copyJson = useCallback((text: string) => {
    navigator.clipboard.writeText(text)
    setConfigCopied(true)
    setTimeout(() => setConfigCopied(false), 2000)
  }, [])

  /* ─── save lab configuration ───────────────────────── */
  function createLab(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const configData = {
      ok: true,
      timestamp: new Date().toISOString(),
      config: {
        protocol,
        server,
        port: Number(port),
        tlsMode,
        starttlsRequired,
        tlsVersion,
        cipherSuite,
        keyExchange,
        namedGroup,
        forwardSecrecy,
        certificateProfile,
        certKeyAlgorithm,
        certKeyLength,
        certSignatureAlgorithm,
        authentication,
        testScenario,
      },
      capture_policy: {
        format: 'PCAPNG',
        capture_tls_handshakes: true,
        capture_message_parts: true,
        embed_encrypted_config: true,
        config_encryption: 'AES-256-GCM',
      },
    }
    setSavedConfigJson(JSON.stringify(configData, null, 2))
    setConfigured(true)
    setConfigCollapsed(false)
  }

  /* ─── simulate streaming log output ─────────────────── */
  async function sendEmail(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!configured) return

    const currentRunId = `run_${String(Math.floor(Math.random() * 900) + 100).padStart(3, '0')}`
    setRunId(currentRunId)
    setGenerating(true)
    setLogLines([])
    setSent(false)
    setResponseJson(null)
    setLogCollapsed(false)

    const configForLog = {
      protocol,
      server,
      port,
      tlsMode,
      tlsVersion,
      cipherSuite,
      keyExchange,
      namedGroup,
      certificateProfile,
      authentication,
      recipient,
      forwardSecrecy,
    }
    const allLines = generateLogLines(currentRunId, configForLog)

    // Stream logs line by line with realistic delay
    for (let i = 0; i < allLines.length; i++) {
      const line = allLines[i]
      await new Promise((resolve) => setTimeout(resolve, Math.random() * 80 + 20))
      setLogLines((prev) => [...prev, line])
      requestAnimationFrame(() => {
        if (logBoxRef.current) {
          logBoxRef.current.scrollTop = logBoxRef.current.scrollHeight
        }
      })
    }

    // Now fire the actual API call
    try {
      const response = await fetch('/api/lab-sessions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          recipient,
          subject,
          draft,
          protocol,
          server,
          port,
          tlsMode,
          starttls: tlsMode !== 'None',
          starttlsRequired,
          tlsVersion,
          cipherSuite,
          keyExchange,
          namedGroup,
          certificateProfile,
          certKeyAlgorithm,
          certKeyLength: Number(certKeyLength),
          certSignatureAlgorithm,
          testScenario,
          authentication,
          files: Array.from(attachments ?? []).map((file) => ({
            name: file.name,
            size: file.size,
          })),
        }),
      })

      if (response.ok) {
        const session = await response.json()
        setSessionId(session.id)
        if (session.analysis) {
          saveAnalysisSession(session.analysis)
        }


        const fullResponse = {
          ok: true,
          run_id: currentRunId,
          session_id: session.id,
          capture_format: 'PCAPNG',
          capture_file: session.files?.[0]?.originalName,
          config_embedding: 'AES-256-GCM encrypted manifest in Custom Block',
          config: {
            protocol,
            server,
            port: Number(port),
            tls_mode: tlsMode,
            tls_version: tlsVersion,
            cipher_suite: cipherSuite,
            key_exchange: keyExchange,
            named_group: namedGroup,
            forward_secrecy: forwardSecrecy,
            certificate_profile: certificateProfile,
            authentication,
          },
          analysis_available: Boolean(session.analysis),
          security_score: session.analysis?.securityScore?.total,
          download_url: `/api/lab-sessions/download?session=${session.id}`,
        }
        setResponseJson(JSON.stringify(fullResponse, null, 2))
        setSent(true)
        window.history.replaceState(
          null,
          '',
          `/lab?session=${encodeURIComponent(session.id)}`,
        )
      }
    } catch {
      setLogLines((prev) => [...prev, '', '[ERROR] Failed to connect to API endpoint'])
    } finally {
      setGenerating(false)
    }
  }

  /* ─── download real PCAPNG from server ──────────────── */
  async function downloadPcapng() {
    if (!sessionId) return
    const a = document.createElement('a')
    a.href = `/api/lab-sessions/download?session=${encodeURIComponent(sessionId)}`
    a.download = `${runId}.pcapng`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
  }

  const availableCiphers = tlsVersion === 'TLS1.3' ? CIPHERS_TLS13 : CIPHERS_TLS12

  return (
    <AppShell>
      <PageHeader
        eyebrow="Controlled environment"
        title="Email traffic lab"
        description="Configure the lab, compose an email with attachments, then generate PCAPNG captures with encrypted configuration metadata for reconstruction."
        action={
          <StatusBadge tone={configured ? 'success' : 'neutral'}>
            {configured ? 'Configuration saved' : 'Needs configuration'}
          </StatusBadge>
        }
      />

      <div className="grid gap-6 xl:grid-cols-[1.08fr_0.92fr]">
        {/* ─── LEFT COLUMN: Lab Configuration ───────────── */}
        <section className="rounded-2xl border border-[#e5eaf1] bg-white p-6">
          <div className="flex items-start gap-3">
            <div className="flex size-10 items-center justify-center rounded-xl bg-[#eaf1f9] text-[#173b64]">
              <Server className="size-5" />
            </div>
            <div>
              <h2 className="font-bold text-[#182230]">Lab configuration</h2>
              <p className="mt-1 text-sm text-[#718096]">
                Set the exact email and TLS scenario to simulate.
              </p>
            </div>
          </div>

          <form onSubmit={createLab} className="mt-7 flex flex-col gap-5">

            {/* ── Security Test Scenario Presets ────────────── */}
            <div>
              <div className="flex items-center gap-2 mb-3">
                <Zap className="size-4 text-[#2d8d78]" />
                <span className="text-sm font-semibold text-[#36516d]">Test scenario preset</span>
              </div>
              <div className="grid gap-2 sm:grid-cols-2">
                {(Object.keys(PRESETS) as TestScenario[]).map((key) => (
                  <button
                    key={key}
                    type="button"
                    onClick={() => applyPreset(key)}
                    className={`rounded-xl border px-3 py-2.5 text-left text-xs transition-all duration-200 ${
                      testScenario === key
                        ? 'border-[#2d8d78] bg-[#f0faf6] text-[#247c6b] font-semibold'
                        : 'border-[#e5eaf1] text-[#607087] hover:border-[#b9d8d0] hover:bg-[#f7fbff]'
                    }`}
                  >
                    <div className="font-semibold">{PRESETS[key].label}</div>
                    <div className="text-[10px] opacity-75 mt-0.5">{PRESETS[key].description}</div>
                  </button>
                ))}
              </div>
            </div>

            <hr className="border-[#edf0f5]" />

            {/* ── A. Email Protocol ─────────────────────────── */}
            <div className="rounded-xl bg-[#f7f9fc] p-4">
              <p className="mb-3 text-xs font-bold uppercase tracking-[0.14em] text-[#9aa6b5]">A · Email Protocol</p>
              <div className="grid gap-4 sm:grid-cols-3">
                <label className={labelClass}>
                  Protocol
                  <select
                    value={protocol}
                    onChange={(e) => handleProtocolChange(e.target.value as EmailProtocol)}
                    className={inputClass}
                  >
                    <option value="SMTP">SMTP</option>
                    <option value="IMAP">IMAP</option>
                    <option value="POP3">POP3</option>
                  </select>
                </label>
                <label className={labelClass}>
                  Port
                  <select
                    value={port}
                    onChange={(e) => setPort(e.target.value)}
                    className={inputClass}
                  >
                    {protocol === 'SMTP' && (
                      <>
                        <option value="587">587 (SUBMISSION)</option>
                        <option value="465">465 (SMTPS)</option>
                        <option value="25">25 (SMTP)</option>
                      </>
                    )}
                    {protocol === 'IMAP' && (
                      <>
                        <option value="993">993 (IMAPS)</option>
                        <option value="143">143 (IMAP)</option>
                      </>
                    )}
                    {protocol === 'POP3' && (
                      <>
                        <option value="995">995 (POP3S)</option>
                        <option value="110">110 (POP3)</option>
                      </>
                    )}
                  </select>
                </label>
                <label className={labelClass}>
                  Mail server
                  <input
                    value={server}
                    onChange={(e) => setServer(e.target.value)}
                    className={inputClass}
                  />
                </label>
              </div>
            </div>

            {/* ── B. STARTTLS ───────────────────────────────── */}
            <div className="rounded-xl bg-[#f7f9fc] p-4">
              <p className="mb-3 text-xs font-bold uppercase tracking-[0.14em] text-[#9aa6b5]">B · STARTTLS</p>
              <div className="grid gap-4 sm:grid-cols-2">
                <label className={labelClass}>
                  TLS mode
                  <select
                    value={tlsMode}
                    onChange={(e) => setTlsMode(e.target.value)}
                    className={inputClass}
                  >
                    <option value="STARTTLS">STARTTLS</option>
                    <option value="Direct TLS">Direct TLS</option>
                    <option value="None">None (plaintext)</option>
                  </select>
                </label>
                {tlsMode === 'STARTTLS' && (
                  <label className={labelClass}>
                    STARTTLS policy
                    <select
                      value={starttlsRequired ? 'required' : 'optional'}
                      onChange={(e) => setStarttlsRequired(e.target.value === 'required')}
                      className={inputClass}
                    >
                      <option value="required">Required (must upgrade)</option>
                      <option value="optional">Optional (not enforced)</option>
                    </select>
                  </label>
                )}
              </div>
            </div>

            {/* ── C. TLS Version ────────────────────────────── */}
            <div className="rounded-xl bg-[#f7f9fc] p-4">
              <p className="mb-3 text-xs font-bold uppercase tracking-[0.14em] text-[#9aa6b5]">C · TLS Version</p>
              <div className="grid gap-3 sm:grid-cols-4">
                {(['TLS1.0', 'TLS1.1', 'TLS1.2', 'TLS1.3'] as TlsVersion[]).map((v) => {
                  const deprecated = isTlsDeprecated(v)
                  return (
                    <button
                      key={v}
                      type="button"
                      onClick={() => handleTlsVersionChange(v)}
                      className={`rounded-xl border px-3 py-3 text-xs text-left transition-all ${
                        tlsVersion === v
                          ? deprecated
                            ? 'border-[#f87171] bg-[#fff5f5] text-[#b91c1c] font-semibold'
                            : 'border-[#2d8d78] bg-[#f0faf6] text-[#247c6b] font-semibold'
                          : 'border-[#e5eaf1] text-[#607087] hover:border-[#b9c9d9]'
                      }`}
                    >
                      <div className="font-semibold">TLS {v.replace('TLS', '')}</div>
                      <div className={`text-[10px] mt-0.5 ${deprecated ? 'text-[#f87171]' : 'text-[#9aa6b5]'}`}>
                        {deprecated ? '⚠ Deprecated' : '✓ Modern'}
                      </div>
                    </button>
                  )
                })}
              </div>
              {tlsDeprecated && (
                <div className="mt-3 flex items-start gap-2 rounded-xl bg-[#fff5f5] border border-[#f87171]/30 px-3 py-2.5">
                  <AlertTriangle className="size-4 text-[#ef4444] mt-0.5 shrink-0" />
                  <p className="text-xs text-[#b91c1c]">
                    <strong>{tlsVersion.replace('TLS', 'TLS ')} is deprecated</strong> (RFC 8996). Allowed for security-testing purposes only.
                  </p>
                </div>
              )}
            </div>

            {/* ── D. Cipher Suite ───────────────────────────── */}
            {tlsMode !== 'None' && (
              <div className="rounded-xl bg-[#f7f9fc] p-4">
                <p className="mb-3 text-xs font-bold uppercase tracking-[0.14em] text-[#9aa6b5]">D · Cipher Suite</p>
                <label className={labelClass}>
                  Cipher suite ({tlsVersion === 'TLS1.3' ? 'TLS 1.3' : 'TLS 1.2'})
                  <select
                    value={cipherSuite}
                    onChange={(e) => setCipherSuite(e.target.value as CipherSuite)}
                    className={inputClass}
                  >
                    {availableCiphers.map((cs) => (
                      <option key={cs} value={cs}>
                        {cs}
                      </option>
                    ))}
                  </select>
                </label>
              </div>
            )}

            {/* ── E + F. Key Exchange + PFS ─────────────────── */}
            {tlsMode !== 'None' && tlsVersion !== 'TLS1.3' && (
              <div className="rounded-xl bg-[#f7f9fc] p-4">
                <p className="mb-3 text-xs font-bold uppercase tracking-[0.14em] text-[#9aa6b5]">E · Key Exchange & PFS</p>
                <div className="grid gap-4 sm:grid-cols-2">
                  <label className={labelClass}>
                    Key exchange mechanism
                    <select
                      value={keyExchange}
                      onChange={(e) => setKeyExchange(e.target.value as KeyExchangeMechanism)}
                      className={inputClass}
                    >
                      <option value="ECDHE">ECDHE</option>
                      <option value="DHE">DHE</option>
                      <option value="RSA">RSA (no PFS)</option>
                      <option value="X25519">X25519</option>
                      <option value="X448">X448</option>
                    </select>
                  </label>
                  <label className={labelClass}>
                    Named group / curve
                    <select
                      value={namedGroup}
                      onChange={(e) => setNamedGroup(e.target.value as NamedGroup)}
                      className={inputClass}
                    >
                      <option value="X25519">X25519</option>
                      <option value="X448">X448</option>
                      <option value="secp256r1">secp256r1 (P-256)</option>
                      <option value="secp384r1">secp384r1 (P-384)</option>
                      <option value="secp521r1">secp521r1 (P-521)</option>
                    </select>
                  </label>
                </div>
                <div className={`mt-3 flex items-center gap-2 rounded-xl px-3 py-2.5 text-xs ${forwardSecrecy ? 'bg-[#f0faf6] text-[#247c6b]' : 'bg-[#fff5f5] text-[#b91c1c]'}`}>
                  {forwardSecrecy ? <CheckCircle2 className="size-4" /> : <AlertTriangle className="size-4" />}
                  <span>
                    <strong>Perfect Forward Secrecy: {forwardSecrecy ? 'Enabled' : 'Disabled'}</strong>
                    {' '}— derived from key exchange ({keyExchange})
                  </span>
                </div>
              </div>
            )}
            {tlsVersion === 'TLS1.3' && (
              <div className="flex items-center gap-2 rounded-xl bg-[#f0faf6] border border-[#cfe9df] px-3 py-2.5 text-xs text-[#247c6b]">
                <CheckCircle2 className="size-4 shrink-0" />
                <span><strong>TLS 1.3:</strong> Ephemeral key exchange (PFS) is inherent — always enabled.</span>
              </div>
            )}

            {/* ── G. Certificate ────────────────────────────── */}
            <div className="rounded-xl bg-[#f7f9fc] p-4">
              <p className="mb-3 text-xs font-bold uppercase tracking-[0.14em] text-[#9aa6b5]">G · Certificate</p>
              <div className="grid gap-4 sm:grid-cols-2">
                <label className={labelClass}>
                  Certificate scenario
                  <select
                    value={certificateProfile}
                    onChange={(e) => setCertificateProfile(e.target.value)}
                    className={inputClass}
                  >
                    <option value="valid">✅ Valid certificate</option>
                    <option value="expired">❌ Expired certificate</option>
                    <option value="not_yet_valid">❌ Not yet valid</option>
                    <option value="self_signed">⚠️ Self-signed</option>
                    <option value="invalid_chain">❌ Invalid chain</option>
                    <option value="weak_key">⚠️ Weak public key (RSA 1024)</option>
                    <option value="weak_signature">⚠️ Weak signature (SHA1)</option>
                  </select>
                </label>
                <label className={labelClass}>
                  Public key algorithm
                  <select
                    value={certKeyAlgorithm}
                    onChange={(e) => setCertKeyAlgorithm(e.target.value as CertKeyAlgorithm)}
                    className={inputClass}
                  >
                    <option value="RSA">RSA</option>
                    <option value="ECDSA">ECDSA</option>
                    <option value="Ed25519">Ed25519</option>
                  </select>
                </label>
                <label className={labelClass}>
                  Key length / curve
                  <select
                    value={certKeyLength}
                    onChange={(e) => setCertKeyLength(e.target.value)}
                    className={inputClass}
                  >
                    {certKeyAlgorithm === 'RSA' ? (
                      <>
                        <option value="1024">RSA 1024 (⚠️ Weak)</option>
                        <option value="2048">RSA 2048</option>
                        <option value="3072">RSA 3072</option>
                        <option value="4096">RSA 4096</option>
                      </>
                    ) : certKeyAlgorithm === 'ECDSA' ? (
                      <>
                        <option value="256">P-256 (secp256r1)</option>
                        <option value="384">P-384 (secp384r1)</option>
                        <option value="521">P-521 (secp521r1)</option>
                      </>
                    ) : (
                      <option value="256">255 (Curve25519)</option>
                    )}
                  </select>
                </label>
                <label className={labelClass}>
                  Signature algorithm
                  <select
                    value={certSignatureAlgorithm}
                    onChange={(e) => setCertSignatureAlgorithm(e.target.value as SignatureAlgorithm)}
                    className={inputClass}
                  >
                    <option value="SHA256withRSA">SHA256withRSA</option>
                    <option value="SHA384withRSA">SHA384withRSA</option>
                    <option value="SHA512withRSA">SHA512withRSA</option>
                    <option value="SHA1withRSA">SHA1withRSA (⚠️ Weak)</option>
                    <option value="SHA256withECDSA">SHA256withECDSA</option>
                    <option value="SHA384withECDSA">SHA384withECDSA</option>
                    <option value="Ed25519">Ed25519</option>
                  </select>
                </label>
              </div>
            </div>

            {/* ── Authentication ────────────────────────────── */}
            <div className="grid gap-5 sm:grid-cols-2">
              <label className={labelClass}>
                Authentication
                <select
                  value={authentication}
                  onChange={(e) => setAuthentication(e.target.value)}
                  className={inputClass}
                >
                  <option>Enabled</option>
                  <option>Disabled</option>
                </select>
              </label>
            </div>

            <div className="rounded-xl bg-[#f7f9fc] p-4 text-sm text-[#607087]">
              <div className="flex items-center gap-2 font-semibold text-[#36516d]">
                <SlidersHorizontal className="size-4" />
                Capture policy
              </div>
              <p className="mt-2 leading-6">
                Generates a real <strong>PCAPNG</strong> file with simulated SMTP/TLS traffic.
                Configuration is encrypted (AES-256-GCM) and embedded in a Custom Block.
                Label: <em>Simulated Testbed</em>.
              </p>
            </div>

            <button
              type="submit"
              className="inline-flex items-center justify-center gap-2 rounded-xl bg-[#173b64] px-4 py-3 text-sm font-semibold text-white transition-all duration-200 hover:bg-[#214d7d] hover:shadow-lg active:scale-[0.98]"
            >
              <Server className="size-4" />
              {configured ? 'Update configuration' : 'Save configuration'}
            </button>
          </form>

          {/* ── JSON Config Preview Box ──────────────────── */}
          {savedConfigJson && (
            <div className="mt-6 animate-[fadeSlideIn_0.3s_ease-out]">
              <div className="flex items-center justify-between rounded-t-xl border border-b-0 border-[#d7e0ea] bg-gradient-to-r from-[#173b64] to-[#214d7d] px-4 py-2.5">
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="size-4 text-[#4ade80]" />
                  <span className="text-sm font-semibold text-white">
                    Saved Configuration (JSON)
                  </span>
                </div>
                <div className="flex items-center gap-1">
                  <button
                    onClick={() => copyJson(savedConfigJson)}
                    className="rounded-lg p-1.5 text-white/70 transition-colors hover:bg-white/10 hover:text-white"
                    title="Copy JSON"
                  >
                    {configCopied ? (
                      <CheckCircle2 className="size-4 text-[#4ade80]" />
                    ) : (
                      <Copy className="size-4" />
                    )}
                  </button>
                  <button
                    onClick={() => setConfigCollapsed(!configCollapsed)}
                    className="rounded-lg p-1.5 text-white/70 transition-colors hover:bg-white/10 hover:text-white"
                    title={configCollapsed ? 'Expand' : 'Collapse'}
                  >
                    {configCollapsed ? (
                      <ChevronDown className="size-4" />
                    ) : (
                      <ChevronUp className="size-4" />
                    )}
                  </button>
                </div>
              </div>
              <div
                className={`overflow-hidden transition-all duration-300 ${configCollapsed ? 'max-h-0' : 'max-h-[600px]'}`}
              >
                <pre className="overflow-auto rounded-b-xl border border-[#d7e0ea] bg-[#0d1b2a] p-4 font-mono text-xs leading-6 text-[#a3f7bf] selection:bg-[#2d8d78]/40">
                  {savedConfigJson}
                </pre>
              </div>
            </div>
          )}
        </section>

        {/* ─── RIGHT COLUMN: Compose Test Email ─────────── */}
        <section className="rounded-2xl border border-[#e5eaf1] bg-white p-6">
          <div className="flex items-start gap-3">
            <div className="flex size-10 items-center justify-center rounded-xl bg-[#e5f4ef] text-[#247c6b]">
              <Mail className="size-5" />
            </div>
            <div>
              <h2 className="font-bold text-[#182230]">Compose test email</h2>
              <p className="mt-1 text-sm text-[#718096]">
                The next stage begins after configuration is saved.
              </p>
            </div>
          </div>

          {!configured ? (
            <div className="mt-7 rounded-xl border border-[#dce9f5] bg-[#f7fbff] p-4 text-sm leading-6 text-[#607087]">
              <strong className="text-[#36516d]">Step 1 · Configure first</strong>
              <br />
              Save the email protocol, server, TLS, certificate, and authentication settings to
              unlock the draft composer.
            </div>
          ) : (
            <form onSubmit={sendEmail} className="mt-7 flex flex-col gap-4">
              <div className="rounded-xl border border-[#cfe9df] bg-[#f0faf6] p-3 text-xs text-[#247c6b]">
                <strong>Step 2 · Draft and capture</strong>
                <br />
                {protocol} via {server}:{port} · {tlsMode} · TLS {tlsVersion.replace('TLS', '')} ·{' '}
                {cipherSuite} · PFS: {forwardSecrecy ? 'Yes' : 'No'} · {certificateProfile} cert
              </div>

              <label className={labelClass}>
                Recipient
                <input
                  value={recipient}
                  onChange={(e) => setRecipient(e.target.value)}
                  className={inputClass}
                />
              </label>

              <label className={labelClass}>
                Subject
                <input
                  value={subject}
                  onChange={(e) => setSubject(e.target.value)}
                  className={inputClass}
                />
              </label>

              <label className={labelClass}>
                Draft message
                <textarea
                  value={draft}
                  onChange={(e) => setDraft(e.target.value)}
                  rows={4}
                  className={`${inputClass} resize-none`}
                />
              </label>

              <label className={labelClass}>
                Attachments
                <div className="mt-2 flex items-center gap-2 rounded-xl border border-dashed border-[#b9c9d9] bg-[#fbfcfe] px-3 py-3">
                  <Paperclip className="size-4 text-[#247c6b]" />
                  <input
                    type="file"
                    multiple
                    accept=".pdf,.doc,.docx,.jpg,.jpeg,.png,.mp4,.zip,.pcap"
                    onChange={(e) => setAttachments(e.target.files)}
                    className="min-w-0 text-xs font-normal text-[#607087]"
                  />
                </div>
              </label>

              {attachments && (
                <div className="rounded-xl bg-[#f7f9fc] p-3 text-xs text-[#607087]">
                  <strong className="text-[#36516d]">
                    {attachments.length} file(s) selected · {formatBytes(attachmentSize)}
                  </strong>
                  <div className="mt-2 flex flex-col gap-1">
                    {Array.from(attachments).map((file) => (
                      <span key={`${file.name}-${file.size}`}>
                        {file.name} · {formatBytes(file.size)}
                      </span>
                    ))}
                  </div>
                  <p className="mt-2 text-[#247c6b]">
                    Estimated capture output: {pcapCount} PCAPNG file
                    {pcapCount === 1 ? '' : 's'} (up to 5 MB per capture).
                  </p>
                </div>
              )}

              <button
                type="submit"
                disabled={generating}
                className="inline-flex items-center justify-center gap-2 rounded-xl bg-[#2d8d78] px-4 py-3 text-sm font-semibold text-white transition-all duration-200 hover:bg-[#247c6b] hover:shadow-lg active:scale-[0.98] disabled:opacity-60 disabled:cursor-not-allowed"
              >
                {generating ? (
                  <Loader2 className="size-4 animate-spin" />
                ) : (
                  <Mail className="size-4" />
                )}
                {generating ? 'Generating traffic…' : 'Generate email traffic'}
              </button>
            </form>
          )}

          {/* ── Log Output Box ───────────────────────────── */}
          {logLines.length > 0 && (
            <div className="mt-5 animate-[fadeSlideIn_0.3s_ease-out]">
              <div className="flex items-center justify-between rounded-t-xl border border-b-0 border-[#1a3a2a] bg-gradient-to-r from-[#0f2818] to-[#0d1b2a] px-4 py-2.5">
                <div className="flex items-center gap-2">
                  <Terminal className="size-4 text-[#4ade80]" />
                  <span className="text-sm font-semibold text-[#a3f7bf]">Capture Logs</span>
                  {generating && (
                    <span className="flex items-center gap-1.5 text-xs text-[#4ade80]/70">
                      <span className="size-1.5 animate-pulse rounded-full bg-[#4ade80]" />
                      streaming…
                    </span>
                  )}
                </div>
                <div className="flex items-center gap-1">
                  <span className="mr-2 rounded-md bg-[#1a3a2a] px-2 py-0.5 text-[10px] font-mono text-[#4ade80]/70">
                    {logLines.length} lines
                  </span>
                  <button
                    onClick={() => setLogCollapsed(!logCollapsed)}
                    className="rounded-lg p-1.5 text-[#4ade80]/50 transition-colors hover:bg-white/5 hover:text-[#4ade80]"
                    title={logCollapsed ? 'Expand' : 'Collapse'}
                  >
                    {logCollapsed ? (
                      <ChevronDown className="size-4" />
                    ) : (
                      <ChevronUp className="size-4" />
                    )}
                  </button>
                </div>
              </div>
              <div
                className={`overflow-hidden transition-all duration-300 ${logCollapsed ? 'max-h-0' : 'max-h-[500px]'}`}
              >
                <pre
                  ref={logBoxRef}
                  className="max-h-[400px] overflow-auto rounded-b-xl border border-[#1a3a2a] bg-[#0a0f14] p-4 font-mono text-[11px] leading-5 text-[#c8d6e5] selection:bg-[#2d8d78]/30"
                  style={{ scrollbarWidth: 'thin', scrollbarColor: '#1a3a2a #0a0f14' }}
                >
                  {logLines.map((line, i) => (
                    <div
                      key={i}
                      className={`${
                        line.startsWith('===')
                          ? 'text-[#fbbf24] font-semibold'
                          : line.startsWith('[')
                          ? line.includes('ERROR')
                            ? 'text-[#f87171]'
                            : line.match(/^\[\d+\]/)
                            ? 'text-[#60a5fa] font-medium'
                            : line.startsWith('[SMTP]')
                            ? 'text-[#a78bfa]'
                            : line.startsWith('[TLS]')
                            ? 'text-[#34d399]'
                            : line.startsWith('[AUTH]')
                            ? 'text-[#fbbf24]'
                            : 'text-[#c8d6e5]'
                          : line.startsWith('#')
                          ? 'text-[#6b7280]'
                          : line.startsWith(' Container') || line.startsWith(' Network')
                          ? 'text-[#94a3b8]'
                          : 'text-[#c8d6e5]'
                      }`}
                    >
                      {line || '\u00A0'}
                    </div>
                  ))}
                  {generating && (
                    <span className="inline-block h-4 w-1.5 animate-pulse bg-[#4ade80]" />
                  )}
                </pre>
              </div>
            </div>
          )}

          {/* ── Success + PCAPNG Download ──────────────────── */}
          {sent && (
            <div className="mt-5 animate-[fadeSlideIn_0.3s_ease-out]">
              <div className="rounded-xl border border-[#cfe9df] bg-[#f0faf6] p-4 text-sm text-[#247c6b]">
                <div className="flex items-center gap-2 font-semibold">
                  <CheckCircle2 className="size-4" />
                  Step 3 · PCAPNG capture ready
                </div>
                <p className="mt-2 leading-6">
                  Session <strong>{runId}</strong> generated a real <strong>PCAPNG</strong> file
                  with encrypted configuration metadata (AES-256-GCM) embedded in a Custom Block.
                  The configuration is cryptographically bound to the capture.
                </p>
                <p className="mt-1 text-xs opacity-75">
                  Label: Simulated Testbed — packet data represents realistic SMTP/TLS exchange
                  derived from your configuration.
                </p>

                <div className="mt-3 flex flex-wrap gap-2">
                  <button
                    onClick={downloadPcapng}
                    className="inline-flex items-center gap-2 rounded-lg bg-[#173b64] px-3.5 py-2 text-xs font-semibold text-white transition-all hover:bg-[#214d7d] hover:shadow-lg active:scale-[0.98]"
                  >
                    <Download className="size-3.5" />
                    Download {runId}.pcapng
                  </button>
                  <a
                    href={`/analysis?session=${sessionId}`}
                    className="inline-flex items-center gap-1 rounded-lg border border-[#cfe9df] px-3.5 py-2 text-xs font-bold text-[#247c6b] transition-all hover:bg-[#e5f4ef]"
                  >
                    <FileText className="size-3" />
                    Continue to Traffic Analysis
                  </a>
                </div>
              </div>

              {/* Response JSON box */}
              {responseJson && (
                <div className="mt-4">
                  <div className="flex items-center justify-between rounded-t-xl border border-b-0 border-[#d7e0ea] bg-gradient-to-r from-[#2d8d78] to-[#247c6b] px-4 py-2">
                    <span className="text-xs font-semibold text-white">API Response (JSON)</span>
                    <button
                      onClick={() => copyJson(responseJson)}
                      className="rounded-lg p-1 text-white/70 transition-colors hover:bg-white/10 hover:text-white"
                      title="Copy response JSON"
                    >
                      <Copy className="size-3.5" />
                    </button>
                  </div>
                  <pre className="max-h-[300px] overflow-auto rounded-b-xl border border-[#d7e0ea] bg-[#0d1b2a] p-4 font-mono text-xs leading-6 text-[#a3f7bf] selection:bg-[#2d8d78]/40">
                    {responseJson}
                  </pre>
                </div>
              )}
            </div>
          )}
        </section>
      </div>

      <div className="mt-6 flex items-center gap-2 text-xs text-[#8290a2]">
        <ShieldCheck className="size-4 text-[#2d8d78]" />
        No external messages are sent. This is a controlled forensic lab simulation (Simulated
        Testbed). Generated captures are PCAPNG format with encrypted configuration metadata.
      </div>
    </AppShell>
  )
}
