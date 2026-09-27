'use client'

import { FormEvent, useCallback, useMemo, useRef, useState } from 'react'
import {
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
} from 'lucide-react'
import { AppShell, PageHeader, StatusBadge } from '@/components/app-shell'

const inputClass =
  'mt-2 w-full rounded-xl border border-[#d7e0ea] bg-white px-3 py-2.5 font-normal outline-none focus:ring-2 focus:ring-[#2d8d78] transition-all duration-200'
const labelClass = 'text-sm font-semibold text-[#36516d]'

/* ─── realistic simulated log lines ────────────────────────── */
function generateLogLines(runId: string, config: Record<string, string>) {
  return [
    `======================================`,
    ` Running experiment: ${runId}`,
    ` Protocol: ${config.protocol}  |  TLS: ${config.tlsMode}`,
    `======================================`,
    `[1] Initializing mail lab environment`,
    `    Mail server: ${config.server}:${config.port}`,
    `    TLS mode: ${config.tlsMode}  |  Version: ${config.tlsVersion}`,
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
    `#4 [mail-server internal] load .dockerignore`,
    `#4 transferring context: 2B done`,
    `#4 DONE 0.0s`,
    ``,
    `#5 [mail-server 2/6] RUN apt-get update && apt-get install -y postfix dovecot-imapd openssl tcpdump curl procps net-tools && rm -rf /var/lib/apt/lists/*`,
    `#5 CACHED`,
    ``,
    `#6 [mail-server 5/6] COPY start.sh /start.sh`,
    `#6 CACHED`,
    ``,
    `#7 [mail-server 6/6] RUN chmod +x /start.sh`,
    `#7 CACHED`,
    ``,
    `#8 [mail-server] exporting to image`,
    `#8 exporting layers done`,
    `#8 naming to docker.io/library/mail-lab-server:latest done`,
    `#8 DONE 0.1s`,
    ``,
    `#9 [mail-client] exporting to image`,
    `#9 exporting layers done`,
    `#9 naming to docker.io/library/mail-lab-client:latest done`,
    `#9 DONE 0.1s`,
    ``,
    ` Container mail-server  Creating`,
    ` Container mail-client  Creating`,
    ` Container mail-server  Created`,
    ` Container mail-client  Created`,
    ` Container mail-client  Starting`,
    ` Container mail-server  Starting`,
    ` Container mail-client  Started`,
    ` Container mail-server  Started`,
    ``,
    `[3] Waiting for containers`,
    `    mail-server: healthy`,
    `    mail-client: healthy`,
    ``,
    `[4] Configuring network endpoints`,
    `Client:`,
    `2: eth0@if11: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP`,
    `    inet 172.30.0.2/24 brd 172.30.0.255 scope global eth0`,
    `    inet 10.10.1.1/24 scope global eth0`,
    `Server:`,
    `2: eth0@if12: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP`,
    `    inet 172.30.0.3/24 brd 172.30.0.255 scope global eth0`,
    `    inet 10.20.1.1/24 scope global eth0`,
    ``,
    `[5] Configuring ${config.tlsMode} (${config.tlsVersion})`,
    `    Loading certificate profile: ${config.certificateProfile}`,
    `    Generating RSA-2048 key pair...`,
    `    Certificate CN=mail-lab.local generated`,
    `    TLS handshake parameters configured`,
    ``,
    `[6] Starting packet capture on port ${config.port}`,
    `    tcpdump: listening on eth0, capture size 262144 bytes`,
    ``,
    `[7] Initiating ${config.protocol} session`,
    `[SMTP] Connecting to ${config.server}:${config.port}`,
    `[SMTP] 220 mail-lab.local ESMTP Postfix`,
    `[SMTP] EHLO client.lab.local`,
    `[SMTP] 250-mail-lab.local`,
    `[SMTP] 250-STARTTLS`,
    `[SMTP] 250-AUTH LOGIN PLAIN`,
    `[SMTP] 250 OK`,
    config.tlsMode !== 'None' ? `[TLS] Starting ${config.tlsMode} negotiation` : `[SMTP] Proceeding without TLS`,
    config.tlsMode !== 'None' ? `[TLS] ${config.tlsVersion} handshake initiated` : ``,
    config.tlsMode !== 'None' ? `[TLS] Cipher suite: TLS_AES_256_GCM_SHA384` : ``,
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
    `[SMTP] Sending message body (${Math.floor(Math.random() * 500 + 200)} bytes)...`,
    `[SMTP] Sending attachments via MIME multipart...`,
    `[SMTP] 250 OK: queued as ${runId.toUpperCase()}${Math.floor(Math.random() * 9000 + 1000)}`,
    `[SMTP] QUIT`,
    `[SMTP] 221 Bye`,
    ``,
    `[8] Stopping packet capture`,
    `    tcpdump: ${Math.floor(Math.random() * 200 + 80)} packets captured`,
    `    ${Math.floor(Math.random() * 200 + 80)} packets received by filter`,
    `    0 packets dropped by kernel`,
    ``,
    `[9] Copying logs`,
    `    mail-server.log: ${(Math.random() * 2 + 0.5).toFixed(1)}M`,
    `    mail-client.log: ${(Math.random() * 2 + 0.5).toFixed(1)}M`,
    ``,
    `[10] Copying PCAP`,
    `    ${runId}.pcap: ${Math.floor(Math.random() * 50 + 15)}K`,
    ``,
    `======================================`,
    ` Experiment completed`,
    ` Dataset: dataset/runs/${runId}`,
    `======================================`,
    `total ${(Math.random() * 5 + 2).toFixed(1)}M`,
    `-rw-r--r-- 1 lab lab ${(Math.random() * 2 + 0.5).toFixed(1)}M  mail-server.log`,
    `-rw-r--r-- 1 lab lab ${(Math.random() * 2 + 0.5).toFixed(1)}M  mail-client.log`,
    `-rw-r--r-- 1 lab lab  ${Math.floor(Math.random() * 50 + 15)}K  ${runId}.pcap`,
    `-rw-r--r-- 1 lab lab 2.8K  sa.txt`,
    `-rw-r--r-- 1 lab lab 4.7K  tls-handshake.txt`,
  ].filter(Boolean)
}

export default function LabPage() {
  /* ─── configuration state ──────────────────────────── */
  const [configured, setConfigured] = useState(false)
  const [savedConfigJson, setSavedConfigJson] = useState<string | null>(null)
  const [configCopied, setConfigCopied] = useState(false)
  const [configCollapsed, setConfigCollapsed] = useState(false)

  /* ─── form fields ─────────────────────────────────── */
  const [server, setServer] = useState('smtp.lab.local')
  const [protocol, setProtocol] = useState('SMTP')
  const [port, setPort] = useState('587')
  const [tlsMode, setTlsMode] = useState('STARTTLS')
  const [tlsVersion, setTlsVersion] = useState('TLS 1.3')
  const [securityProfile, setSecurityProfile] = useState('Secure')
  const [certificateProfile, setCertificateProfile] = useState('Valid')
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
  const [responseJson, setResponseJson] = useState<string | null>(null)
  const [logCollapsed, setLogCollapsed] = useState(false)
  const logBoxRef = useRef<HTMLPreElement>(null)

  /* ─── helpers ──────────────────────────────────────── */
  const attachmentSize = useMemo(
    () =>
      Array.from(attachments ?? []).reduce(
        (total, file) => total + file.size,
        0,
      ),
    [attachments],
  )
  const pcapCount = Math.max(1, Math.ceil(attachmentSize / (5 * 1024 * 1024)))
  const formatBytes = (bytes: number) =>
    bytes < 1024 * 1024
      ? `${Math.max(1, Math.round(bytes / 1024))} KB`
      : `${(bytes / (1024 * 1024)).toFixed(1)} MB`

  /* ─── copy JSON to clipboard ────────────────────────── */
  const copyJson = useCallback(
    (text: string) => {
      navigator.clipboard.writeText(text)
      setConfigCopied(true)
      setTimeout(() => setConfigCopied(false), 2000)
    },
    [],
  )

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
        tls_mode: tlsMode,
        tls_version: tlsVersion,
        security_profile: securityProfile,
        certificate_profile: certificateProfile,
        authentication,
      },
      capture_policy: {
        capture_tls_handshakes: true,
        capture_message_parts: true,
        capture_attachment_transfers: true,
        capture_retransmissions: true,
        group_under_single_capture: true,
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

    const configForLog: Record<string, string> = {
      protocol,
      server,
      port,
      tlsMode,
      tlsVersion,
      certificateProfile,
      authentication,
      recipient,
    }
    const allLines = generateLogLines(currentRunId, configForLog)

    // Stream logs line by line with realistic delay
    for (let i = 0; i < allLines.length; i++) {
      const line = allLines[i]
      await new Promise((resolve) =>
        setTimeout(resolve, Math.random() * 80 + 20),
      )
      setLogLines((prev) => [...prev, line])
      // Auto-scroll
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
          tlsVersion,
          certificateProfile,
          authentication,
          files: Array.from(attachments ?? []).map((file) => ({
            name: file.name,
            size: file.size,
          })),
        }),
      })

      if (response.ok) {
        const session = await response.json()

        const fullResponse = {
          ok: true,
          run_id: currentRunId,
          config: {
            protocol,
            server,
            port: Number(port),
            tls_mode: tlsMode,
            tls_version: tlsVersion,
            certificate_profile: certificateProfile,
            authentication,
          },
          session_id: session.id,
          dataset_dir: `dataset/runs/${currentRunId}`,
          pcap: `captures/${currentRunId}.pcap`,
          download_url: `/api/lab-sessions/download/${session.id}`,
          files_generated: session.files,
          reconstruction: session.reconstruction,
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
      setLogLines((prev) => [
        ...prev,
        '',
        '[ERROR] Failed to connect to API endpoint',
      ])
    } finally {
      setGenerating(false)
    }
  }

  /* ─── download dummy PCAP ──────────────────────────── */
  function downloadPcap() {
    // Build realistic PCAP-like content
    const pcapHeader = [
      `# SecureMailScope — Forensic PCAP Export`,
      `# Run ID: ${runId}`,
      `# Generated: ${new Date().toISOString()}`,
      `# Protocol: ${protocol} | TLS: ${tlsMode} (${tlsVersion})`,
      `# Server: ${server}:${port}`,
      `# Certificate: ${certificateProfile} | Auth: ${authentication}`,
      ``,
      `# ──── Packet Summary ──────────────────────────────`,
      `# Frame 1: 74 bytes on wire, TCP SYN`,
      `#   Source: 172.30.0.2:${Math.floor(Math.random() * 50000 + 10000)}  →  Destination: 172.30.0.3:${port}`,
      `#   Flags: 0x002 (SYN)  Seq=0  Win=65535`,
      ``,
      `# Frame 2: 74 bytes on wire, TCP SYN-ACK`,
      `#   Source: 172.30.0.3:${port}  →  Destination: 172.30.0.2:${Math.floor(Math.random() * 50000 + 10000)}`,
      `#   Flags: 0x012 (SYN, ACK)  Seq=0  Ack=1  Win=65535`,
      ``,
      `# Frame 3: 66 bytes on wire, TCP ACK`,
      `#   Flags: 0x010 (ACK)  Seq=1  Ack=1  Win=65535`,
      ``,
      `# Frame 4: SMTP Banner`,
      `#   220 mail-lab.local ESMTP Postfix`,
      ``,
      `# Frame 5: EHLO`,
      `#   EHLO client.lab.local`,
      ``,
      `# Frame 6: EHLO Response`,
      `#   250-mail-lab.local`,
      `#   250-STARTTLS`,
      `#   250-AUTH LOGIN PLAIN`,
      `#   250 OK`,
      ``,
      tlsMode !== 'None' ? `# Frame 7: STARTTLS` : `# Frame 7: MAIL FROM`,
      tlsMode !== 'None' ? `#   STARTTLS` : `#   MAIL FROM:<sender@lab.local>`,
      ``,
      tlsMode !== 'None' ? `# Frame 8: TLS Handshake — ClientHello` : ``,
      tlsMode !== 'None' ? `#   ${tlsVersion} ClientHello` : ``,
      tlsMode !== 'None'
        ? `#   Cipher Suites: TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256`
        : ``,
      ``,
      tlsMode !== 'None' ? `# Frame 9: TLS Handshake — ServerHello` : ``,
      tlsMode !== 'None' ? `#   ${tlsVersion} ServerHello` : ``,
      tlsMode !== 'None'
        ? `#   Selected Cipher: TLS_AES_256_GCM_SHA384`
        : ``,
      ``,
      `# ──── End of Summary ──────────────────────────────`,
      ``,
      `# Total packets captured: ${Math.floor(Math.random() * 200 + 80)}`,
      `# Capture duration: ${(Math.random() * 5 + 1).toFixed(2)} seconds`,
      `# File size: ${Math.floor(Math.random() * 50 + 15)} KB`,
    ]
      .filter(Boolean)
      .join('\n')

    const blob = new Blob([pcapHeader], { type: 'application/octet-stream' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${runId}.pcap`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }

  return (
    <AppShell>
      <PageHeader
        eyebrow="Controlled environment"
        title="Email traffic lab"
        description="Configure the lab, compose an email with attachments, then generate related PCAP captures for reconstruction."
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
            <div className="grid gap-5 sm:grid-cols-2">
              <label className={labelClass}>
                Email protocol
                <select
                  value={protocol}
                  onChange={(e) => setProtocol(e.target.value)}
                  className={inputClass}
                >
                  <option>SMTP</option>
                  <option>IMAP</option>
                  <option>POP3</option>
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
              <label className={labelClass}>
                Port
                <input
                  value={port}
                  onChange={(e) => setPort(e.target.value)}
                  inputMode="numeric"
                  className={inputClass}
                />
              </label>
              <label className={labelClass}>
                TLS mode
                <select
                  value={tlsMode}
                  onChange={(e) => setTlsMode(e.target.value)}
                  className={inputClass}
                >
                  <option>STARTTLS</option>
                  <option>Direct TLS</option>
                  <option>None</option>
                </select>
              </label>
              <label className={labelClass}>
                TLS version
                <select
                  value={tlsVersion}
                  onChange={(e) => setTlsVersion(e.target.value)}
                  className={inputClass}
                >
                  <option>TLS 1.2</option>
                  <option>TLS 1.3</option>
                </select>
              </label>
              <label className={labelClass}>
                Security profile
                <select
                  value={securityProfile}
                  onChange={(e) => setSecurityProfile(e.target.value)}
                  className={inputClass}
                >
                  <option>Secure</option>
                  <option>Weak</option>
                  <option>Custom</option>
                </select>
              </label>
              <label className={labelClass}>
                Certificate profile
                <select
                  value={certificateProfile}
                  onChange={(e) => setCertificateProfile(e.target.value)}
                  className={inputClass}
                >
                  <option>Valid</option>
                  <option>Expired</option>
                  <option>Self-signed</option>
                </select>
              </label>
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
                All message parts, attachment transfers, TLS handshakes, and
                retransmissions are grouped under one capture.
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
              <strong className="text-[#36516d]">
                Step 1 · Configure first
              </strong>
              <br />
              Save the email protocol, server, TLS, certificate, and
              authentication settings to unlock the draft composer.
            </div>
          ) : (
            <form onSubmit={sendEmail} className="mt-7 flex flex-col gap-4">
              <div className="rounded-xl border border-[#cfe9df] bg-[#f0faf6] p-3 text-xs text-[#247c6b]">
                <strong>Step 2 · Draft and capture</strong>
                <br />
                {protocol} via {server}:{port} · {tlsMode} · {tlsVersion} ·{' '}
                {certificateProfile} certificate
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
                    {attachments.length} file(s) selected ·{' '}
                    {formatBytes(attachmentSize)}
                  </strong>
                  <div className="mt-2 flex flex-col gap-1">
                    {Array.from(attachments).map((file) => (
                      <span key={`${file.name}-${file.size}`}>
                        {file.name} · {formatBytes(file.size)}
                      </span>
                    ))}
                  </div>
                  <p className="mt-2 text-[#247c6b]">
                    Estimated capture output: {pcapCount} related PCAP file
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
                  <span className="text-sm font-semibold text-[#a3f7bf]">
                    Capture Logs
                  </span>
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
                  style={{
                    scrollbarWidth: 'thin',
                    scrollbarColor: '#1a3a2a #0a0f14',
                  }}
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
                                      : line.startsWith('[IKE]') ||
                                          line.startsWith('[ENC]') ||
                                          line.startsWith('[NET]') ||
                                          line.startsWith('[CFG]')
                                        ? 'text-[#38bdf8]'
                                        : 'text-[#c8d6e5]'
                            : line.startsWith('#')
                              ? 'text-[#6b7280]'
                              : line.startsWith(' Container') ||
                                  line.startsWith(' Network') ||
                                  line.startsWith(' Image')
                                ? 'text-[#94a3b8]'
                                : line.startsWith('-rw')
                                  ? 'text-[#a78bfa]'
                                  : line.startsWith('total')
                                    ? 'text-[#fbbf24]'
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

          {/* ── Success + PCAP Download ──────────────────── */}
          {sent && (
            <div className="mt-5 animate-[fadeSlideIn_0.3s_ease-out]">
              <div className="rounded-xl border border-[#cfe9df] bg-[#f0faf6] p-4 text-sm text-[#247c6b]">
                <div className="flex items-center gap-2 font-semibold">
                  <CheckCircle2 className="size-4" />
                  Step 3 · Captures ready
                </div>
                <p className="mt-2 leading-6">
                  Session <strong>{runId}</strong> generated {pcapCount} related
                  PCAP file{pcapCount === 1 ? '' : 's'} for this email. The
                  files stay grouped together while TCP streams are
                  reconstructed.
                </p>

                <div className="mt-3 flex flex-wrap gap-2">
                  <button
                    onClick={downloadPcap}
                    className="inline-flex items-center gap-2 rounded-lg bg-[#173b64] px-3.5 py-2 text-xs font-semibold text-white transition-all hover:bg-[#214d7d] hover:shadow-lg active:scale-[0.98]"
                  >
                    <Download className="size-3.5" />
                    Download {runId}.pcap
                  </button>
                  <a
                    href={`/analysis?session=${runId}`}
                    className="inline-flex items-center gap-1 rounded-lg border border-[#cfe9df] px-3.5 py-2 text-xs font-bold text-[#247c6b] transition-all hover:bg-[#e5f4ef]"
                  >
                    <FileText className="size-3" />
                    Continue to Traffic
                  </a>
                </div>
              </div>

              {/* Response JSON box */}
              {responseJson && (
                <div className="mt-4">
                  <div className="flex items-center justify-between rounded-t-xl border border-b-0 border-[#d7e0ea] bg-gradient-to-r from-[#2d8d78] to-[#247c6b] px-4 py-2">
                    <span className="text-xs font-semibold text-white">
                      API Response (JSON)
                    </span>
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
        No external messages are sent. This is a controlled forensic lab
        simulation.
      </div>

    </AppShell>
  )
}
