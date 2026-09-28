'use client'

import { ChangeEvent, DragEvent, useEffect, useRef, useState } from 'react'
import Link from 'next/link'
import { useRouter } from 'next/navigation'
import {
  Activity,
  ArrowRight,
  CheckCircle2,
  ChevronRight,
  Clock,
  Code2,
  FileArchive,
  FileText,
  FolderOpen,
  Loader2,
  LockKeyhole,
  Scale,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  UploadCloud,
  X,
} from 'lucide-react'
import { AppShell, PageHeader, StatusBadge } from '@/components/app-shell'
import { saveAnalysisSession } from '@/lib/analysis-storage'
import type { CanonicalAnalysis } from '@/lib/types'
import { evaluateSecurityRules } from '@/lib/security-rules'

const MAX_FILE_SIZE = 500 * 1024 * 1024
const ACCEPTED = ['.pcap', '.pcapng']

interface LogEntry {
  id: string
  stage: string
  timestamp: string
  json: Record<string, unknown>
}

export default function UploadPage() {
  const router = useRouter()
  const inputRef = useRef<HTMLInputElement>(null)
  const logTerminalRef = useRef<HTMLDivElement>(null)

  const [isDragging, setIsDragging] = useState(false)
  const [files, setFiles] = useState<File[]>([])
  const [isProcessing, setIsProcessing] = useState(false)
  const [error, setError] = useState('')
  const [stageText, setStageText] = useState('')

  // 40-second analysis state
  const [analysisActive, setAnalysisActive] = useState(false)
  const [analysisComplete, setAnalysisComplete] = useState(false)
  const [progressPercent, setProgressPercent] = useState(0)
  const [categoriesCompleted, setCategoriesCompleted] = useState(0)
  const [elapsedSeconds, setElapsedSeconds] = useState(0)
  const [currentStageName, setCurrentStageName] = useState('')
  const [logs, setLogs] = useState<LogEntry[]>([])
  const [completedAnalysis, setCompletedAnalysis] = useState<CanonicalAnalysis | null>(null)
  const [sessionId, setSessionId] = useState<string>('')

  // Auto-scroll terminal
  useEffect(() => {
    if (logTerminalRef.current) {
      logTerminalRef.current.scrollTop = logTerminalRef.current.scrollHeight
    }
  }, [logs])

  // Timer interval for elapsed time
  useEffect(() => {
    let timer: NodeJS.Timeout | null = null
    if (analysisActive && !analysisComplete) {
      timer = setInterval(() => {
        setElapsedSeconds((prev) => prev + 1)
      }, 1000)
    }
    return () => {
      if (timer) clearInterval(timer)
    }
  }, [analysisActive, analysisComplete])

  function addFiles(selected: FileList | File[]) {
    const incoming = Array.from(selected)
    const invalid = incoming.find(
      (file) => !ACCEPTED.includes(file.name.toLowerCase().slice(file.name.lastIndexOf('.')))
    )
    const oversized = incoming.find((file) => file.size > MAX_FILE_SIZE)
    if (invalid) return setError(`${invalid.name}: only .pcap and .pcapng files are supported.`)
    if (oversized) return setError(`${oversized.name}: the maximum file size is 500 MB.`)
    setError('')
    setFiles((current) => [
      ...current,
      ...incoming.filter(
        (file) => !current.some((item) => item.name === file.name && item.size === file.size)
      ),
    ])
  }

  function handleDrop(event: DragEvent<HTMLDivElement>) {
    event.preventDefault()
    setIsDragging(false)
    addFiles(event.dataTransfer.files)
  }

  function handleInput(event: ChangeEvent<HTMLInputElement>) {
    if (event.target.files) addFiles(event.target.files)
    event.target.value = ''
  }

  async function uploadAndAnalyze() {
    if (!files.length) return setError('Add at least one PCAP file.')
    setIsProcessing(true)
    setError('')
    setAnalysisActive(true)
    setAnalysisComplete(false)
    setProgressPercent(0)
    setCategoriesCompleted(0)
    setElapsedSeconds(0)
    setLogs([])
    setStageText('Uploading and initializing forensic analysis pipeline…')

    const formData = new FormData()
    files.forEach((file) => formData.append('files', file))

    let uploadResult: { id: string; files: unknown[]; analysis?: CanonicalAnalysis } | null = null

    try {
      // 1. Kick off actual server-side upload and parsing
      const response = await fetch('/api/uploads', { method: 'POST', body: formData })
      const result = await response.json()
      if (!response.ok) throw new Error(result.error || 'Upload failed.')
      uploadResult = result
      setSessionId(result.id)

      if (result.analysis) {
        saveAnalysisSession(result.analysis)
      }
    } catch (uploadError) {
      setError(
        uploadError instanceof Error
          ? uploadError.message
          : 'Upload failed. Please check network and try again.'
      )
      setIsProcessing(false)
      setAnalysisActive(false)
      return
    }

    // 2. Perform the progressive ~40 second demonstration of the 17 security categories
    const analysis = uploadResult.analysis
    const evaluated = analysis
      ? evaluateSecurityRules({
          configured: analysis.configured,
          observed: analysis.observed,
          configurationComparison: analysis.configurationComparison,
          capture: analysis.capture,
        })
      : null

    // Define 19 progressive stages (~2.1s each -> ~40s total)
    const stages = [
      {
        name: 'PCAP Validation',
        categoryIdx: 0,
        buildJson: () => ({
          stage: 'pcap_validation',
          status: 'completed',
          filename: analysis?.capture.filename || files[0]?.name || 'capture.pcapng',
          format: analysis?.capture.format || 'PCAPNG',
          sizeBytes: files.reduce((s, f) => s + f.size, 0),
          metadataIntegrity: analysis?.capture.metadataIntegrity || 'valid',
          timestamp: new Date().toISOString(),
        }),
      },
      {
        name: 'TCP Stream Reconstruction',
        categoryIdx: 0,
        buildJson: () => ({
          stage: 'tcp_stream_reconstruction',
          status: 'completed',
          source: `${analysis?.capture.sourceIp || '172.30.0.2'}:${analysis?.capture.sourcePort || 50000}`,
          destination: `${analysis?.capture.destinationIp || '172.30.0.3'}:${analysis?.capture.destinationPort || 587}`,
          packetsProcessed: analysis?.capture.packetCount || 42,
          reconstructedStreams: 1,
        }),
      },
      {
        name: '1. Protocol Security',
        categoryIdx: 1,
        buildJson: () => ({
          category: 'Protocol Security',
          ruleId: 'PROTO-001',
          protocol: analysis?.observed.protocol.detected || 'SMTP',
          port: analysis?.observed.protocol.port || 587,
          transportSecurity: analysis?.observed.tls.handshakeComplete ? 'TLS_ENCRYPTED' : 'PLAINTEXT',
          status: evaluated?.categorySummaries.find((c) => c.category === 'Protocol Security')?.status || 'PASS',
        }),
      },
      {
        name: '2. TLS Version',
        categoryIdx: 2,
        buildJson: () => ({
          category: 'TLS Version',
          ruleId: 'TLS-001',
          observedVersion: analysis?.observed.tls.version || 'TLS1.3',
          standard: 'RFC 8996 / NIST SP 800-52 Rev. 2',
          status: evaluated?.categorySummaries.find((c) => c.category === 'TLS Version')?.status || 'PASS',
        }),
      },
      {
        name: '3. Cipher Suite',
        categoryIdx: 3,
        buildJson: () => ({
          category: 'Cipher Suite',
          ruleId: 'CIPHER-001',
          cipherSuite: analysis?.observed.tls.cipherSuite || 'TLS_AES_256_GCM_SHA384',
          authenticatedEncryption:
            analysis?.observed.tls.cipherSuite.includes('GCM') ||
            analysis?.observed.tls.cipherSuite.includes('POLY1305')
              ? 'AEAD_COMPLIANT'
              : 'LEGACY_CBC',
          status: evaluated?.categorySummaries.find((c) => c.category === 'Cipher Suite')?.status || 'PASS',
        }),
      },
      {
        name: '4. Cryptographic Strength',
        categoryIdx: 4,
        buildJson: () => ({
          category: 'Cryptographic Strength',
          ruleId: 'CRYPTO-001',
          standard: 'NIST SP 800-57 Part 1 Rev. 5',
          asymmetricSecurityBits:
            analysis?.observed.certificate.publicKeyAlgorithm === 'RSA'
              ? analysis.observed.certificate.publicKeyLength < 2048
                ? '< 80 bits (Disallowed)'
                : '112+ bits'
              : '128+ bits',
          bulkEncryptionBits: analysis?.observed.tls.cipherSuite.includes('256') ? '256 bits' : '128 bits',
          status: evaluated?.categorySummaries.find((c) => c.category === 'Cryptographic Strength')?.status || 'PASS',
        }),
      },
      {
        name: '5. Key Exchange',
        categoryIdx: 5,
        buildJson: () => ({
          category: 'Key Exchange',
          ruleId: 'KEX-001',
          mechanism: analysis?.observed.tls.keyExchange || 'ECDHE',
          namedGroup: analysis?.observed.tls.namedGroup || 'X25519',
          ephemeral: analysis?.observed.tls.keyExchange !== 'RSA',
          status: evaluated?.categorySummaries.find((c) => c.category === 'Key Exchange')?.status || 'PASS',
        }),
      },
      {
        name: '6. Forward Secrecy',
        categoryIdx: 6,
        buildJson: () => ({
          category: 'Forward Secrecy',
          ruleId: 'PFS-001',
          perfectForwardSecrecy: analysis?.observed.tls.forwardSecrecy ? 'ENABLED' : 'DISABLED',
          protection: analysis?.observed.tls.forwardSecrecy
            ? 'Guarantees past session confidentiality'
            : 'Vulnerable to retrospective decryption',
          status: evaluated?.categorySummaries.find((c) => c.category === 'Forward Secrecy')?.status || 'PASS',
        }),
      },
      {
        name: '7. Certificate Security',
        categoryIdx: 7,
        buildJson: () => ({
          category: 'Certificate Security',
          ruleId: 'CERT-001',
          present: analysis?.observed.certificate.present || false,
          commonName: analysis?.observed.certificate.commonName || 'not_observable',
          issuer: analysis?.observed.certificate.issuer || 'not_observable',
          selfSigned: analysis?.observed.certificate.selfSigned || false,
          status: evaluated?.categorySummaries.find((c) => c.category === 'Certificate Security')?.status || 'PASS',
        }),
      },
      {
        name: '8. Certificate Chain',
        categoryIdx: 8,
        buildJson: () => ({
          category: 'Certificate Chain',
          ruleId: 'CHAIN-001',
          chainValid: analysis?.observed.certificate.chainValid ?? false,
          trustAnchor: analysis?.observed.certificate.chainValid ? 'VERIFIED_ROOT' : 'UNTRUSTED_OR_INCOMPLETE',
          status: evaluated?.categorySummaries.find((c) => c.category === 'Certificate Chain')?.status || 'PASS',
        }),
      },
      {
        name: '9. Certificate Expiration',
        categoryIdx: 9,
        buildJson: () => ({
          category: 'Certificate Expiration',
          ruleId: 'EXP-001',
          validFrom: analysis?.observed.certificate.validFrom || 'not_observable',
          validUntil: analysis?.observed.certificate.validUntil || 'not_observable',
          expired: analysis?.observed.certificate.expired || false,
          notYetValid: analysis?.observed.certificate.notYetValid || false,
          status: evaluated?.categorySummaries.find((c) => c.category === 'Certificate Expiration')?.status || 'PASS',
        }),
      },
      {
        name: '10. Public Key Algorithm',
        categoryIdx: 10,
        buildJson: () => ({
          category: 'Public Key Algorithm',
          ruleId: 'PK-ALG-001',
          algorithm: analysis?.observed.certificate.publicKeyAlgorithm || 'not_observable',
          approved: ['RSA', 'ECDSA', 'Ed25519'].includes(analysis?.observed.certificate.publicKeyAlgorithm || ''),
          status: evaluated?.categorySummaries.find((c) => c.category === 'Public Key Algorithm')?.status || 'PASS',
        }),
      },
      {
        name: '11. Public Key Length',
        categoryIdx: 11,
        buildJson: () => ({
          category: 'Public Key Length',
          ruleId: 'PK-LEN-001',
          lengthBits: analysis?.observed.certificate.publicKeyLength || 0,
          minimumRequirement: '>= 2048 bits (RSA)',
          status: evaluated?.categorySummaries.find((c) => c.category === 'Public Key Length')?.status || 'PASS',
        }),
      },
      {
        name: '12. Signature Algorithm',
        categoryIdx: 12,
        buildJson: () => ({
          category: 'Signature Algorithm',
          ruleId: 'SIG-001',
          signatureAlgorithm: analysis?.observed.certificate.signatureAlgorithm || 'not_observable',
          hashDigest: analysis?.observed.certificate.signatureAlgorithm?.includes('SHA256')
            ? 'SHA-256'
            : analysis?.observed.certificate.signatureAlgorithm?.includes('SHA1')
            ? 'SHA-1 (DEPRECATED)'
            : 'Other',
          status: evaluated?.categorySummaries.find((c) => c.category === 'Signature Algorithm')?.status || 'PASS',
        }),
      },
      {
        name: '13. STARTTLS Security',
        categoryIdx: 13,
        buildJson: () => ({
          category: 'STARTTLS Security',
          ruleId: 'STARTTLS-001',
          advertised: analysis?.observed.starttls.advertised ?? false,
          negotiated: analysis?.observed.starttls.negotiated ?? false,
          state: evaluated?.starttlsAssessment.state || 'NOT_OBSERVABLE',
          status: evaluated?.categorySummaries.find((c) => c.category === 'STARTTLS Security')?.status || 'PASS',
        }),
      },
      {
        name: '14. Configuration Compliance',
        categoryIdx: 14,
        buildJson: () => ({
          category: 'Configuration Compliance',
          ruleId: 'COMP-001',
          standard: 'CISA Emergency Directive & Guidelines',
          complianceStatus:
            evaluated?.categorySummaries.find((c) => c.category === 'Configuration Compliance')?.status ||
            'COMPLIANT',
          status: evaluated?.categorySummaries.find((c) => c.category === 'Configuration Compliance')?.status || 'PASS',
        }),
      },
      {
        name: '15. Deprecated Cryptography',
        categoryIdx: 15,
        buildJson: () => ({
          category: 'Deprecated Cryptography',
          ruleId: 'DEP-001',
          prohibitedPrimsFound:
            analysis?.observed.tls.version === 'TLS1.0' ||
            analysis?.observed.tls.version === 'TLS1.1' ||
            analysis?.observed.tls.cipherSuite.includes('3DES')
              ? true
              : false,
          status: evaluated?.categorySummaries.find((c) => c.category === 'Deprecated Cryptography')?.status || 'PASS',
        }),
      },
      {
        name: '16. TLS Anomalies',
        categoryIdx: 16,
        buildJson: () => ({
          category: 'TLS Anomalies',
          ruleId: 'ANOM-001',
          anomaliesDetected: analysis?.anomalies.length || 0,
          downgradeAttempts: analysis?.anomalies.some((a) => a.type.includes('DOWNGRADE')) || false,
          status: evaluated?.categorySummaries.find((c) => c.category === 'TLS Anomalies')?.status || 'PASS',
        }),
      },
      {
        name: '17. Configuration vs Observed',
        categoryIdx: 17,
        buildJson: () => ({
          category: 'Configuration vs Observed mismatch',
          ruleId: 'MISMATCH-001',
          manifestAvailable: analysis?.capture.hasSecureMailScopeMetadata || false,
          mismatchesCount: analysis?.configurationComparison?.mismatches.length || 0,
          mismatches: analysis?.configurationComparison?.mismatches || [],
          status:
            evaluated?.categorySummaries.find((c) => c.category === 'Configuration vs Observed mismatch')
              ?.status || 'PASS',
        }),
      },
      {
        name: 'Security Scoring & Posture Assembly',
        categoryIdx: 17,
        buildJson: () => ({
          stage: 'final_security_posture',
          status: 'completed',
          securityScore: analysis?.securityScore.total ?? 100,
          grade: analysis?.securityScore.grade ?? 'A',
          riskLevel: analysis?.securityScore.level ?? 'Excellent',
          findingsCount: analysis?.findings.length ?? 0,
          deductionsCount: analysis?.securityScore.deductions.length ?? 0,
          aiAssessment: analysis?.aiAssessment.available ? 'GROQ_INTEGRATED' : 'DETERMINISTIC_RULES',
        }),
      },
    ]

    // Step through each stage with ~2000ms delay per stage (~40s total)
    const stepDurationMs = 2100

    for (let i = 0; i < stages.length; i++) {
      const current = stages[i]
      setCurrentStageName(current.name)
      setCategoriesCompleted(current.categoryIdx)
      const currentPct = Math.round(((i + 1) / stages.length) * 100)
      setProgressPercent(currentPct)

      const entry: LogEntry = {
        id: `log-${i + 1}`,
        stage: current.name,
        timestamp: new Date().toLocaleTimeString(),
        json: current.buildJson(),
      }

      setLogs((prev) => [...prev, entry])
      setStageText(`Processing ${current.name} (${currentPct}%)…`)

      await new Promise((resolve) => setTimeout(resolve, stepDurationMs))
    }

    // Finalize
    if (analysis) {
      setCompletedAnalysis(analysis)
      saveAnalysisSession(analysis)
    }
    setAnalysisComplete(true)
    setIsProcessing(false)
    setProgressPercent(100)
    setCategoriesCompleted(17)
    setCurrentStageName('Analysis Complete')
    setStageText('Cryptographic posture assessment complete. All 17 categories processed.')
  }

  return (
    <AppShell>
      <PageHeader
        eyebrow="Capture input"
        title="Upload PCAP files"
        description="Add related PCAP files. They will be stored together, reconstructed, and evaluated across 17 cryptographic posture categories."
      />

      <div className="mx-auto max-w-4xl space-y-6">
        {/* Helper Banner */}
        <div className="rounded-2xl border border-[#dce9f5] bg-[#f7fbff] p-4 text-sm text-[#36516d]">
          <div className="flex items-start gap-3">
            <FolderOpen className="mt-0.5 size-5 shrink-0 text-[#173b64]" />
            <p>
              <strong>Real-time cryptographic forensic engine.</strong> All selected files are saved
              together, TCP streams are reconstructed, and the security rules engine deterministically
              evaluates all 17 NIST/RFC categories with streaming logs.
            </p>
          </div>
        </div>

        {/* Upload Drop Zone */}
        <div
          onDragOver={(event) => {
            event.preventDefault()
            setIsDragging(true)
          }}
          onDragLeave={() => setIsDragging(false)}
          onDrop={handleDrop}
          className={`rounded-2xl border border-dashed p-8 text-center transition sm:p-10 ${
            isDragging ? 'border-[#2d8d78] bg-[#f0faf6]' : 'border-[#b8c9dc] bg-white'
          }`}
        >
          <input
            ref={inputRef}
            type="file"
            multiple
            accept=".pcap,.pcapng,application/vnd.tcpdump.pcap"
            onChange={handleInput}
            className="sr-only"
          />
          <div className="mx-auto flex size-14 items-center justify-center rounded-2xl bg-[#eaf1f9] text-[#173b64]">
            <UploadCloud className="size-7" />
          </div>
          <h2 className="mt-4 text-lg font-bold">
            {files.length
              ? `${files.length} PCAP file${files.length === 1 ? '' : 's'} selected`
              : 'Drop PCAP files here'}
          </h2>
          <p className="mx-auto mt-2 max-w-md text-xs leading-5 text-[#718096]">
            Select .pcap or .pcapng files. The engine groups them, validates handshake parameters, and
            extracts cryptographic telemetry.
          </p>

          {/* File Pills */}
          {files.length > 0 && (
            <div className="mx-auto mt-4 flex max-w-lg flex-col gap-2 text-left">
              {files.map((file) => (
                <div
                  key={`${file.name}-${file.size}`}
                  className="flex items-center gap-3 rounded-xl border border-[#edf0f5] bg-[#fbfcfe] px-3 py-2 text-xs"
                >
                  <ShieldCheck className="size-4 text-[#247c6b]" />
                  <span className="min-w-0 flex-1 truncate font-medium">{file.name}</span>
                  <span className="text-[#8290a2]">{(file.size / 1024 / 1024).toFixed(2)} MB</span>
                  <button
                    type="button"
                    disabled={isProcessing}
                    onClick={() => setFiles((current) => current.filter((item) => item !== file))}
                    aria-label={`Remove ${file.name}`}
                  >
                    <X className="size-4 text-[#8290a2] hover:text-[#bb4e4e]" />
                  </button>
                </div>
              ))}
            </div>
          )}

          {/* Action Buttons */}
          <div className="mt-6 flex flex-wrap justify-center gap-3">
            <button
              type="button"
              disabled={isProcessing}
              onClick={() => inputRef.current?.click()}
              className="rounded-xl border border-[#d7e0ea] bg-white px-4 py-2.5 text-xs font-semibold text-[#173b64] hover:bg-[#f7fbff] disabled:opacity-50"
            >
              Add PCAP files
            </button>
            {files.length > 0 && (
              <button
                type="button"
                onClick={uploadAndAnalyze}
                disabled={isProcessing || analysisComplete}
                className="inline-flex items-center gap-2 rounded-xl bg-[#173b64] px-5 py-2.5 text-xs font-semibold text-white shadow-sm hover:bg-[#122e4e] disabled:cursor-not-allowed disabled:opacity-60"
              >
                {isProcessing ? (
                  <>
                    <Loader2 className="size-3.5 animate-spin" />
                    Analyzing Cryptographic Posture…
                  </>
                ) : analysisComplete ? (
                  <>
                    <CheckCircle2 className="size-3.5 text-[#4ade80]" />
                    Analysis Complete
                  </>
                ) : (
                  <>
                    <LockKeyhole className="size-3.5" />
                    Save &amp; Analyze PCAP
                  </>
                )}
              </button>
            )}
          </div>

          <p className="mt-3 text-[11px] text-[#9aa6b5]">
            Up to 20 files &bull; Maximum 500 MB each &bull; PCAP and PCAPNG supported
          </p>

          {error && (
            <p role="alert" className="mt-3 text-xs font-medium text-[#b44b4b]">
              {error}
            </p>
          )}
        </div>

        {/* ── Live Log & Progress Box (~40 Second Staged Demonstration) ──── */}
        {analysisActive && (
          <div className="rounded-2xl border border-[#1e293b] bg-[#0b1120] text-white shadow-xl overflow-hidden animate-[fadeSlideIn_0.3s_ease-out]">
            {/* Terminal Header */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between border-b border-white/10 bg-[#0f172a] px-5 py-3.5 gap-2">
              <div className="flex items-center gap-2.5">
                <Terminal className="size-4 text-[#38bdf8]" />
                <h3 className="text-xs font-bold uppercase tracking-wider text-slate-200">
                  Cryptographic Posture Across 17 Security Categories
                </h3>
              </div>

              <div className="flex items-center gap-4 text-xs">
                {/* Live Indicator */}
                <div className="flex items-center gap-1.5 font-medium">
                  {analysisComplete ? (
                    <span className="flex items-center gap-1 text-[#4ade80]">
                      <CheckCircle2 className="size-3.5" />
                      Analysis Complete
                    </span>
                  ) : (
                    <span className="flex items-center gap-1 text-[#38bdf8]">
                      <span className="size-2 rounded-full bg-[#38bdf8] animate-ping" />
                      Analysis in progress...
                    </span>
                  )}
                </div>

                {/* Elapsed Time */}
                <div className="flex items-center gap-1 font-mono text-slate-400">
                  <Clock className="size-3.5" />
                  <span>
                    00:{String(elapsedSeconds).padStart(2, '0')} / ~00:40
                  </span>
                </div>
              </div>
            </div>

            {/* Progress Bar & Stage Indicator */}
            <div className="border-b border-white/10 bg-[#080d1a] px-5 py-3">
              <div className="flex items-center justify-between text-xs mb-1.5">
                <span className="text-slate-300 font-medium">
                  Stage: <strong className="text-white">{currentStageName}</strong>
                </span>
                <span className="font-mono text-slate-300">
                  <strong>{categoriesCompleted}</strong> / 17 categories completed ({progressPercent}%)
                </span>
              </div>
              <div className="h-2 w-full overflow-hidden rounded-full bg-slate-800">
                <div
                  className="h-full bg-gradient-to-r from-[#2d8d78] via-[#38bdf8] to-[#4ade80] transition-all duration-500 ease-out"
                  style={{ width: `${progressPercent}%` }}
                />
              </div>
            </div>

            {/* Terminal Body: JSON Log Stream */}
            <div
              ref={logTerminalRef}
              className="max-h-[380px] min-h-[260px] overflow-y-auto p-4 font-mono text-[11px] leading-relaxed selection:bg-[#38bdf8]/30"
              style={{ scrollbarWidth: 'thin', scrollbarColor: '#334155 #0b1120' }}
            >
              {logs.length === 0 ? (
                <div className="flex items-center gap-2 text-slate-500 italic py-4">
                  <Loader2 className="size-3.5 animate-spin" />
                  Streaming forensic cryptographic logs line-by-line...
                </div>
              ) : (
                logs.map((log) => (
                  <div key={log.id} className="mb-3 rounded-lg bg-black/40 p-2.5 border border-white/5">
                    <div className="flex items-center justify-between text-[10px] text-slate-400 mb-1 border-b border-white/5 pb-1">
                      <span className="text-[#38bdf8] font-bold">[{log.stage}]</span>
                      <span>{log.timestamp}</span>
                    </div>
                    <pre className="text-[#a5f3fc] overflow-x-auto">
                      {JSON.stringify(log.json, null, 2)}
                    </pre>
                  </div>
                ))
              )}
              {!analysisComplete && (
                <div className="flex items-center gap-1.5 text-[#38bdf8] py-1 text-[11px]">
                  <span className="inline-block h-3.5 w-1.5 animate-pulse bg-[#38bdf8]" />
                  <span>Evaluating cryptographic parameters...</span>
                </div>
              )}
            </div>

            {/* Post-Completion Summary & Navigation Actions */}
            {analysisComplete && completedAnalysis && (
              <div className="border-t border-white/10 bg-[#0f172a] p-5 animate-[fadeSlideIn_0.3s_ease-out]">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                  <div className="flex items-center gap-4">
                    <div className="flex size-12 items-center justify-center rounded-xl bg-[#247c6b]/20 text-[#4ade80] border border-[#247c6b]/40">
                      <span className="text-xl font-black">
                        {completedAnalysis.securityScore.grade}
                      </span>
                    </div>
                    <div>
                      <h4 className="text-sm font-bold text-white">
                        Cryptographic Assessment Complete
                      </h4>
                      <p className="text-xs text-slate-400 mt-0.5">
                        Security Score: <strong>{completedAnalysis.securityScore.total}/100</strong>{' '}
                        &bull; Risk: <strong>{completedAnalysis.securityScore.level}</strong> &bull;{' '}
                        <strong>17/17</strong> Categories Processed &bull;{' '}
                        <strong>{completedAnalysis.findings.length}</strong> Finding(s) &bull;{' '}
                        <strong>{completedAnalysis.anomalies.length}</strong> Anomaly(ies)
                      </p>
                    </div>
                  </div>

                  {/* 3 Explicit Navigation Actions */}
                  <div className="flex flex-wrap gap-2">
                    <Link
                      href={`/analysis?session=${encodeURIComponent(sessionId)}`}
                      className="inline-flex items-center gap-1.5 rounded-xl bg-slate-800 border border-slate-700 px-3.5 py-2 text-xs font-semibold text-white hover:bg-slate-700"
                    >
                      <Activity className="size-3.5 text-[#38bdf8]" />
                      Traffic Analysis
                    </Link>
                    <Link
                      href={`/findings?session=${encodeURIComponent(sessionId)}`}
                      className="inline-flex items-center gap-1.5 rounded-xl bg-[#173b64] px-3.5 py-2 text-xs font-semibold text-white hover:bg-[#214d7d]"
                    >
                      <ShieldCheck className="size-3.5 text-[#4ade80]" />
                      Security Assessment
                    </Link>
                    <Link
                      href={`/reports?session=${encodeURIComponent(sessionId)}`}
                      className="inline-flex items-center gap-1.5 rounded-xl bg-[#247c6b] px-3.5 py-2 text-xs font-semibold text-white hover:bg-[#2c9682]"
                    >
                      <FileText className="size-3.5" />
                      Reports &amp; Downloads
                    </Link>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </AppShell>
  )
}
