'use client'

import { Suspense, useEffect, useState } from 'react'
import Link from 'next/link'
import { useSearchParams } from 'next/navigation'
import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  Download,
  ExternalLink,
  FileArchive,
  FileCode,
  FileText,
  Info,
  Loader2,
  LockKeyhole,
  Scale,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
} from 'lucide-react'
import { AppShell, PageHeader, StatusBadge } from '@/components/app-shell'
import { ReportAssistant } from '@/components/report-assistant'
import type { CanonicalAnalysis } from '@/lib/types'
import {
  getStoredAnalysis,
  saveAnalysisSession,
  handlePageLifecycle,
} from '@/lib/analysis-storage'
import { evaluateSecurityRules } from '@/lib/security-rules'

function gradeColor(g: string) {
  if (g === 'A') return 'text-[#247c6b] bg-[#edf8f4] border-[#b4ded4]'
  if (g === 'B') return 'text-[#2563eb] bg-[#eff6ff] border-[#bfdbfe]'
  if (g === 'C') return 'text-[#a66b1b] bg-[#fefce8] border-[#fde68a]'
  if (g === 'D') return 'text-[#e07b27] bg-[#fff7ed] border-[#fed7aa]'
  return 'text-[#bb4e4e] bg-[#fef2f2] border-[#fecaca]'
}

function ReportsView() {
  const searchParams = useSearchParams()
  const sessionFromUrl = searchParams.get('session')
  const [analysis, setAnalysis] = useState<CanonicalAnalysis | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    handlePageLifecycle()
    let isMounted = true

    async function resolveAnalysis() {
      setLoading(true)

      // 1. Try URL session parameter first
      if (sessionFromUrl) {
        try {
          const res = await fetch(`/api/analyze?session=${encodeURIComponent(sessionFromUrl)}`)
          if (res.ok) {
            const data: CanonicalAnalysis = await res.json()
            if (isMounted) {
              setAnalysis(data)
              saveAnalysisSession(data)
              setLoading(false)
              return
            }
          }
          const res2 = await fetch(`/api/uploads?id=${encodeURIComponent(sessionFromUrl)}`)
          if (res2.ok) {
            const sessionData = await res2.json()
            if (sessionData.analysis && isMounted) {
              setAnalysis(sessionData.analysis)
              saveAnalysisSession(sessionData.analysis)
              setLoading(false)
              return
            }
          }
        } catch {
          // Fallback to storage below
        }
      }

      // 2. Try restoring from client session storage
      const stored = getStoredAnalysis()
      if (stored && isMounted) {
        setAnalysis(stored)
        setLoading(false)
        return
      }

      if (isMounted) {
        setAnalysis(null)
        setLoading(false)
      }
    }

    resolveAnalysis()

    return () => {
      isMounted = false
    }
  }, [sessionFromUrl])

  function downloadJsonDirect() {
    if (!analysis) return
    const blob = new Blob([JSON.stringify(analysis, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `SecureMailScope_${analysis.session.id}_report.json`

    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }

  if (loading) {
    return (
      <AppShell>
        <div className="flex h-64 flex-col items-center justify-center gap-3">
          <Loader2 className="size-8 animate-spin text-[#173b64]" />
          <p className="text-sm font-medium text-[#718096]">Loading report deliverables…</p>
        </div>
      </AppShell>
    )
  }

  if (!analysis) {
    return (
      <AppShell>
        <PageHeader
          eyebrow="Deliverables & Compliance"
          title="Forensic report center"
          description="Download audit deliverables (PDF, HTML, and canonical JSON) generated from the reconstructed capture session."
        />
        <section className="mt-7 rounded-2xl border border-[#dce9f5] bg-[#f7fbff] p-8 text-center">
          <FileArchive className="mx-auto size-10 text-[#5f83ad]" />
          <h2 className="mt-4 text-lg font-bold text-[#182230]">No report available</h2>
          <p className="mx-auto mt-2 max-w-lg text-sm leading-6 text-[#718096]">
            Upload or generate a PCAP capture first. Reports stay empty until security analysis has
            data from that capture.
          </p>
          <div className="mt-5 flex justify-center gap-3">
            <Link
              href="/upload"
              className="inline-flex items-center gap-2 rounded-xl bg-[#173b64] px-4 py-2.5 text-sm font-semibold text-white shadow-sm hover:bg-[#122e4e]"
            >
              Upload PCAP <ArrowRight className="size-4" />
            </Link>
            <Link
              href="/lab"
              className="inline-flex items-center gap-2 rounded-xl border border-[#d0dbe7] bg-white px-4 py-2.5 text-sm font-semibold text-[#173b64] hover:bg-[#f7fbff]"
            >
              Email Lab
            </Link>
          </div>
        </section>
      </AppShell>
    )
  }

  const session = analysis.session.id
  const pdfHref = `/api/reports/demo-pdf?session=${encodeURIComponent(session)}`
  const htmlHref = `/api/reports/html?session=${encodeURIComponent(session)}`
  const jsonHref = `/api/reports/json?session=${encodeURIComponent(session)}`

  const evaluated = evaluateSecurityRules({
    configured: analysis.configured,
    observed: analysis.observed,
    configurationComparison: analysis.configurationComparison,
    capture: analysis.capture,
  })

  return (
    <AppShell>
      <PageHeader
        eyebrow="Deliverables & Compliance"
        title="Forensic report center"
        description="Comprehensive audit deliverables (PDF, HTML, and canonical JSON) generated from the reconstructed capture session."
      />

      {/* ── 1. Executive Posture Card ──────────────────────── */}
      <section className="mt-7 rounded-2xl border border-[#e5eaf1] bg-white p-6 shadow-sm">
        <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <span className="text-xs font-semibold uppercase tracking-wider text-[#5f83ad]">
              Forensic Assessment Overview
            </span>
            <h2 className="mt-1 text-xl font-bold text-[#182230]">
              {analysis.capture.filename}
            </h2>
            <p className="mt-1 text-xs text-[#8290a2]">
              Session: <code className="font-mono">{session}</code> &bull; Analyzed on{' '}
              {new Date(analysis.analysisTimestamp).toLocaleString()}
            </p>
          </div>
          <div
            className={`flex items-center gap-3 rounded-2xl border px-5 py-3 ${gradeColor(
              analysis.securityScore.grade
            )}`}
          >
            <div className="text-3xl font-extrabold">{analysis.securityScore.grade}</div>
            <div>
              <div className="text-sm font-bold">{analysis.securityScore.total} / 100</div>
              <div className="text-xs font-medium opacity-80">
                {analysis.securityScore.level} Posture
              </div>
            </div>
          </div>
        </div>

        {/* Telemetry Highlights */}
        <div className="mt-6 grid grid-cols-2 gap-3 sm:grid-cols-4">
          <div className="rounded-xl border border-[#edf0f5] bg-[#f8fbfe] p-3">
            <div className="text-xs font-medium text-[#718096]">Observed Protocol</div>
            <div className="mt-1 text-sm font-bold text-[#182230]">
              {analysis.observed.protocol.detected} (Port {analysis.observed.protocol.port})
            </div>
          </div>
          <div className="rounded-xl border border-[#edf0f5] bg-[#f8fbfe] p-3">
            <div className="text-xs font-medium text-[#718096]">TLS &amp; Cipher</div>
            <div
              className="mt-1 truncate text-sm font-bold text-[#182230]"
              title={analysis.observed.tls.cipherSuite}
            >
              {analysis.observed.tls.version} &bull;{' '}
              {analysis.observed.tls.forwardSecrecy ? 'PFS Active' : 'No PFS'}
            </div>
          </div>
          <div className="rounded-xl border border-[#edf0f5] bg-[#f8fbfe] p-3">
            <div className="text-xs font-medium text-[#718096]">Certificate Status</div>
            <div className="mt-1 text-sm font-bold text-[#182230]">
              {analysis.observed.certificate.expired
                ? 'Expired'
                : analysis.observed.certificate.chainValid
                ? 'Trusted / Valid'
                : 'Untrusted'}
            </div>
          </div>
          <div className="rounded-xl border border-[#edf0f5] bg-[#f8fbfe] p-3">
            <div className="text-xs font-medium text-[#718096]">Integrity &amp; Metadata</div>
            <div className="mt-1 text-sm font-bold text-[#182230]">
              {analysis.capture.hasSecureMailScopeMetadata
                ? 'Verified Manifest'
                : 'Standard PCAP'}
            </div>
          </div>
        </div>

        {/* AI Security Summary */}
        <div className="mt-5 rounded-xl border border-[#dce5ef] bg-[#f8fbfe] p-4">
          <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-[#173b64]">
            <Sparkles className="size-4 text-[#2d8d78]" />
            AI Executive Summary
          </div>
          {analysis.aiAssessment?.available ? (
            <>
              <p className="mt-2 text-sm leading-6 text-[#34455a]">
                {analysis.aiAssessment.executiveSummary}
              </p>
              {analysis.aiAssessment.riskNarrative && (
                <p className="mt-1 text-xs italic text-[#718096]">
                  {analysis.aiAssessment.riskNarrative}
                </p>
              )}
            </>
          ) : (
            <p className="mt-2 text-sm leading-6 text-[#607087]">
              AI summary unavailable. Showing deterministic security assessment grounded in NIST SP
              800-52 Rev. 2 and RFC standards.
            </p>
          )}
        </div>
      </section>

      {/* ── 2. Export Deliverables ─────────────────────────── */}
      <section className="mt-7 rounded-2xl border border-[#e5eaf1] bg-white p-6 shadow-sm">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="font-bold text-[#182230]">Export Deliverables</h2>
            <p className="mt-1 text-xs text-[#8290a2]">
              Standards-compliant forensic artifacts ready for distribution, auditing, or SIEM
              integration.
            </p>
          </div>
          <ShieldCheck className="size-5 text-[#2d8d78]" />
        </div>

        <div className="mt-5 divide-y divide-[#edf0f5]">
          {/* PDF Deliverable */}
          <div className="flex flex-col gap-3 py-4 first:pt-1 sm:flex-row sm:items-center">
            <div className="flex size-10 items-center justify-center rounded-xl bg-[#f0f4f8]">
              <FileText className="size-5 text-[#173b64]" />
            </div>
            <div className="min-w-0 flex-1">
              <p className="text-sm font-semibold text-[#182230]">
                Forensic Security Posture Report (PDF)
              </p>
              <p className="mt-0.5 text-xs text-[#8290a2]">
                Audit summary with cryptographic findings, evidence breakdown, and recommendations.
              </p>
            </div>
            <StatusBadge tone="success">PDF</StatusBadge>
            <a
              href={pdfHref}
              download={`SecureMailScope_${session}_report.pdf`}
              className="inline-flex items-center gap-2 rounded-xl bg-[#173b64] px-3.5 py-2 text-xs font-semibold text-white shadow-sm hover:bg-[#122e4e]"
            >
              <Download className="size-4" />
              Download PDF Report
            </a>
          </div>

          {/* HTML Deliverable */}
          <div className="flex flex-col gap-3 py-4 sm:flex-row sm:items-center">
            <div className="flex size-10 items-center justify-center rounded-xl bg-[#f0fdf4]">
              <FileCode className="size-5 text-[#247c6b]" />
            </div>
            <div className="min-w-0 flex-1">
              <p className="text-sm font-semibold text-[#182230]">
                Interactive HTML Forensic Brief
              </p>
              <p className="mt-0.5 text-xs text-[#8290a2]">
                Stand-alone self-contained HTML deliverable for presentation to stakeholders.
              </p>
            </div>
            <StatusBadge tone="success">HTML</StatusBadge>
            <div className="flex gap-2">
              <a
                href={htmlHref}
                target="_blank"
                rel="noreferrer"
                className="inline-flex items-center gap-1.5 rounded-xl border border-[#d0dbe7] bg-white px-3 py-2 text-xs font-semibold text-[#173b64] hover:bg-[#f7fbff]"
              >
                <ExternalLink className="size-3.5" />
                View HTML
              </a>
              <a
                href={htmlHref}
                download={`SecureMailScope_${session}_report.html`}
                className="inline-flex items-center gap-2 rounded-xl bg-[#173b64] px-3.5 py-2 text-xs font-semibold text-white shadow-sm hover:bg-[#122e4e]"
              >
                <Download className="size-4" />
                Download HTML Report
              </a>
            </div>
          </div>

          {/* Canonical JSON Deliverable */}
          <div className="flex flex-col gap-3 py-4 last:pb-1 sm:flex-row sm:items-center">
            <div className="flex size-10 items-center justify-center rounded-xl bg-[#fff7ed]">
              <FileCode className="size-5 text-[#c2410c]" />
            </div>
            <div className="min-w-0 flex-1">
              <p className="text-sm font-semibold text-[#182230]">Canonical Analysis JSON Schema</p>
              <p className="mt-0.5 text-xs text-[#8290a2]">
                Raw, structured forensic evidence model suitable for SIEM, SOC, or pipeline ingestion.
              </p>
            </div>
            <StatusBadge tone="neutral">JSON</StatusBadge>
            <button
              onClick={downloadJsonDirect}
              className="inline-flex items-center gap-2 rounded-xl border border-[#d0dbe7] bg-white px-3.5 py-2 text-xs font-semibold text-[#173b64] hover:bg-[#f7fbff]"
            >
              <Download className="size-4" />
              Download JSON Report
            </button>

          </div>
        </div>
      </section>

      {/* ── 3. Forensic Report Sections Preview ───────────── */}
      <section className="mt-7 rounded-2xl border border-[#e5eaf1] bg-white p-6 shadow-sm">
        <h2 className="font-bold text-[#182230] mb-4">Complete Forensic Audit Sections</h2>

        {/* Protocol & TLS */}
        <div className="mb-6 rounded-xl border border-[#edf0f5] p-4 bg-[#fbfcfe]">
          <h3 className="text-xs font-bold uppercase tracking-wider text-[#173b64] mb-3">
            1. Protocol &amp; TLS Handshake Analysis
          </h3>
          <div className="grid gap-3 sm:grid-cols-3 text-xs">
            <div>
              <span className="text-[#8290a2] block">Protocol / Port:</span>
              <span className="font-semibold text-[#182230]">
                {analysis.observed.protocol.detected} (Port {analysis.observed.protocol.port})
              </span>
            </div>
            <div>
              <span className="text-[#8290a2] block">STARTTLS State:</span>
              <span className="font-semibold text-[#182230]">
                {evaluated.starttlsAssessment.label}
              </span>
            </div>
            <div>
              <span className="text-[#8290a2] block">TLS Version:</span>
              <span className="font-semibold text-[#182230]">{analysis.observed.tls.version}</span>
            </div>
            <div>
              <span className="text-[#8290a2] block">Cipher Suite:</span>
              <span className="font-mono text-[#182230]">{analysis.observed.tls.cipherSuite}</span>
            </div>
            <div>
              <span className="text-[#8290a2] block">Key Exchange:</span>
              <span className="font-semibold text-[#182230]">
                {analysis.observed.tls.keyExchange} ({analysis.observed.tls.namedGroup})
              </span>
            </div>
            <div>
              <span className="text-[#8290a2] block">Forward Secrecy:</span>
              <span className="font-semibold text-[#182230]">
                {analysis.observed.tls.forwardSecrecy ? 'PFS Active' : 'No PFS'}
              </span>
            </div>
          </div>
        </div>

        {/* Certificate */}
        <div className="mb-6 rounded-xl border border-[#edf0f5] p-4 bg-[#fbfcfe]">
          <h3 className="text-xs font-bold uppercase tracking-wider text-[#173b64] mb-3">
            2. Certificate &amp; Trust Chain Analysis
          </h3>
          <div className="grid gap-3 sm:grid-cols-3 text-xs">
            <div>
              <span className="text-[#8290a2] block">Subject (CN):</span>
              <span className="font-semibold text-[#182230]">
                {analysis.observed.certificate.commonName}
              </span>
            </div>
            <div>
              <span className="text-[#8290a2] block">Issuer:</span>
              <span className="font-semibold text-[#182230]">
                {analysis.observed.certificate.issuer}
              </span>
            </div>
            <div>
              <span className="text-[#8290a2] block">Validity Range:</span>
              <span className="font-semibold text-[#182230]">
                {analysis.observed.certificate.validFrom} to{' '}
                {analysis.observed.certificate.validUntil}
              </span>
            </div>
            <div>
              <span className="text-[#8290a2] block">Public Key:</span>
              <span className="font-semibold text-[#182230]">
                {analysis.observed.certificate.publicKeyAlgorithm}{' '}
                {analysis.observed.certificate.publicKeyLength} bits
              </span>
            </div>
            <div>
              <span className="text-[#8290a2] block">Signature Algorithm:</span>
              <span className="font-semibold text-[#182230]">
                {analysis.observed.certificate.signatureAlgorithm}
              </span>
            </div>
            <div>
              <span className="text-[#8290a2] block">Trust Chain Status:</span>
              <span
                className={`font-semibold ${
                  analysis.observed.certificate.chainValid ? 'text-[#247c6b]' : 'text-[#bb4e4e]'
                }`}
              >
                {analysis.observed.certificate.chainValid ? 'Valid / Trusted' : 'Invalid / Untrusted'}
              </span>
            </div>
          </div>
        </div>

        {/* Cryptographic Strength */}
        <div className="mb-6 rounded-xl border border-[#edf0f5] p-4 bg-[#fbfcfe]">
          <h3 className="text-xs font-bold uppercase tracking-wider text-[#173b64] mb-3">
            3. Cryptographic Strength (NIST SP 800-57)
          </h3>
          <div className="grid gap-2 sm:grid-cols-2 text-xs">
            {evaluated.cryptoStrength.map((item) => (
              <div key={item.component} className="flex justify-between border-b border-[#edf0f5] py-1.5">
                <span className="text-[#607087]">{item.component} ({item.algorithm}):</span>
                <span className="font-bold text-[#182230]">{item.estimatedSecurityStrength}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Findings Summary Table */}
        <div>
          <h3 className="text-xs font-bold uppercase tracking-wider text-[#173b64] mb-3">
            4. Security Findings Included in Deliverables ({analysis.findings.length})
          </h3>
          {analysis.findings.length === 0 ? (
            <p className="text-xs text-[#247c6b]">No security findings identified in this capture.</p>
          ) : (
            <div className="divide-y divide-[#edf0f5] rounded-xl border border-[#edf0f5]">
              {analysis.findings.map((f) => (
                <div key={f.id} className="p-3 text-xs flex items-center justify-between">
                  <div className="min-w-0 flex-1 pr-3">
                    <span className="font-bold text-[#182230]">{f.title}</span>
                    <span className="text-[#8290a2] block mt-0.5 truncate">{f.description}</span>
                  </div>
                  <div className="shrink-0 flex items-center gap-2">
                    <span className="font-mono text-[10px] text-[#8290a2]">{f.id}</span>
                    <StatusBadge
                      tone={
                        f.severity === 'CRITICAL' || f.severity === 'HIGH'
                          ? 'danger'
                          : f.severity === 'MEDIUM'
                          ? 'warning'
                          : 'neutral'
                      }
                    >
                      {f.severity}
                    </StatusBadge>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </section>

      {/* ── 4. AI Interactive Report Assistant ────────────── */}
      <section className="mt-7">
        <ReportAssistant sessionId={session} />
      </section>
    </AppShell>
  )
}

export default function ReportsPage() {
  return (
    <Suspense
      fallback={
        <AppShell>
          <div className="flex h-64 items-center justify-center">
            <Loader2 className="size-8 animate-spin text-[#173b64]" />
          </div>
        </AppShell>
      }
    >
      <ReportsView />
    </Suspense>
  )
}
