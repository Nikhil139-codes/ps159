'use client'

import { Suspense, useEffect, useState } from 'react'
import Link from 'next/link'
import { useSearchParams } from 'next/navigation'
import {
  AlertTriangle,
  ArrowRight,
  ArrowUpRight,
  CheckCircle2,
  ExternalLink,
  FileArchive,
  Info,
  Lightbulb,
  Loader2,
  LockKeyhole,
  Scale,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  XCircle,
} from 'lucide-react'
import { AppShell, PageHeader, StatusBadge } from '@/components/app-shell'
import type { CanonicalAnalysis, FindingSeverity } from '@/lib/types'
import {
  getStoredAnalysis,
  saveAnalysisSession,
  handlePageLifecycle,
} from '@/lib/analysis-storage'
import {
  evaluateSecurityRules,
  type SecurityRuleResult,
  type CategorySummary,
  type CryptoStrengthItem,
  type ConfigAssessmentRow,
} from '@/lib/security-rules'

// ─── Severity helpers ─────────────────────────────────────────────────────────

function severityTone(s: FindingSeverity): 'danger' | 'warning' | 'neutral' {
  if (s === 'CRITICAL' || s === 'HIGH') return 'danger'
  if (s === 'MEDIUM') return 'warning'
  return 'neutral'
}

function SeverityIcon({ severity }: { severity: FindingSeverity }) {
  if (severity === 'CRITICAL' || severity === 'HIGH')
    return <ShieldAlert className="size-5 text-[#bb4e4e]" />
  if (severity === 'MEDIUM') return <AlertTriangle className="size-5 text-[#a66b1b]" />
  if (severity === 'LOW') return <Info className="size-5 text-[#5f83ad]" />
  return <CheckCircle2 className="size-5 text-[#247c6b]" />
}

function gradeColor(g: string) {
  if (g === 'A') return 'text-[#247c6b]'
  if (g === 'B') return 'text-[#3b82f6]'
  if (g === 'C') return 'text-[#a66b1b]'
  if (g === 'D') return 'text-[#e07b27]'
  return 'text-[#bb4e4e]'
}

function categoryStatusBadge(status: 'PASS' | 'WARNING' | 'FAIL' | 'NOT_OBSERVABLE') {
  if (status === 'PASS') return <StatusBadge tone="success">PASS</StatusBadge>
  if (status === 'WARNING') return <StatusBadge tone="warning">WARNING</StatusBadge>
  if (status === 'FAIL') return <StatusBadge tone="danger">FAIL</StatusBadge>
  return <StatusBadge tone="neutral">NOT OBSERVABLE</StatusBadge>
}

// ─── Findings View Component ──────────────────────────────────────────────────

function FindingsView() {
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

  if (loading) {
    return (
      <AppShell>
        <div className="flex h-64 flex-col items-center justify-center gap-3">
          <Loader2 className="size-8 animate-spin text-[#173b64]" />
          <p className="text-sm font-medium text-[#718096]">
            Evaluating security rules & cryptographic posture…
          </p>
        </div>
      </AppShell>
    )
  }

  if (!analysis) {
    return (
      <AppShell>
        <PageHeader
          eyebrow="Security assessment"
          title="No security data available"
          description="Security findings are generated only after PCAP files have been uploaded or generated."
        />
        <section className="rounded-2xl border border-[#dce9f5] bg-[#f7fbff] p-8 text-center">
          <FileArchive className="mx-auto size-10 text-[#5f83ad]" />
          <h2 className="mt-4 text-lg font-bold text-[#182230]">
            Upload and reconstruct PCAP files first
          </h2>
          <p className="mx-auto mt-2 max-w-lg text-sm leading-6 text-[#718096]">
            This page stays empty before a capture exists, so the results always belong to the
            current traffic session.
          </p>
          <div className="mt-5 flex justify-center gap-3">
            <Link
              href="/upload"
              className="inline-flex items-center gap-2 rounded-xl bg-[#173b64] px-4 py-2.5 text-sm font-semibold text-white"
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

  const { findings, anomalies, securityScore, aiAssessment, recommendations, configured } = analysis
  const sessionId = analysis.session.id

  // Evaluate the centralized cryptographic security rules engine
  const evaluated = evaluateSecurityRules({
    configured: analysis.configured,
    observed: analysis.observed,
    configurationComparison: analysis.configurationComparison,
    capture: analysis.capture,
  })

  const critical = findings.filter((f) => f.severity === 'CRITICAL').length
  const high = findings.filter((f) => f.severity === 'HIGH').length
  const medium = findings.filter((f) => f.severity === 'MEDIUM').length
  const low = findings.filter((f) => f.severity === 'LOW' || f.severity === 'INFO').length

  return (
    <AppShell>
      <PageHeader
        eyebrow="Security assessment"
        title="Security findings & posture"
        description={`${findings.length} finding${
          findings.length === 1 ? '' : 's'
        } — deterministic evaluation grounded in NIST SP 800-52 Rev. 2, NIST SP 800-57, and RFC standards.`}
        action={
          <div className="flex gap-2">
            <Link
              href={`/reports?session=${encodeURIComponent(sessionId)}`}
              className="inline-flex items-center gap-2 rounded-xl bg-[#173b64] px-4 py-2.5 text-sm font-semibold text-white shadow-sm hover:bg-[#122e4e]"
            >
              Generate report <ArrowUpRight className="size-4" />
            </Link>
            <Link
              href={`/analysis?session=${encodeURIComponent(sessionId)}`}
              className="inline-flex items-center gap-2 rounded-xl border border-[#d8e0e9] bg-white px-4 py-2.5 text-sm font-semibold text-[#173b64] hover:bg-[#f7fbff]"
            >
              Traffic analysis
            </Link>
          </div>
        }
      />

      {/* ── 1. Overall Security Risk Score ────────────────── */}
      <div className="mb-8 grid gap-4 sm:grid-cols-2 lg:grid-cols-5">
        <div className="rounded-2xl border border-[#e5eaf1] bg-white p-5 flex flex-col items-center justify-center lg:col-span-1 shadow-sm">
          <p className="text-[10px] font-bold uppercase tracking-widest text-[#8290a2]">
            SECURITY SCORE
          </p>
          <p className={`mt-1 text-5xl font-black ${gradeColor(securityScore.grade)}`}>
            {securityScore.grade}
          </p>
          <p className="mt-1 text-2xl font-bold text-[#182230]">{securityScore.total} / 100</p>
          <div className="mt-2">
            <span
              className={`rounded-full px-2.5 py-0.5 text-xs font-bold ${
                securityScore.total >= 80
                  ? 'bg-[#e5f4ef] text-[#247c6b]'
                  : securityScore.total >= 60
                  ? 'bg-[#fff1df] text-[#a66b1b]'
                  : 'bg-[#fdeaea] text-[#bb4e4e]'
              }`}
            >
              RISK: {securityScore.level.toUpperCase()}
            </span>
          </div>
        </div>
        <div className="rounded-2xl border border-[#f3d5d5] bg-[#fffafa] p-5 shadow-sm">
          <p className="text-xs font-semibold text-[#bb4e4e]">CRITICAL SEVERITY</p>
          <p className="mt-2 text-3xl font-extrabold text-[#bb4e4e]">
            {String(critical).padStart(2, '0')}
          </p>
          <p className="mt-1 text-xs text-[#8290a2]">Requires immediate remediation</p>
        </div>
        <div className="rounded-2xl border border-[#f3d5d5] bg-[#fffafa] p-5 shadow-sm">
          <p className="text-xs font-semibold text-[#bb4e4e]">HIGH SEVERITY</p>
          <p className="mt-2 text-3xl font-extrabold text-[#bb4e4e]">
            {String(high).padStart(2, '0')}
          </p>
          <p className="mt-1 text-xs text-[#8290a2]">Deprecated protocols or weak keys</p>
        </div>
        <div className="rounded-2xl border border-[#f3e2c4] bg-[#fffdf8] p-5 shadow-sm">
          <p className="text-xs font-semibold text-[#a66b1b]">MEDIUM SEVERITY</p>
          <p className="mt-2 text-3xl font-extrabold text-[#a66b1b]">
            {String(medium).padStart(2, '0')}
          </p>
          <p className="mt-1 text-xs text-[#8290a2]">Configuration or PFS warnings</p>
        </div>
        <div className="rounded-2xl border border-[#edf1f5] bg-[#f9fafb] p-5 shadow-sm">
          <p className="text-xs font-semibold text-[#64748b]">LOW / INFO</p>
          <p className="mt-2 text-3xl font-extrabold text-[#64748b]">
            {String(low).padStart(2, '0')}
          </p>
          <p className="mt-1 text-xs text-[#8290a2]">Informational & hardening notes</p>
        </div>
      </div>

      {/* ── 2. AI Assessment & Fallback ───────────────────── */}
      <section className="mb-8 rounded-2xl border border-[#e5eaf1] bg-white p-6 shadow-sm">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-2">
            <Sparkles className="size-5 text-[#2d8d78]" />
            <h2 className="font-bold text-[#182230]">AI Forensic Assessment (Groq)</h2>
          </div>
          <StatusBadge tone={aiAssessment?.available ? 'success' : 'neutral'}>
            {aiAssessment?.available ? 'GROQ ONLINE' : 'DETERMINISTIC FALLBACK'}
          </StatusBadge>
        </div>

        {aiAssessment?.available ? (
          <div className="flex flex-col gap-3">
            <p className="text-sm leading-6 text-[#34455a] font-medium">
              {aiAssessment.executiveSummary}
            </p>
            {aiAssessment.riskNarrative && (
              <p className="text-xs italic text-[#718096] bg-[#f8fbfe] p-3 rounded-xl border border-[#e2eaf4]">
                {aiAssessment.riskNarrative}
              </p>
            )}
            {aiAssessment.prioritizedFindings && aiAssessment.prioritizedFindings.length > 0 && (
              <div className="mt-2">
                <p className="text-xs font-bold uppercase tracking-wider text-[#173b64] mb-1.5">
                  Prioritized AI Findings:
                </p>
                <ul className="list-disc pl-5 text-xs text-[#526477] space-y-1">
                  {aiAssessment.prioritizedFindings.map((item, idx) => (
                    <li key={idx}>{item}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        ) : (
          <div className="flex items-start gap-3 rounded-xl border border-[#dce9f5] bg-[#f7fbff] p-4 text-xs text-[#36516d]">
            <Info className="size-5 text-[#5f83ad] shrink-0 mt-0.5" />
            <div>
              <p className="font-semibold text-[#182230]">
                AI assessment unavailable. Showing deterministic security assessment.
              </p>
              <p className="mt-1 leading-5 text-[#607087]">
                Deterministic cryptographic rules and NIST SP 800-52 / 800-57 guidelines are fully
                active. To enable natural-language AI insights, add your{' '}
                <code className="rounded bg-[#eaf1f9] px-1 font-mono text-[#173b64]">
                  GROQ_API_KEY
                </code>{' '}
                to <code className="rounded bg-[#eaf1f9] px-1 font-mono text-[#173b64]">local.env</code>.
              </p>
            </div>
          </div>
        )}
      </section>

      {/* ── 3. 17 Security Assessment Categories ──────────── */}
      <section className="mb-8 rounded-2xl border border-[#e5eaf1] bg-white p-6 shadow-sm">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h2 className="font-bold text-[#182230]">
              Cryptographic Posture Across 17 Security Categories
            </h2>
            <p className="text-xs text-[#8290a2] mt-0.5">
              Standard-aligned posture validation covering protocol, cipher, certificate, and STARTTLS
              states.
            </p>
          </div>
          <Scale className="size-5 text-[#173b64]" />
        </div>

        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {evaluated.categorySummaries.map((cat, idx) => (
            <div
              key={cat.category}
              className={`rounded-xl border p-4 transition-all ${
                cat.status === 'FAIL'
                  ? 'border-[#f3d5d5] bg-[#fffafa]'
                  : cat.status === 'WARNING'
                  ? 'border-[#f3e2c4] bg-[#fffdf8]'
                  : cat.status === 'PASS'
                  ? 'border-[#dcefe7] bg-[#f7fcf9]'
                  : 'border-[#edf0f5] bg-[#f8fbfe]'
              }`}
            >
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-[#182230]">
                  {idx + 1}. {cat.category}
                </span>
                {categoryStatusBadge(cat.status)}
              </div>
              <p className="mt-2 text-xs leading-5 text-[#607087] line-clamp-2">{cat.details}</p>
            </div>
          ))}
        </div>
      </section>

      {/* ── 4. Cryptographic Configuration Assessment ────── */}
      <section className="mb-8 rounded-2xl border border-[#e5eaf1] bg-white p-6 shadow-sm">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h2 className="font-bold text-[#182230]">
              Cryptographic Configuration Assessment (Configured vs Observed)
            </h2>
            <p className="text-xs text-[#8290a2] mt-0.5">
              Distinguishes administrative policy intent from actual wire-level observations.
            </p>
          </div>
          <LockKeyhole className="size-5 text-[#173b64]" />
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-[#edf0f5] bg-[#f7f9fc] text-[10px] font-bold uppercase tracking-wider text-[#8290a2]">
                <th className="py-2.5 px-3">Parameter</th>
                <th className="py-2.5 px-3">Configured (Manifest)</th>
                <th className="py-2.5 px-3">Observed (Wire Capture)</th>
                <th className="py-2.5 px-3">Status</th>
                <th className="py-2.5 px-3">Standard Reference</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#edf0f5]">
              {evaluated.configAssessment.map((row) => (
                <tr key={row.parameter} className="hover:bg-[#fbfcfe]">
                  <td className="py-2.5 px-3 font-semibold text-[#182230]">{row.parameter}</td>
                  <td className="py-2.5 px-3 font-mono text-[#607087]">{row.configured}</td>
                  <td
                    className={`py-2.5 px-3 font-mono ${
                      row.status === 'MISMATCH' || row.status === 'FAIL'
                        ? 'font-bold text-[#bb4e4e]'
                        : 'text-[#182230]'
                    }`}
                  >
                    {row.observed}
                  </td>
                  <td className="py-2.5 px-3">
                    <StatusBadge
                      tone={
                        row.status === 'MATCH' || row.status === 'PASS'
                          ? 'success'
                          : row.status === 'MISMATCH' || row.status === 'FAIL'
                          ? 'danger'
                          : row.status === 'WARNING'
                          ? 'warning'
                          : 'neutral'
                      }
                    >
                      {row.status}
                    </StatusBadge>
                  </td>
                  <td className="py-2.5 px-3 text-[#718096]">{row.standardReference}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {/* ── 5. Cryptographic Security Strength (NIST SP 800-57) ── */}
      <section className="mb-8 rounded-2xl border border-[#e5eaf1] bg-white p-6 shadow-sm">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h2 className="font-bold text-[#182230]">
              Cryptographic Security Strength Assessment (NIST SP 800-57 Part 1 Rev. 5)
            </h2>
            <p className="text-xs text-[#8290a2] mt-0.5">
              Assesses equivalent bits of security for asymmetric keys, bulk ciphers, and hash functions.
            </p>
          </div>
          <ShieldCheck className="size-5 text-[#247c6b]" />
        </div>

        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          {evaluated.cryptoStrength.map((item) => (
            <div
              key={item.component}
              className={`rounded-xl border p-4 ${
                item.status === 'DEPRECATED'
                  ? 'border-[#f3d5d5] bg-[#fffafa]'
                  : item.status === 'STRONG'
                  ? 'border-[#dcefe7] bg-[#f7fcf9]'
                  : 'border-[#edf0f5] bg-white'
              }`}
            >
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-[#182230]">{item.component}</span>
                <StatusBadge
                  tone={
                    item.status === 'STRONG'
                      ? 'success'
                      : item.status === 'DEPRECATED'
                      ? 'danger'
                      : 'neutral'
                  }
                >
                  {item.status}
                </StatusBadge>
              </div>
              <p className="mt-2 font-mono text-sm font-bold text-[#182230]">{item.algorithm}</p>
              <p className="text-xs text-[#718096]">{item.parameter}</p>
              <div className="mt-3 rounded-lg bg-black/5 p-2 text-[11px]">
                <span className="text-[#8290a2] block">Security Strength:</span>
                <span className="font-bold text-[#173b64]">{item.estimatedSecurityStrength}</span>
              </div>
              <p className="mt-2 text-[10px] text-[#8290a2]">{item.source}</p>
            </div>
          ))}
        </div>
      </section>

      {/* ── 6. STARTTLS State Assessment ──────────────────── */}
      <section className="mb-8 rounded-2xl border border-[#e5eaf1] bg-white p-6 shadow-sm">
        <h2 className="font-bold text-[#182230] mb-2 flex items-center gap-2">
          <LockKeyhole className="size-4 text-[#173b64]" />
          STARTTLS Protocol State Assessment
        </h2>
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 rounded-xl border border-[#dce9f5] bg-[#f8fbfe] p-4">
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-bold text-[#8290a2]">DETECTED STATE:</span>
              <span
                className={`font-mono text-xs font-bold px-2 py-0.5 rounded-full ${
                  evaluated.starttlsAssessment.state === 'SECURE_UPGRADE'
                    ? 'bg-[#e5f4ef] text-[#247c6b]'
                    : evaluated.starttlsAssessment.state === 'STARTTLS_ADVERTISED_NOT_USED'
                    ? 'bg-[#fdeaea] text-[#bb4e4e]'
                    : 'bg-[#fff1df] text-[#a66b1b]'
                }`}
              >
                {evaluated.starttlsAssessment.label}
              </span>
            </div>
            <p className="mt-2 text-xs leading-5 text-[#475569]">
              {evaluated.starttlsAssessment.description}
            </p>
          </div>
          <div className="shrink-0 text-right">
            <span className="text-[10px] font-bold uppercase tracking-wider text-[#8290a2] block">
              Reference
            </span>
            <span className="text-xs text-[#173b64] font-medium">
              {evaluated.starttlsAssessment.reference}
            </span>
          </div>
        </div>
      </section>

      {/* ── 7. Score Deductions Breakdown ─────────────────── */}
      <section className="mb-8 rounded-2xl border border-[#e5eaf1] bg-white p-6 shadow-sm">
        <h2 className="mb-3 font-bold text-[#182230]">Score Impact & Deductions Summary</h2>
        <div className="flex flex-col gap-2">
          {securityScore.deductions.length === 0 ? (
            <div className="flex items-center gap-2 rounded-xl bg-[#f0faf6] px-4 py-3 text-sm text-[#247c6b]">
              <CheckCircle2 className="size-5" />
              Zero deductions — flawless cryptographic implementation
            </div>
          ) : (
            securityScore.deductions.map((d, i) => (
              <div
                key={i}
                className="grid grid-cols-[auto_1fr_auto] gap-3 rounded-xl border border-[#edf0f5] px-4 py-3 items-center text-xs"
              >
                <span
                  className={`rounded-full px-2 py-0.5 text-[10px] font-bold ${
                    d.severity === 'CRITICAL'
                      ? 'bg-[#fdeaea] text-[#bb4e4e]'
                      : d.severity === 'HIGH'
                      ? 'bg-[#fff1df] text-[#a66b1b]'
                      : d.severity === 'MEDIUM'
                      ? 'bg-[#fff8e1] text-[#9a6400]'
                      : 'bg-[#edf1f5] text-[#64748b]'
                  }`}
                >
                  {d.severity}
                </span>
                <span className="text-[#607087] font-medium">{d.reason}</span>
                <span className="font-mono font-bold text-[#bb4e4e]">−{d.points} pts</span>
              </div>
            ))
          )}
        </div>
      </section>

      {/* ── 8. Anomalies ─────────────────────────────────── */}
      {anomalies.length > 0 && (
        <section className="mb-8 rounded-2xl border border-[#f3d5d5] bg-white p-6 shadow-sm">
          <h2 className="mb-4 font-bold text-[#bb4e4e] flex items-center gap-2">
            <AlertTriangle className="size-5" />
            Detected Anomalies ({anomalies.length})
          </h2>
          <div className="flex flex-col gap-3">
            {anomalies.map((anomaly, i) => (
              <div key={i} className="rounded-xl border border-[#f3d5d5] bg-[#fffafa] px-4 py-3">
                <div className="flex items-center gap-3">
                  <StatusBadge tone="danger">{anomaly.type}</StatusBadge>
                  <StatusBadge tone={anomaly.severity === 'HIGH' ? 'danger' : 'warning'}>
                    {anomaly.severity}
                  </StatusBadge>
                </div>
                <p className="mt-2 text-sm text-[#607087]">{anomaly.evidence}</p>
                {anomaly.configured && (
                  <p className="mt-1 text-xs text-[#8290a2]">
                    Configured: <span className="font-mono">{anomaly.configured}</span> → Observed:{' '}
                    <span className="font-mono text-[#bb4e4e]">{anomaly.observed}</span>
                  </p>
                )}
              </div>
            ))}
          </div>
        </section>
      )}

      {/* ── 9. Structured Security Findings ───────────────── */}
      <section className="mb-8">
        <div className="flex items-center justify-between mb-4">
          <h2 className="font-bold text-[#182230] text-lg">
            Detailed Security Findings ({findings.length})
          </h2>
          <span className="text-xs text-[#8290a2]">
            Evidence-backed cryptographic evaluations with standard references
          </span>
        </div>

        {findings.length === 0 ? (
          <div className="rounded-2xl border border-[#d7e9e2] bg-[#fbfefd] p-8 text-center">
            <ShieldCheck className="mx-auto size-10 text-[#2d9b7d]" />
            <h3 className="mt-4 font-bold text-[#182230]">No security issues detected</h3>
            <p className="mt-2 text-sm text-[#718096]">
              The capture passed all deterministic security checks.
            </p>
          </div>
        ) : (
          <div className="flex flex-col gap-4">
            {findings.map((finding) => (
              <article
                key={finding.id}
                className="rounded-2xl border border-[#e5eaf1] bg-white p-5 sm:p-6 shadow-sm"
              >
                <div className="flex gap-5">
                  <div
                    className={`flex size-11 shrink-0 items-center justify-center rounded-xl ${
                      finding.severity === 'CRITICAL' || finding.severity === 'HIGH'
                        ? 'bg-[#fdeaea]'
                        : finding.severity === 'MEDIUM'
                        ? 'bg-[#fff1df]'
                        : 'bg-[#f7f9fc]'
                    }`}
                  >
                    <SeverityIcon severity={finding.severity} />
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <h3 className="font-bold text-[#182230]">{finding.title}</h3>
                      <StatusBadge tone={severityTone(finding.severity)}>
                        {finding.severity}
                      </StatusBadge>
                      <StatusBadge>{finding.category}</StatusBadge>
                      <span className="text-[10px] font-mono text-[#9aa6b5]">{finding.id}</span>
                    </div>

                    <p className="mt-3 text-sm leading-6 text-[#718096]">{finding.description}</p>

                    {/* Standard Reference Link */}
                    <div className="mt-3 flex items-center gap-2 rounded-xl bg-[#f0f4f8] px-3 py-2 text-xs text-[#173b64]">
                      <Scale className="size-4 text-[#2d8d78] shrink-0" />
                      <span className="font-semibold">Standard Source:</span>
                      <span>
                        {finding.category === 'TLS'
                          ? 'RFC 8996 / NIST SP 800-52 Rev. 2 Section 3.1'
                          : finding.category === 'Cipher'
                          ? 'NIST SP 800-52 Rev. 2 Section 3.3.1'
                          : finding.category === 'Certificate'
                          ? 'CA/Browser Forum Baseline Requirements Section 6.1.5'
                          : finding.category === 'STARTTLS'
                          ? 'RFC 3207 / NIST SP 800-52 Rev. 2'
                          : finding.category === 'PFS' || finding.category === 'KeyExchange'
                          ? 'NIST SP 800-52 Rev. 2 Section 3.3.2 / CISA Guidance'
                          : 'NIST SP 800-57 Part 1 Rev. 5'}
                      </span>
                    </div>

                    {/* Evidence Box */}
                    <div className="mt-3 rounded-xl border border-[#edf0f5] bg-[#f7f9fc] p-3">
                      <p className="text-[10px] font-bold uppercase tracking-widest text-[#9aa6b5] mb-1">
                        Observed Evidence
                      </p>
                      <code className="text-xs text-[#36516d] break-all font-mono">
                        {typeof finding.evidence === 'string'
                          ? finding.evidence
                          : JSON.stringify(finding.evidence)}
                      </code>
                    </div>

                    {/* Impact */}
                    <p className="mt-3 text-xs text-[#718096]">
                      <strong className="text-[#607087]">Impact:</strong> {finding.impact}
                    </p>

                    {/* Recommendation */}
                    <div className="mt-3 flex items-start gap-3 rounded-xl bg-[#f7f9fc] p-4 border border-[#eaf0f6]">
                      <Lightbulb className="mt-0.5 size-4 shrink-0 text-[#a66b1b]" />
                      <div>
                        <p className="text-xs font-semibold uppercase tracking-[0.14em] text-[#8290a2]">
                          Remediation Recommendation
                        </p>
                        <p className="mt-1 text-sm leading-6 text-[#5d6c80]">
                          {finding.recommendation}
                        </p>
                      </div>
                    </div>
                  </div>
                </div>
              </article>
            ))}
          </div>
        )}
      </section>

      {/* ── 10. Top Remediation Recommendations ──────────── */}
      {recommendations.length > 0 && (
        <section className="mb-8 rounded-2xl border border-[#e5eaf1] bg-white p-6 shadow-sm">
          <h2 className="mb-4 font-bold text-[#182230]">Prioritized Remediation Actions</h2>
          <ol className="flex flex-col gap-3">
            {recommendations.map((rec, i) => (
              <li key={i} className="flex items-start gap-3 text-sm">
                <span className="flex size-6 shrink-0 items-center justify-center rounded-full bg-[#173b64] text-[10px] font-bold text-white">
                  {i + 1}
                </span>
                <span className="text-[#607087] leading-6">{rec}</span>
              </li>
            ))}
          </ol>
        </section>
      )}

      {/* ── 11. Configuration Source Provenance ───────────── */}
      {configured && (
        <section className="rounded-2xl border border-[#dce9f5] bg-[#f7fbff] p-4 text-xs text-[#607087]">
          <p>
            <strong>Configuration Source:</strong> SecureMailScope Email Lab (AES-256-GCM encrypted
            manifest embedded in PCAPNG Custom Block) &bull;{' '}
            <strong>Scenario:</strong> {configured.testScenario} &bull;{' '}
            <strong>Generator:</strong> {configured.metadata.generatorVersion} &bull;{' '}
            <strong>Session ID:</strong> {configured.sessionId}
          </p>
        </section>
      )}
    </AppShell>
  )
}

export default function FindingsPage() {
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
      <FindingsView />
    </Suspense>
  )
}
