'use client'

import { Suspense, useEffect, useState } from 'react'
import Link from 'next/link'
import { useSearchParams } from 'next/navigation'
import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  CircleDot,
  FileArchive,
  Fingerprint,
  Info,
  Loader2,
  LockKeyhole,
  Network,
  Server,
  ShieldAlert,
  ShieldCheck,
  XCircle,
} from 'lucide-react'
import { AppShell, PageHeader, StatusBadge } from '@/components/app-shell'
import type { CanonicalAnalysis, ObservableStatus } from '@/lib/types'
import {
  getStoredAnalysis,
  saveAnalysisSession,
  handlePageLifecycle,
} from '@/lib/analysis-storage'

// ─── Status icon helper ───────────────────────────────────────────────────────

function StatusIcon({ status }: { status: ObservableStatus }) {
  if (status === 'match') return <CheckCircle2 className="size-4 text-[#2d9b7d]" />
  if (status === 'mismatch') return <XCircle className="size-4 text-[#bb4e4e]" />
  if (status === 'not_observable') return <Info className="size-4 text-[#8290a2]" />
  return <CircleDot className="size-4 text-[#8290a2]" />
}

function statusBadgeTone(status: ObservableStatus): 'success' | 'danger' | 'neutral' {
  if (status === 'match') return 'success'
  if (status === 'mismatch') return 'danger'
  return 'neutral'
}

function statusLabel(status: ObservableStatus): string {
  if (status === 'match') return 'MATCH'
  if (status === 'mismatch') return 'MISMATCH'
  if (status === 'not_observable') return 'NOT OBSERVABLE'
  return 'UNAVAILABLE'
}

// ─── Comparison Row ───────────────────────────────────────────────────────────

function ComparisonRow({
  label,
  configured,
  observed,
  status,
}: {
  label: string
  configured: string
  observed: string
  status: ObservableStatus
}) {
  return (
    <div className="grid grid-cols-[1fr_1fr_1fr_auto] gap-3 rounded-xl border border-[#edf0f5] bg-white p-3 text-xs items-center">
      <div className="font-semibold text-[#36516d]">{label}</div>
      <div>
        <span className="text-[9px] uppercase tracking-widest text-[#9aa6b5] block mb-0.5">
          CONFIGURED
        </span>
        <span className="font-mono text-[#173b64] break-all">{configured}</span>
      </div>
      <div>
        <span className="text-[9px] uppercase tracking-widest text-[#9aa6b5] block mb-0.5">
          OBSERVED
        </span>
        <span
          className={`font-mono break-all ${
            observed === 'not_observable'
              ? 'text-[#8290a2] italic'
              : status === 'mismatch'
              ? 'text-[#bb4e4e] font-semibold'
              : 'text-[#173b64]'
          }`}
        >
          {observed === 'not_observable' ? '—' : observed}
        </span>
      </div>
      <div className="flex items-center gap-1.5">
        <StatusIcon status={status} />
        <StatusBadge tone={statusBadgeTone(status)}>{statusLabel(status)}</StatusBadge>
      </div>
    </div>
  )
}

function gradeColor(g: string) {
  if (g === 'A') return 'text-[#247c6b]'
  if (g === 'B') return 'text-[#3b82f6]'
  if (g === 'C') return 'text-[#a66b1b]'
  if (g === 'D') return 'text-[#e07b27]'
  return 'text-[#bb4e4e]'
}

// ─── Analysis View Component ──────────────────────────────────────────────────

function AnalysisView() {
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
          // Fallback to uploads API
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
          // If network fetch fails, fallback to sessionStorage below
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
          <p className="text-sm font-medium text-[#718096]">Loading session traffic analysis…</p>
        </div>
      </AppShell>
    )
  }

  if (!analysis) {
    return (
      <AppShell>
        <PageHeader
          eyebrow="Traffic analysis"
          title="No capture available"
          description="Generate or upload PCAP files first. Traffic data will appear here only after the capture workflow is complete."
        />
        <section className="rounded-2xl border border-[#dce9f5] bg-[#f7fbff] p-8 text-center">
          <FileArchive className="mx-auto size-10 text-[#5f83ad]" />
          <h2 className="mt-4 text-lg font-bold text-[#182230]">PCAP files required</h2>
          <p className="mx-auto mt-2 max-w-lg text-sm leading-6 text-[#718096]">
            The traffic page stays empty until a real upload or controlled email lab session creates
            its grouped PCAP captures and reconstructs the TCP streams.
          </p>
          <div className="mt-5 flex justify-center gap-3">
            <Link
              href="/upload"
              className="inline-flex items-center gap-2 rounded-xl bg-[#173b64] px-4 py-2.5 text-sm font-semibold text-white hover:bg-[#102e50]"
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

  const { capture, observed, configurationComparison: comp, securityScore, findings } = analysis
  const sessionId = analysis.session.id

  return (
    <AppShell>
      <PageHeader
        eyebrow="Analysis pipeline"
        title="Traffic analysis"
        description={`${capture.filename} · ${capture.format} · ${capture.packetCount} packets`}
        action={
          <div className="flex gap-2">
            <Link
              href={`/findings?session=${encodeURIComponent(sessionId)}`}
              className="inline-flex items-center gap-2 rounded-xl bg-[#173b64] px-4 py-2.5 text-sm font-semibold text-white hover:bg-[#102e50]"
            >
              Security Findings <ArrowRight className="size-4" />
            </Link>
            <Link
              href={`/reports?session=${encodeURIComponent(sessionId)}`}
              className="inline-flex items-center gap-2 rounded-xl border border-[#d8e0e9] bg-white px-4 py-2.5 text-sm font-semibold text-[#173b64] hover:bg-[#f7fbff]"
            >
              Report Center
            </Link>
          </div>
        }
      />

      <div className="flex flex-col gap-6">
        {/* ── A. Capture Information ────────────────────── */}
        <section className="rounded-2xl border border-[#e5eaf1] bg-white p-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="font-bold text-[#182230]">A · Capture Information</h2>
            <StatusBadge tone={capture.hasSecureMailScopeMetadata ? 'success' : 'neutral'}>
              {capture.hasSecureMailScopeMetadata ? 'SecureMailScope Capture' : 'External Capture'}
            </StatusBadge>
          </div>
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            {[
              { label: 'Session ID', value: analysis.session.id.slice(0, 24) + '…' },
              { label: 'Capture file', value: capture.filename },
              { label: 'Format', value: capture.format },
              { label: 'Packet count', value: capture.packetCount.toLocaleString() },
              { label: 'Duration', value: `${capture.durationSeconds.toFixed(1)}s` },
              { label: 'Source', value: `${capture.sourceIp}:${capture.sourcePort}` },
              { label: 'Destination', value: `${capture.destinationIp}:${capture.destinationPort}` },
              {
                label: 'Metadata integrity',
                value:
                  capture.metadataIntegrity === 'valid'
                    ? '✅ Valid (hash verified)'
                    : capture.metadataIntegrity === 'missing'
                    ? '— Not available'
                    : `❌ ${capture.metadataIntegrity}`,
              },
            ].map(({ label, value }) => (
              <div key={label} className="rounded-xl bg-[#f7f9fc] p-3">
                <p className="text-[10px] font-bold uppercase tracking-widest text-[#9aa6b5]">
                  {label}
                </p>
                <p className="mt-1.5 text-sm font-medium text-[#182230] break-all">{value}</p>
              </div>
            ))}
          </div>

          {!capture.hasSecureMailScopeMetadata && (
            <div className="mt-4 flex items-start gap-2 rounded-xl border border-[#dce9f5] bg-[#f7fbff] px-4 py-3">
              <Info className="size-4 text-[#5f83ad] mt-0.5 shrink-0" />
              <p className="text-sm text-[#36516d]">
                <strong>Configuration metadata not available in this capture.</strong> This appears
                to be an external PCAP. Only observed values will be shown — no comparison with
                configured values is possible.
              </p>
            </div>
          )}
        </section>

        {/* ── B + C. Protocol + STARTTLS ────────────────── */}
        <div className="grid gap-6 lg:grid-cols-2">
          <section className="rounded-2xl border border-[#e5eaf1] bg-white p-6">
            <h2 className="mb-4 font-bold text-[#182230] flex items-center gap-2">
              <Server className="size-4 text-[#173b64]" />
              B · Protocol Detection
            </h2>
            <div className="flex flex-col gap-3">
              <div className="flex items-center gap-3 rounded-xl bg-[#f7f9fc] p-3">
                <div className="flex size-9 items-center justify-center rounded-xl bg-[#eaf1f9] text-[#173b64]">
                  <Network className="size-4" />
                </div>
                <div>
                  <p className="text-sm font-semibold">{observed.protocol.detected}</p>
                  <p className="text-xs text-[#8290a2]">Port {observed.protocol.port}</p>
                </div>
                <div className="ml-auto">
                  <StatusBadge tone="success">{observed.protocol.confidence} confidence</StatusBadge>
                </div>
              </div>
            </div>
          </section>

          <section className="rounded-2xl border border-[#e5eaf1] bg-white p-6">
            <h2 className="mb-4 font-bold text-[#182230] flex items-center gap-2">
              <LockKeyhole className="size-4 text-[#173b64]" />
              C · Email Security (STARTTLS)
            </h2>
            <div className="flex flex-col gap-2">
              {[
                {
                  label: 'STARTTLS advertised',
                  value: observed.starttls.advertised ? 'Yes' : 'No',
                  ok: observed.starttls.advertised,
                },
                {
                  label: 'STARTTLS negotiated',
                  value: observed.starttls.negotiated ? 'Yes' : 'No',
                  ok: observed.starttls.negotiated,
                },
                {
                  label: 'STARTTLS required',
                  value: observed.starttls.required ? 'Yes' : 'No',
                  ok: observed.starttls.required,
                },
                {
                  label: 'Plaintext phase',
                  value: observed.starttls.plaintextPhaseObserved ? 'Observed' : 'Not observed',
                  ok: !observed.starttls.plaintextPhaseObserved,
                },
                {
                  label: 'Encrypted phase',
                  value: observed.starttls.encryptedPhaseObserved ? 'Observed' : 'Not observed',
                  ok: observed.starttls.encryptedPhaseObserved,
                },
              ].map(({ label, value, ok }) => (
                <div
                  key={label}
                  className="flex items-center justify-between rounded-xl border border-[#edf0f5] px-3 py-2.5 text-xs"
                >
                  <span className="text-[#607087]">{label}</span>
                  <span
                    className={`flex items-center gap-1.5 font-semibold ${
                      ok ? 'text-[#247c6b]' : 'text-[#8290a2]'
                    }`}
                  >
                    {ok ? <CheckCircle2 className="size-3.5" /> : <CircleDot className="size-3.5" />}
                    {value}
                  </span>
                </div>
              ))}
            </div>
          </section>
        </div>

        {/* ── D. TLS Analysis ───────────────────────────── */}
        <section className="rounded-2xl border border-[#e5eaf1] bg-white p-6">
          <h2 className="mb-4 font-bold text-[#182230] flex items-center gap-2">
            <LockKeyhole className="size-4 text-[#173b64]" />
            D · TLS Analysis
          </h2>
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {[
              { label: 'TLS Version', value: observed.tls.version },
              { label: 'Cipher Suite', value: observed.tls.cipherSuite },
              { label: 'Key Exchange', value: observed.tls.keyExchange },
              { label: 'Named Group', value: observed.tls.namedGroup },
              { label: 'Forward Secrecy', value: observed.tls.forwardSecrecy ? 'Yes' : 'No' },
              { label: 'Handshake Complete', value: observed.tls.handshakeComplete ? 'Yes' : 'No' },
              { label: 'ClientHello observed', value: observed.tls.clientHelloObserved ? 'Yes' : 'No' },
              { label: 'ServerHello observed', value: observed.tls.serverHelloObserved ? 'Yes' : 'No' },
            ].map(({ label, value }) => (
              <div key={label} className="rounded-xl bg-[#f7f9fc] p-3">
                <p className="text-[10px] font-bold uppercase tracking-widest text-[#9aa6b5]">
                  {label}
                </p>
                <p className="mt-1.5 text-sm font-semibold text-[#182230] break-all">{value}</p>
              </div>
            ))}
          </div>
        </section>

        {/* ── E. Certificate Analysis ───────────────────── */}
        <section className="rounded-2xl border border-[#e5eaf1] bg-white p-6">
          <h2 className="mb-4 font-bold text-[#182230] flex items-center gap-2">
            <ShieldCheck className="size-4 text-[#173b64]" />
            E · Certificate Analysis
          </h2>
          {!observed.certificate.present ? (
            <div className="rounded-xl border border-[#dce9f5] bg-[#f7fbff] p-4 text-sm text-[#718096]">
              No certificate was observed in the capture. The TLS handshake may be incomplete or the
              capture did not include the Certificate handshake message.
            </div>
          ) : (
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
              {[
                { label: 'Common Name', value: observed.certificate.commonName },
                { label: 'Issuer', value: observed.certificate.issuer },
                { label: 'Valid From', value: observed.certificate.validFrom },
                { label: 'Valid Until', value: observed.certificate.validUntil },
                {
                  label: 'Status',
                  value: observed.certificate.expired
                    ? '❌ Expired'
                    : observed.certificate.notYetValid
                    ? '❌ Not yet valid'
                    : '✅ Valid',
                },
                {
                  label: 'Self-signed',
                  value: observed.certificate.selfSigned ? '⚠️ Yes' : 'No',
                },
                { label: 'Public Key Algorithm', value: observed.certificate.publicKeyAlgorithm },
                {
                  label: 'Public Key Length',
                  value: String(observed.certificate.publicKeyLength) + '-bit',
                },
                { label: 'Signature Algorithm', value: observed.certificate.signatureAlgorithm },
                {
                  label: 'Chain Valid',
                  value: observed.certificate.chainValid ? '✅ Valid' : '❌ Invalid',
                },
              ].map(({ label, value }) => (
                <div key={label} className="rounded-xl bg-[#f7f9fc] p-3">
                  <p className="text-[10px] font-bold uppercase tracking-widest text-[#9aa6b5]">
                    {label}
                  </p>
                  <p className="mt-1.5 text-sm font-semibold text-[#182230] break-all">{value}</p>
                </div>
              ))}
            </div>
          )}
        </section>

        {/* ── F. Configuration Comparison ───────────────── */}
        {comp && (
          <section className="rounded-2xl border border-[#e5eaf1] bg-white p-6">
            <div className="flex items-center justify-between mb-4">
              <h2 className="font-bold text-[#182230] flex items-center gap-2">
                <Fingerprint className="size-4 text-[#173b64]" />
                F · Configuration vs Observed Comparison
              </h2>
              <StatusBadge tone={comp.overallStatus === 'consistent' ? 'success' : 'danger'}>
                {comp.overallStatus === 'consistent' ? 'CONSISTENT' : 'CONFIGURATION MISMATCH'}
              </StatusBadge>
            </div>

            {comp.mismatches.length > 0 && (
              <div className="mb-4 flex items-start gap-2 rounded-xl border border-[#f3d5d5] bg-[#fffafa] px-4 py-3">
                <AlertTriangle className="size-4 text-[#bb4e4e] mt-0.5 shrink-0" />
                <p className="text-sm text-[#bb4e4e]">
                  <strong>{comp.mismatches.length} mismatch(es) detected:</strong>{' '}
                  {comp.mismatches.join(', ')}
                </p>
              </div>
            )}

            <div className="mb-3 grid grid-cols-[1fr_1fr_1fr_auto] gap-3 px-3 text-[10px] font-bold uppercase tracking-widest text-[#9aa6b5]">
              <span>Field</span>
              <span>Configured</span>
              <span>Observed</span>
              <span>Status</span>
            </div>

            <div className="flex flex-col gap-2">
              <ComparisonRow label="TLS Version" {...comp.tlsVersion} />
              <ComparisonRow label="Cipher Suite" {...comp.cipherSuite} />
              <ComparisonRow label="Key Exchange" {...comp.keyExchange} />
              <ComparisonRow label="Named Group" {...comp.namedGroup} />
              <ComparisonRow label="Forward Secrecy" {...comp.forwardSecrecy} />
              <ComparisonRow label="STARTTLS" {...comp.starttls} />
              <ComparisonRow label="STARTTLS Required" {...comp.starttlsRequired} />
              <ComparisonRow label="Certificate Expiry" {...comp.certExpired} />
              <ComparisonRow label="Certificate Chain" {...comp.certChainValid} />
              {comp.certCommonName.status !== 'not_observable' && (
                <ComparisonRow label="Common Name" {...comp.certCommonName} />
              )}
              {comp.publicKeyAlgorithm.status !== 'not_observable' && (
                <ComparisonRow label="Public Key Algorithm" {...comp.publicKeyAlgorithm} />
              )}
              {comp.signatureAlgorithm.status !== 'not_observable' && (
                <ComparisonRow label="Signature Algorithm" {...comp.signatureAlgorithm} />
              )}
            </div>

            <p className="mt-4 text-xs text-[#8290a2]">
              <strong>CONFIGURED</strong> = values embedded in the SecureMailScope capture manifest
              (AES-256-GCM encrypted). <strong>OBSERVED</strong> = values extracted from actual packet
              data. <strong>NOT OBSERVABLE</strong> = value not extractable from encrypted traffic.
            </p>
          </section>
        )}

        {/* ── G. Security Score Preview ─────────────────── */}
        <section className="rounded-2xl border border-[#e5eaf1] bg-white p-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="font-bold text-[#182230] flex items-center gap-2">
              <ShieldAlert className="size-4 text-[#173b64]" />
              G · Security Score Preview
            </h2>
            <Link
              href={`/findings?session=${encodeURIComponent(sessionId)}`}
              className="inline-flex items-center gap-2 rounded-xl border border-[#d8e0e9] px-3 py-2 text-xs font-semibold text-[#173b64] hover:bg-[#f7fbff]"
            >
              Full findings <ArrowRight className="size-3" />
            </Link>
          </div>

          <div className="grid gap-4 sm:grid-cols-[auto_1fr]">
            <div className="flex flex-col items-center justify-center rounded-2xl bg-[#f7f9fc] px-8 py-6">
              <p className={`text-6xl font-black ${gradeColor(securityScore.grade)}`}>
                {securityScore.grade}
              </p>
              <p className="mt-1 text-2xl font-bold text-[#182230]">{securityScore.total}</p>
              <p className="text-xs text-[#8290a2]">{securityScore.level}</p>
            </div>
            <div className="flex flex-col gap-2">
              {securityScore.deductions.slice(0, 5).map((d, i) => (
                <div
                  key={i}
                  className="flex items-center gap-3 rounded-xl border border-[#edf0f5] px-3 py-2.5 text-xs"
                >
                  <span
                    className={`shrink-0 rounded-full px-2 py-0.5 font-bold text-[10px] ${
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
                  <span className="flex-1 text-[#607087]">{d.reason}</span>
                  <span className="shrink-0 font-mono font-semibold text-[#bb4e4e]">−{d.points}</span>
                </div>
              ))}
              {securityScore.deductions.length > 5 && (
                <p className="text-xs text-[#8290a2] text-center">
                  +{securityScore.deductions.length - 5} more deductions — see findings page
                </p>
              )}
              {findings.length === 0 && (
                <div className="flex items-center gap-2 rounded-xl bg-[#f0faf6] px-3 py-2.5 text-xs text-[#247c6b]">
                  <CheckCircle2 className="size-4" />
                  No security issues detected
                </div>
              )}
            </div>
          </div>
        </section>
      </div>
    </AppShell>
  )
}

export default function AnalysisPage() {
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
      <AnalysisView />
    </Suspense>
  )
}
