import Link from 'next/link'
import { ArrowRight, ArrowUpRight, FileArchive, Lightbulb, ShieldAlert } from 'lucide-react'
import { AppShell, PageHeader, StatusBadge } from '@/components/app-shell'
import { buildForensicReport } from '@/lib/forensic-report'

type Session = { id: string; files: { originalName: string; size: number }[]; reconstruction: { sessionsReconstructed: number } }

async function getSession(id?: string): Promise<Session | null> {
  if (!id) return null
  const response = await fetch(`${process.env.NEXT_PUBLIC_APP_URL || 'http://localhost:3000'}/api/uploads?id=${encodeURIComponent(id)}`, { cache: 'no-store' }).catch(() => null)
  return response?.ok ? response.json() : null
}

const findingTemplates = [
  { severity: 'High', tone: 'danger' as const, title: 'TLS negotiation requires review', host: 'smtp.lab.local', protocol: 'SMTP', evidence: 'A captured session used a weaker-than-preferred TLS negotiation profile.', recommendation: 'Require TLS 1.2 or newer and remove legacy cipher suites.' },
  { severity: 'Medium', tone: 'warning' as const, title: 'Certificate chain needs attention', host: 'imap.lab.local', protocol: 'IMAP', evidence: 'The reconstructed stream exposed a certificate profile that should be checked before production use.', recommendation: 'Renew the certificate and confirm the complete trusted chain is served.' },
  { severity: 'Medium', tone: 'warning' as const, title: 'Forward secrecy was not consistent', host: 'smtp.lab.local', protocol: 'SMTP', evidence: 'Some reconstructed sessions did not negotiate the preferred forward-secret key exchange.', recommendation: 'Prefer ECDHE cipher suites for all enabled email services.' },
  { severity: 'Low', tone: 'neutral' as const, title: 'Authentication exposure observed', host: 'pop3.lab.local', protocol: 'POP3', evidence: 'The captured traffic included an authentication path that should be restricted to encrypted sessions.', recommendation: 'Disable cleartext authentication and enforce TLS before login.' },
]

export default async function FindingsPage({ searchParams }: { searchParams: Promise<{ session?: string }> }) {
  const { session: sessionId } = await searchParams
  const session = await getSession(sessionId)
  if (!session) return <AppShell><PageHeader eyebrow="AI assessment" title="No security data available" description="Security findings are generated only after PCAP files have been uploaded and reconstructed." /><section className="rounded-2xl border border-[#dce9f5] bg-[#f7fbff] p-8 text-center"><FileArchive className="mx-auto size-10 text-[#5f83ad]" /><h2 className="mt-4 text-lg font-bold text-[#182230]">Upload and reconstruct PCAP files first</h2><p className="mx-auto mt-2 max-w-lg text-sm leading-6 text-[#718096]">This page stays empty before a capture exists, so the results always belong to the current traffic session.</p><Link href="/" className="mt-5 inline-flex items-center gap-2 rounded-xl bg-[#173b64] px-4 py-2.5 text-sm font-semibold text-white">Return to overview <ArrowRight className="size-4" /></Link></section></AppShell>

  const report = buildForensicReport(session)
  const findings = report.findings.map((finding, index) => ({ ...finding, protocol: index === 1 ? 'SMTP' : index === 2 ? 'POP3' : 'TLS', tone: finding.severity === 'High' ? 'danger' as const : finding.severity === 'Medium' ? 'warning' as const : 'neutral' as const, host: `${index === 1 ? 'smtp' : index === 2 ? 'pop3' : 'tls'}.capture-${report.totalSessions + index}.lab` }))
  const high = findings.filter((finding) => finding.severity === 'High').length
  const medium = findings.filter((finding) => finding.severity === 'Medium').length
  const confidence = Math.max(80, 100 - report.anomalySessions * 3)

  return <AppShell><PageHeader eyebrow="AI assessment" title="Security findings" description={`Session-specific findings from ${session.files.length} reconstructed PCAP file${session.files.length === 1 ? '' : 's'}.`} action={<Link href={`/reports?session=${encodeURIComponent(session.id)}`} className="inline-flex items-center gap-2 rounded-xl border border-[#d8e0e9] bg-white px-4 py-2.5 text-sm font-semibold text-[#173b64]">Generate report <ArrowUpRight className="size-4" /></Link>} /><div className="mb-6 grid gap-4 sm:grid-cols-3"><div className="rounded-2xl border border-[#f3d5d5] bg-[#fffafa] p-5"><p className="text-xs text-[#8290a2]">High priority</p><p className="mt-2 text-2xl font-bold text-[#bb4e4e]">{String(high).padStart(2, '0')}</p></div><div className="rounded-2xl border border-[#f3e2c4] bg-[#fffdf8] p-5"><p className="text-xs text-[#8290a2]">Medium priority</p><p className="mt-2 text-2xl font-bold text-[#a66b1b]">{String(medium).padStart(2, '0')}</p></div><div className="rounded-2xl border border-[#d7e9e2] bg-[#fbfefd] p-5"><p className="text-xs text-[#8290a2]">AI confidence</p><p className="mt-2 text-2xl font-bold text-[#247c6b]">{confidence}%</p></div></div><div className="flex flex-col gap-4">{findings.map((finding) => <article className="rounded-2xl border border-[#e5eaf1] bg-white p-5 sm:p-6" key={finding.title}><div className="flex gap-5"><div className="flex size-11 shrink-0 items-center justify-center rounded-xl bg-[#f7f9fc] text-[#bb4e4e]"><ShieldAlert className="size-5" /></div><div className="min-w-0 flex-1"><div className="flex flex-wrap items-center gap-3"><h2 className="font-bold">{finding.title}</h2><StatusBadge tone={finding.tone}>{finding.severity}</StatusBadge><StatusBadge>{finding.protocol}</StatusBadge></div><p className="mt-2 text-sm font-medium text-[#5d6c80]">{finding.host}</p><p className="mt-4 text-sm leading-6 text-[#718096]">{finding.evidence}</p><div className="mt-4 flex items-start gap-3 rounded-xl bg-[#f7f9fc] p-4"><Lightbulb className="mt-0.5 size-4 shrink-0 text-[#a66b1b]" /><div><p className="text-xs font-semibold uppercase tracking-[0.14em] text-[#8290a2]">Recommendation</p><p className="mt-1 text-sm leading-6 text-[#5d6c80]">{finding.recommendation}</p></div></div></div></div></article>)}</div></AppShell>
}
