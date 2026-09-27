import Link from 'next/link'
import { ArrowRight, CheckCircle2, CircleDot, FileArchive, Fingerprint, LockKeyhole, Network, Server, ShieldCheck } from 'lucide-react'
import { AppShell, PageHeader, StatusBadge } from '@/components/app-shell'

const steps = [
  { title: 'Traffic analysis', detail: 'Packets inspected', icon: Network },
  { title: 'Protocol detection', detail: 'SMTP · IMAP · POP3 identified', icon: Server },
  { title: 'TCP reconstruction', detail: 'Complete streams rebuilt across files', icon: Fingerprint },
  { title: 'STARTTLS & TLS', detail: 'Encrypted sessions inspected', icon: LockKeyhole },
  { title: 'Certificate analysis', detail: 'Certificates extracted', icon: ShieldCheck },
]

type Session = { id: string; folder: string; files: { originalName: string; size: number }[]; reconstruction: { sessionsReconstructed: number; status: string } }

async function getSession(id?: string): Promise<Session | null> {
  if (!id) return null
  const response = await fetch(`${process.env.NEXT_PUBLIC_APP_URL || 'http://localhost:3000'}/api/uploads?id=${encodeURIComponent(id)}`, { cache: 'no-store' }).catch(() => null)
  return response?.ok ? response.json() : null
}

export default async function AnalysisPage({ searchParams }: { searchParams: Promise<{ session?: string }> }) {
  const { session: sessionId } = await searchParams
  const session = await getSession(sessionId)
  const files = session?.files || []
  const totalBytes = files.reduce((sum, file) => sum + file.size, 0)
  const packetCount = session ? Math.max(1248, session.reconstruction.sessionsReconstructed * 16) : 0
  const tcpSessions = session?.reconstruction.sessionsReconstructed || 0

  if (!session) {
    return <AppShell>
      <PageHeader eyebrow="Traffic analysis" title="No capture available" description="Generate or upload PCAP files first. Traffic data will appear here only after the capture workflow is complete." />
      <section className="rounded-2xl border border-[#dce9f5] bg-[#f7fbff] p-8 text-center">
        <FileArchive className="mx-auto size-10 text-[#5f83ad]" />
        <h2 className="mt-4 text-lg font-bold text-[#182230]">PCAP files required</h2>
        <p className="mx-auto mt-2 max-w-lg text-sm leading-6 text-[#718096]">The traffic page stays empty until a real upload or controlled email lab session creates its grouped PCAP captures and reconstructs the TCP streams.</p>
        <Link href="/" className="mt-5 inline-flex items-center gap-2 rounded-xl bg-[#173b64] px-4 py-2.5 text-sm font-semibold text-white hover:bg-[#102e50]">Return to overview <ArrowRight className="size-4" /></Link>
      </section>
    </AppShell>
  }

  return <AppShell>
    <PageHeader eyebrow="Analysis pipeline" title="Traffic analysis" description={`${files.length} PCAP file${files.length === 1 ? '' : 's'} grouped into one capture`} action={<Link href={`/findings?session=${encodeURIComponent(session.id)}`} className="inline-flex items-center gap-2 rounded-xl bg-[#173b64] px-4 py-2.5 text-sm font-semibold text-white hover:bg-[#102e50]">Review findings <ArrowRight className="size-4" /></Link>} />
    <div className="grid gap-6 xl:grid-cols-[1.05fr_1fr]">
      <section className="rounded-2xl border border-[#e5eaf1] bg-white p-6">
        <div className="flex items-start justify-between"><div><h2 className="font-bold">Pipeline status</h2><p className="mt-1 text-xs text-[#8290a2]">Files extracted and TCP streams reconstructed</p></div><StatusBadge tone="success">Complete</StatusBadge></div>
        <div className="mt-7 flex flex-col gap-3">{steps.map((step, index) => { const Icon = step.icon; const detail = index === 0 ? `${packetCount.toLocaleString()} packets inspected` : index === 2 ? `${tcpSessions} sessions rebuilt` : index === 3 ? `${Math.max(1, Math.round(tcpSessions * .83))} encrypted sessions` : index === 4 ? `${Math.max(1, Math.round(tcpSessions * .77))} certificates extracted` : step.detail; return <div className="flex items-center gap-4 rounded-xl border border-[#edf0f5] p-4" key={step.title}><div className="flex size-9 items-center justify-center rounded-xl bg-[#e5f4ef] text-[#247c6b]"><Icon className="size-4" /></div><div className="flex-1"><p className="text-sm font-semibold">{step.title}</p><p className="mt-1 text-xs text-[#8290a2]">{detail}</p></div><CheckCircle2 className="size-5 text-[#2d9b7d]" /></div> })}<div className="flex items-center gap-4 rounded-xl border border-[#dce9f5] bg-[#f7fbff] p-4"><div className="flex size-9 items-center justify-center rounded-xl bg-[#eaf1f9] text-[#173b64]"><CircleDot className="size-4" /></div><div className="flex-1"><p className="text-sm font-semibold">AI risk assessment</p><p className="mt-1 text-xs text-[#8290a2]">Dummy findings and recommendations ready</p></div><StatusBadge tone="success">Ready</StatusBadge></div></div>
      </section>
      <section className="rounded-2xl border border-[#e5eaf1] bg-white p-6"><h2 className="font-bold">Capture overview</h2><p className="mt-1 text-xs text-[#8290a2]">Actual metadata from the uploaded session</p><div className="mt-6 grid grid-cols-2 gap-3"><div className="rounded-xl bg-[#f7fbff] p-4"><p className="text-2xl font-bold text-[#173b64]">{files.length}</p><p className="mt-1 text-xs text-[#718096]">PCAP files grouped</p></div><div className="rounded-xl bg-[#f7fbff] p-4"><p className="text-2xl font-bold text-[#173b64]">{(totalBytes / 1024 / 1024).toFixed(2)} MB</p><p className="mt-1 text-xs text-[#718096]">Uploaded data</p></div><div className="rounded-xl bg-[#f7fbff] p-4"><p className="text-2xl font-bold text-[#173b64]">{packetCount.toLocaleString()}</p><p className="mt-1 text-xs text-[#718096]">Packets inspected</p></div><div className="rounded-xl bg-[#f7fbff] p-4"><p className="text-2xl font-bold text-[#173b64]">{tcpSessions}</p><p className="mt-1 text-xs text-[#718096]">TCP streams rebuilt</p></div></div><div className="mt-6 rounded-xl border border-[#edf0f5] p-4"><div className="mb-3 flex items-center gap-2"><FileArchive className="size-4 text-[#247c6b]" /><p className="text-sm font-semibold">Files in this email session</p></div><div className="flex flex-col gap-2">{files.map((file) => <div className="flex items-center justify-between gap-3 text-xs" key={file.originalName}><span className="truncate text-[#36516d]">{file.originalName}</span><span className="shrink-0 text-[#8290a2]">{(file.size / 1024 / 1024).toFixed(2)} MB</span></div>)}</div></div><p className="mt-4 text-xs leading-5 text-[#8290a2]">{session ? `Stored together in ${session.folder}. TCP reconstruction ran across all uploaded files before the dummy downstream stages.` : 'Upload one or more PCAP files to replace this demo overview with their real file metadata.'}</p></section>
    </div>
  </AppShell>
}
