import Link from 'next/link'
import { Download, FileArchive, FileText, ShieldCheck } from 'lucide-react'
import { AppShell, PageHeader, StatusBadge } from '@/components/app-shell'
import { ReportAssistant } from '@/components/report-assistant'

export default async function ReportsPage({ searchParams }: { searchParams: Promise<{ session?: string }> }) {
  const { session } = await searchParams
  const reportHref = session ? `/api/reports/demo-pdf?session=${encodeURIComponent(session)}` : undefined

  return <AppShell>
    <PageHeader eyebrow="Deliverables" title="Forensic reports" description="Download the PDF generated from the current reconstructed capture." />
    {!session ? <section className="mt-7 rounded-2xl border border-[#dce9f5] bg-[#f7fbff] p-8 text-center">
      <FileArchive className="mx-auto size-10 text-[#5f83ad]" />
      <h2 className="mt-4 text-lg font-bold text-[#182230]">No report available</h2>
      <p className="mx-auto mt-2 max-w-lg text-sm leading-6 text-[#718096]">Upload and reconstruct a PCAP capture first. Reports stay empty until security analysis has data from that capture.</p>
      <Link href="/upload" className="mt-5 inline-flex items-center gap-2 rounded-xl bg-[#173b64] px-4 py-2.5 text-sm font-semibold text-white">Upload PCAP</Link>
    </section> : <>
      <section className="mt-7 rounded-2xl border border-[#e5eaf1] bg-white p-6">
        <div className="flex items-center justify-between"><div><h2 className="font-bold">Report center</h2><p className="mt-1 text-xs text-[#8290a2]">Generated from the reconstructed traffic workspace</p></div><ShieldCheck className="size-5 text-[#2d8d78]" /></div>
        <div className="mt-5 divide-y divide-[#edf0f5]"><div className="flex flex-col gap-3 py-4 first:pt-1 sm:flex-row sm:items-center"><div className="flex size-9 items-center justify-center rounded-xl bg-[#f7f9fc]"><FileText className="size-4 text-[#5f83ad]" /></div><div className="min-w-0 flex-1"><p className="truncate text-sm font-semibold">email-lab-forensic-report</p><p className="mt-1 text-xs text-[#8290a2]">Generated from this capture · Session report</p></div><StatusBadge tone="success">PDF</StatusBadge><a href={reportHref} download="securemailscope-forensic-report.pdf" className="inline-flex items-center gap-2 rounded-xl border border-[#d7e0ea] px-3 py-2 text-xs font-semibold text-[#173b64] hover:bg-[#f7fbff]"><Download className="size-4" />Download PDF</a></div></div>
      </section>
      <ReportAssistant />
    </>}
  </AppShell>
}
