import Link from 'next/link'
import { ArrowRight, Mail, UploadCloud } from 'lucide-react'
import { AppShell, PageHeader } from '@/components/app-shell'

export default function Page() {
  return (
    <AppShell>
      <PageHeader
        eyebrow="Workspace overview"
        title="Forensic workspace overview"
        description="Choose how you want to bring a PCAP session into the forensic workflow."
        action={
          <Link href="/upload" className="inline-flex items-center justify-center gap-2 rounded-xl bg-[#173b64] px-4 py-2.5 text-sm font-semibold text-white shadow-sm transition hover:bg-[#102e50]">
            <UploadCloud className="size-4" />
            New analysis
          </Link>
        }
      />

      <section aria-labelledby="start-analysis" className="mx-auto max-w-5xl">
        <div className="mb-5">
          <p className="text-xs font-bold uppercase tracking-[0.16em] text-[#2d8d78]">Start here</p>
          <h2 id="start-analysis" className="mt-1 text-xl font-bold tracking-tight">Bring in a PCAP session</h2>
          <p className="mt-2 text-sm text-[#8290a2]">Both options create one session workspace for related capture files.</p>
        </div>

        <div className="grid gap-4 lg:grid-cols-2">
          <Link href="/upload?mode=manual" className="group rounded-2xl border border-[#d8e2ee] bg-white p-6 transition hover:-translate-y-0.5 hover:border-[#5f83ad] hover:shadow-sm">
            <div className="flex items-start justify-between">
              <div className="flex size-11 items-center justify-center rounded-xl bg-[#eaf1f9] text-[#173b64]"><UploadCloud className="size-5" /></div>
              <ArrowRight className="size-5 text-[#9aa6b5] transition group-hover:translate-x-1 group-hover:text-[#173b64]" />
            </div>
            <h3 className="mt-5 font-bold">Upload PCAP files manually</h3>
            <p className="mt-2 text-sm leading-6 text-[#718096]">Select one or more .pcap or .pcapng files. They are saved together in a single folder.</p>
          </Link>

          <Link href="/lab" className="group rounded-2xl border border-[#eadfcf] bg-[#fffdf8] p-6 transition hover:-translate-y-0.5 hover:border-[#c9934b] hover:shadow-sm lg:col-span-2">
            <div className="flex items-start justify-between">
              <div className="flex size-11 items-center justify-center rounded-xl bg-[#fff2dc] text-[#9a641e]"><Mail className="size-5" /></div>
              <ArrowRight className="size-5 text-[#9aa6b5] transition group-hover:translate-x-1 group-hover:text-[#9a641e]" />
            </div>
            <h3 className="mt-5 font-bold">Email traffic lab</h3>
            <p className="mt-2 text-sm leading-6 text-[#718096]">Configure SMTP and TLS, write a draft email, attach files, send through the controlled lab, then reconstruct the captured PCAP session in Traffic.</p>
          </Link>
        </div>
      </section>
    </AppShell>
  )
}
