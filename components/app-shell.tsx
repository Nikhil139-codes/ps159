'use client'

import Link from 'next/link'
import { usePathname } from 'next/navigation'
import {
  Activity,
  BarChart3,
  ChevronRight,
  FileSearch,
  Files,
  LayoutDashboard,
  LockKeyhole,
  Mail,
  Menu,
  Settings,
  ShieldCheck,
  Upload,
  X,
} from 'lucide-react'
import { useState } from 'react'

const navigation = [
  { label: 'Overview', href: '/', icon: LayoutDashboard },
  { label: 'Email lab', href: '/lab', icon: Mail },
  { label: 'Upload PCAP', href: '/upload', icon: Upload },
  { label: 'Traffic', href: '/analysis', icon: Activity },
  { label: 'Security', href: '/findings', icon: ShieldCheck },
  { label: 'Report center', href: '/reports', icon: Files },
]

export function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname()
  const [mobileOpen, setMobileOpen] = useState(false)

  return (
    <div className="min-h-screen bg-[#f7f9fc] text-[#182230]">
      <aside className={`fixed inset-y-0 left-0 z-40 flex w-64 flex-col border-r border-[#e5eaf1] bg-white transition-transform lg:translate-x-0 ${mobileOpen ? 'translate-x-0' : '-translate-x-full'}`}>
        <div className="flex h-20 items-center gap-3 border-b border-[#edf0f5] px-6">
          <div className="flex size-9 items-center justify-center rounded-xl bg-[#173b64] text-white"><Mail className="size-5" /></div>
          <div><p className="text-sm font-bold tracking-tight">SecureMailScope</p><p className="text-[11px] text-[#7a8798]">Forensic security console</p></div>
          <button className="ml-auto rounded-lg p-1 text-[#7a8798] lg:hidden" onClick={() => setMobileOpen(false)} aria-label="Close navigation"><X className="size-5" /></button>
        </div>
        <div className="px-4 pt-7"><p className="px-3 text-[10px] font-bold uppercase tracking-[0.16em] text-[#9aa6b5]">Workspace</p><nav className="mt-3 flex flex-col gap-1">
          {navigation.map((item) => { const active = pathname === item.href; const Icon = item.icon; return <Link key={item.href} href={item.href} onClick={() => setMobileOpen(false)} className={`flex items-center gap-3 rounded-xl px-3 py-2.5 text-sm font-medium transition-colors ${active ? 'bg-[#eaf1f9] text-[#173b64]' : 'text-[#607087] hover:bg-[#f4f7fa] hover:text-[#173b64]'}`}><Icon className="size-[17px]" />{item.label}{active && <ChevronRight className="ml-auto size-4" />}</Link> })}
        </nav></div>
        <div className="mt-auto border-t border-[#edf0f5] p-4"><Link href="#" className="flex items-center gap-3 rounded-xl px-3 py-2.5 text-sm text-[#607087] hover:bg-[#f4f7fa]"><Settings className="size-[17px]" />Workspace settings</Link></div>
      </aside>
      {mobileOpen && <button className="fixed inset-0 z-30 bg-[#10243b]/30 lg:hidden" onClick={() => setMobileOpen(false)} aria-label="Close navigation overlay" />}
      <div className="lg:pl-64"><header className="flex h-20 items-center justify-between border-b border-[#e5eaf1] bg-white px-5 sm:px-8"><button className="rounded-lg p-2 text-[#607087] lg:hidden" onClick={() => setMobileOpen(true)} aria-label="Open navigation"><Menu className="size-5" /></button><div className="hidden items-center gap-2 text-sm text-[#7a8798] sm:flex"><LockKeyhole className="size-4 text-[#2d8d78]" />Passive analysis workspace</div><div className="ml-auto flex items-center gap-5"><div className="hidden items-center gap-2 text-xs text-[#7a8798] md:flex"><span className="size-2 rounded-full bg-[#2d9b7d]" />All systems operational</div><div className="flex size-8 items-center justify-center rounded-full bg-[#d9e7f5] text-xs font-bold text-[#173b64]">SM</div></div></header><main className="mx-auto max-w-[1440px] px-5 py-8 sm:px-8 lg:px-10">{children}</main></div>
    </div>
  )
}

export function PageHeader({ eyebrow, title, description, action }: { eyebrow: string; title: string; description: string; action?: React.ReactNode }) { return <div className="mb-8 flex flex-col justify-between gap-5 md:flex-row md:items-end"><div><p className="mb-2 text-xs font-bold uppercase tracking-[0.16em] text-[#2d8d78]">{eyebrow}</p><h1 className="text-3xl font-bold tracking-[-0.03em] text-[#182230]">{title}</h1><p className="mt-2 max-w-2xl text-sm leading-6 text-[#718096]">{description}</p></div>{action}</div> }

export function StatCard({ label, value, detail, tone = 'blue' }: { label: string; value: string; detail: string; tone?: 'blue' | 'green' | 'orange' | 'red' }) { const tones = { blue: 'bg-[#eaf1f9] text-[#173b64]', green: 'bg-[#e5f4ef] text-[#247c6b]', orange: 'bg-[#fff1df] text-[#a66b1b]', red: 'bg-[#fdeaea] text-[#bb4e4e]' }; return <div className="rounded-2xl border border-[#e5eaf1] bg-white p-5"><div className="flex items-start justify-between"><p className="text-xs font-semibold text-[#7a8798]">{label}</p><span className={`rounded-lg px-2 py-1 text-[10px] font-bold ${tones[tone]}`}>LIVE</span></div><p className="mt-4 text-3xl font-bold tracking-tight">{value}</p><p className="mt-1 text-xs text-[#8290a2]">{detail}</p></div> }

export function StatusBadge({ children, tone = 'neutral' }: { children: React.ReactNode; tone?: 'success' | 'warning' | 'danger' | 'neutral' }) { const classes = { success: 'bg-[#e5f4ef] text-[#247c6b]', warning: 'bg-[#fff1df] text-[#a66b1b]', danger: 'bg-[#fdeaea] text-[#bb4e4e]', neutral: 'bg-[#edf1f5] text-[#64748b]' }; return <span className={`inline-flex rounded-full px-2.5 py-1 text-[11px] font-semibold ${classes[tone]}`}>{children}</span> }

export function EmptyRouteIcon({ type = 'search' }: { type?: 'search' | 'chart' }) { return type === 'chart' ? <BarChart3 className="size-5 text-[#2d8d78]" /> : <FileSearch className="size-5 text-[#2d8d78]" /> }

export { navigation }
