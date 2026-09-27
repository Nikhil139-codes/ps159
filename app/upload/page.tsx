'use client'

import { ChangeEvent, DragEvent, useRef, useState } from 'react'
import { useRouter } from 'next/navigation'
import { CheckCircle2, FolderOpen, LockKeyhole, ShieldCheck, UploadCloud, X } from 'lucide-react'
import { AppShell, PageHeader } from '@/components/app-shell'

const MAX_FILE_SIZE = 500 * 1024 * 1024
const ACCEPTED = ['.pcap', '.pcapng']

export default function UploadPage() {
  const router = useRouter()
  const inputRef = useRef<HTMLInputElement>(null)
  const [isDragging, setIsDragging] = useState(false)
  const [files, setFiles] = useState<File[]>([])
  const [isProcessing, setIsProcessing] = useState(false)
  const [error, setError] = useState('')
  const [saved, setSaved] = useState(false)
  const [stage, setStage] = useState('')

  function addFiles(selected: FileList | File[]) {
    const incoming = Array.from(selected)
    const invalid = incoming.find((file) => !ACCEPTED.includes(file.name.toLowerCase().slice(file.name.lastIndexOf('.'))))
    const oversized = incoming.find((file) => file.size > MAX_FILE_SIZE)
    if (invalid) return setError(`${invalid.name}: only .pcap and .pcapng files are supported.`)
    if (oversized) return setError(`${oversized.name}: the maximum file size is 500 MB.`)
    setError('')
    setSaved(false)
    setFiles((current) => [...current, ...incoming.filter((file) => !current.some((item) => item.name === file.name && item.size === file.size))])
  }

  function handleDrop(event: DragEvent<HTMLDivElement>) {
    event.preventDefault()
    setIsDragging(false)
    addFiles(event.dataTransfer.files)
  }

  async function uploadFiles() {
    if (!files.length) return setError('Add at least one PCAP file.')
    setIsProcessing(true)
    setError('')
    setStage('Saving all files into one capture folder…')
    const formData = new FormData()
    files.forEach((file) => formData.append('files', file))
    try {
      const response = await fetch('/api/uploads', { method: 'POST', body: formData })
      const result = await response.json()
      if (!response.ok) throw new Error(result.error || 'Upload failed.')
      setStage('Reconstructing complete TCP streams across all PCAP files…')
      await new Promise((resolve) => window.setTimeout(resolve, 900))
      setSaved(true)
      setStage(`${result.files.length} files grouped · ${result.reconstruction.sessionsReconstructed} TCP sessions reconstructed`)
      window.setTimeout(() => router.push(`/analysis?session=${result.id}`), 900)
    } catch (uploadError) {
      setError(uploadError instanceof Error ? uploadError.message : 'Upload failed. Please try again.')
      setStage('')
    } finally {
      setIsProcessing(false)
    }
  }

  function handleInput(event: ChangeEvent<HTMLInputElement>) {
    if (event.target.files) addFiles(event.target.files)
    event.target.value = ''
  }

  return <AppShell>
    <PageHeader eyebrow="Capture input" title="Upload PCAP files" description="Add related PCAP files. They will be stored together and reconstructed before analysis." />
    <div className="mx-auto max-w-3xl">
      <div className="mb-5 rounded-2xl border border-[#dce9f5] bg-[#f7fbff] p-4 text-sm text-[#36516d]"><div className="flex items-start gap-3"><FolderOpen className="mt-0.5 size-5 shrink-0 text-[#173b64]" /><p><strong>One capture, one folder.</strong> All selected files are saved together, then the demo reconstructs TCP streams across the complete file set.</p></div></div>
      <div onDragOver={(event) => { event.preventDefault(); setIsDragging(true) }} onDragLeave={() => setIsDragging(false)} onDrop={handleDrop} className={`rounded-2xl border border-dashed p-8 text-center transition sm:p-12 ${isDragging ? 'border-[#2d8d78] bg-[#f0faf6]' : 'border-[#b8c9dc] bg-white'}`}>
        <input ref={inputRef} type="file" multiple accept=".pcap,.pcapng,application/vnd.tcpdump.pcap" onChange={handleInput} className="sr-only" />
        <div className="mx-auto flex size-16 items-center justify-center rounded-2xl bg-[#eaf1f9] text-[#173b64]"><UploadCloud className="size-7" /></div>
        <h2 className="mt-6 text-xl font-bold">{files.length ? `${files.length} PCAP file${files.length === 1 ? '' : 's'} selected` : 'Drop PCAP files here'}</h2>
        <p className="mx-auto mt-2 max-w-md text-sm leading-6 text-[#718096]">Select multiple related .pcap or .pcapng files. The demo stores them in a new folder under <code className="rounded bg-[#f1f5f9] px-1.5 py-0.5 text-xs">data/uploads</code>.</p>
        {files.length > 0 && <div className="mx-auto mt-5 flex max-w-lg flex-col gap-2 text-left">{files.map((file) => <div key={`${file.name}-${file.size}`} className="flex items-center gap-3 rounded-xl border border-[#edf0f5] bg-[#fbfcfe] px-3 py-2 text-sm"><ShieldCheck className="size-4 text-[#247c6b]" /><span className="min-w-0 flex-1 truncate">{file.name}</span><span className="text-xs text-[#8290a2]">{(file.size / 1024 / 1024).toFixed(2)} MB</span><button type="button" onClick={() => setFiles((current) => current.filter((item) => item !== file))} aria-label={`Remove ${file.name}`}><X className="size-4 text-[#8290a2]" /></button></div>)}</div>}
        <div className="mt-7 flex flex-wrap justify-center gap-3"><button type="button" onClick={() => inputRef.current?.click()} className="rounded-xl border border-[#d7e0ea] bg-white px-5 py-3 text-sm font-semibold text-[#173b64] hover:bg-[#f7fbff]">Add PCAP files</button>{files.length > 0 && <button type="button" onClick={uploadFiles} disabled={isProcessing || saved} className="rounded-xl bg-[#173b64] px-5 py-3 text-sm font-semibold text-white disabled:cursor-not-allowed disabled:opacity-60">{isProcessing ? 'Processing…' : saved ? 'Session ready' : 'Save & reconstruct'}</button>}</div>
        <p className="mt-4 text-xs text-[#9aa6b5]">Up to 20 files · Maximum 500 MB each · PCAP and PCAPNG</p>
        {stage && <p className="mt-4 text-sm font-medium text-[#247c6b]">{saved ? <CheckCircle2 className="mr-2 inline size-4" /> : <LockKeyhole className="mr-2 inline size-4" />}{stage}</p>}
        {error && <p role="alert" className="mt-4 text-sm font-medium text-[#b44b4b]">{error}</p>}
      </div>
    </div>
  </AppShell>
}
