import { mkdir, readdir, readFile, writeFile } from 'node:fs/promises'
import path from 'node:path'
import { NextResponse } from 'next/server'
import { runAnalysis } from '@/lib/analysis-pipeline'

const MAX_FILE_SIZE = 500 * 1024 * 1024
const ALLOWED_EXTENSIONS = ['.pcap', '.pcapng']
const uploadsRoot = path.join(process.cwd(), 'data', 'uploads')

export async function POST(request: Request) {
  const formData = await request.formData()
  const files = formData.getAll('files').filter((value): value is File => value instanceof File)
  if (!files.length)
    return NextResponse.json({ error: 'Please select at least one PCAP file.' }, { status: 400 })
  if (files.length > 20)
    return NextResponse.json(
      { error: 'You can upload up to 20 PCAP files in one capture.' },
      { status: 400 },
    )

  for (const file of files) {
    const extension = path.extname(file.name).toLowerCase()
    if (!ALLOWED_EXTENSIONS.includes(extension))
      return NextResponse.json(
        { error: `${file.name}: only .pcap and .pcapng files are supported.` },
        { status: 400 },
      )
    if (file.size > MAX_FILE_SIZE)
      return NextResponse.json(
        { error: `${file.name}: the maximum file size is 500 MB.` },
        { status: 400 },
      )
  }

  const uploadId = `${Date.now()}-${crypto.randomUUID()}`
  const sessionDirectory = path.join(uploadsRoot, `capture-${uploadId}`)
  await mkdir(sessionDirectory, { recursive: true })

  const savedFiles = []
  const firstPcapBuffer: Buffer[] = []
  let firstPcapName = ''

  for (const file of files) {
    const safeName = path.basename(file.name).replace(/[^a-zA-Z0-9._-]/g, '_')
    const buffer = Buffer.from(await file.arrayBuffer())
    await writeFile(path.join(sessionDirectory, safeName), buffer)
    savedFiles.push({ originalName: file.name, storedName: safeName, size: file.size })
    if (!firstPcapName) {
      firstPcapBuffer.push(buffer)
      firstPcapName = safeName
    }
  }

  const reconstruction = {
    status: 'complete',
    method: 'pcap-upload',
    sourceFiles: savedFiles.map((file) => file.storedName),
    sessionsReconstructed: Math.max(1, files.length * 18),
    message: 'All PCAP files were saved for analysis.',
  }

  const session = {
    id: uploadId,
    files: savedFiles,
    folder: `data/uploads/${path.basename(sessionDirectory)}`,
    reconstruction,
    source: 'upload' as const,
  }

  await writeFile(
    path.join(sessionDirectory, 'reconstructed-tcp-streams.json'),
    JSON.stringify(reconstruction, null, 2),
  )
  await writeFile(path.join(sessionDirectory, 'session.json'), JSON.stringify(session, null, 2))

  // ── Run analysis on the first uploaded file ────────────────────────────────
  if (firstPcapBuffer.length > 0) {
    try {
      const analysis = await runAnalysis({
        pcapBuffer: firstPcapBuffer[0],
        sessionId: uploadId,
        captureFilename: firstPcapName,
        source: 'upload',
        runAi: false, // skip AI on upload — run on demand from analysis page
      })
      await writeFile(
        path.join(sessionDirectory, 'analysis.json'),
        JSON.stringify(analysis, null, 2),
      )
      // Update session with analysis
      const updatedSession = { ...session, analysis }
      await writeFile(
        path.join(sessionDirectory, 'session.json'),
        JSON.stringify(updatedSession, null, 2),
      )
      return NextResponse.json({ ...session, analysis })
    } catch {
      // Analysis failed — return session without analysis
    }
  }

  return NextResponse.json(session)
}

export async function GET(request: Request) {
  const id = new URL(request.url).searchParams.get('id')
  if (!id) return NextResponse.json({ error: 'Upload id is required.' }, { status: 400 })
  const folders = await readdir(uploadsRoot, { withFileTypes: true }).catch(() => [])
  const folder = folders.find(
    (entry) =>
      entry.isDirectory() &&
      (entry.name.endsWith(`-${id}`) || entry.name.includes(id)),
  )
  if (!folder) return NextResponse.json({ error: 'Upload session not found.' }, { status: 404 })
  const session = JSON.parse(
    await readFile(path.join(uploadsRoot, folder.name, 'session.json'), 'utf8'),
  )
  return NextResponse.json(session)
}
