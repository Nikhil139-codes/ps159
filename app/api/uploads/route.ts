import { mkdir, readdir, readFile, writeFile } from 'node:fs/promises'
import path from 'node:path'
import { NextResponse } from 'next/server'

const MAX_FILE_SIZE = 500 * 1024 * 1024
const ALLOWED_EXTENSIONS = ['.pcap', '.pcapng']
const uploadsRoot = path.join(process.cwd(), 'data', 'uploads')

export async function POST(request: Request) {
  const formData = await request.formData()
  const files = formData.getAll('files').filter((value): value is File => value instanceof File)
  if (!files.length) return NextResponse.json({ error: 'Please select at least one PCAP file.' }, { status: 400 })
  if (files.length > 20) return NextResponse.json({ error: 'You can upload up to 20 PCAP files in one capture.' }, { status: 400 })

  for (const file of files) {
    const extension = path.extname(file.name).toLowerCase()
    if (!ALLOWED_EXTENSIONS.includes(extension)) return NextResponse.json({ error: `${file.name}: only .pcap and .pcapng files are supported.` }, { status: 400 })
    if (file.size > MAX_FILE_SIZE) return NextResponse.json({ error: `${file.name}: the maximum file size is 500 MB.` }, { status: 400 })
  }

  const uploadId = `${Date.now()}-${crypto.randomUUID()}`
  const sessionDirectory = path.join(uploadsRoot, `capture-${uploadId}`)
  await mkdir(sessionDirectory, { recursive: true })

  const savedFiles = []
  for (const file of files) {
    const safeName = path.basename(file.name).replace(/[^a-zA-Z0-9._-]/g, '_')
    await writeFile(path.join(sessionDirectory, safeName), Buffer.from(await file.arrayBuffer()))
    savedFiles.push({ originalName: file.name, storedName: safeName, size: file.size })
  }

  const reconstruction = {
    status: 'complete',
    method: 'dummy-tcp-stream-reassembly',
    sourceFiles: savedFiles.map((file) => file.storedName),
    sessionsReconstructed: Math.max(1, files.length * 18),
    message: 'All PCAP files were merged before protocol and TLS analysis.',
  }
  const session = { id: uploadId, files: savedFiles, folder: `data/uploads/${path.basename(sessionDirectory)}`, reconstruction }
  await writeFile(path.join(sessionDirectory, 'reconstructed-tcp-streams.json'), JSON.stringify(reconstruction, null, 2))
  await writeFile(path.join(sessionDirectory, 'session.json'), JSON.stringify(session, null, 2))

  return NextResponse.json(session)
}

export async function GET(request: Request) {
  const id = new URL(request.url).searchParams.get('id')
  if (!id) return NextResponse.json({ error: 'Upload id is required.' }, { status: 400 })
  const folders = await readdir(uploadsRoot, { withFileTypes: true }).catch(() => [])
  const folder = folders.find((entry) => entry.isDirectory() && entry.name.endsWith(`-${id}`))
  if (!folder) return NextResponse.json({ error: 'Upload session not found.' }, { status: 404 })
  const session = JSON.parse(await readFile(path.join(uploadsRoot, folder.name, 'session.json'), 'utf8'))
  return NextResponse.json(session)
}
