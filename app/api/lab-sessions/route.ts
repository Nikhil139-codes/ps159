import { mkdir, writeFile } from 'node:fs/promises'
import path from 'node:path'
import { NextResponse } from 'next/server'

const uploadsRoot = path.join(process.cwd(), 'data', 'uploads')

export async function POST(request: Request) {
  const body = await request.json()
  const files = Array.isArray(body.files) ? body.files : []
  const sessionId = `mail-lab-${Date.now()}-${crypto.randomUUID()}`
  const folderName = `email-lab-${sessionId}`
  const sessionDirectory = path.join(uploadsRoot, folderName)
  await mkdir(sessionDirectory, { recursive: true })

  const savedFiles = files.map((file: { name?: string; size?: number }, index: number) => ({
    originalName: file.name || `attachment-${index + 1}`,
    size: Number(file.size) || 0,
  }))
  const totalBytes = savedFiles.reduce((sum: number, file: { size: number }) => sum + file.size, 0)
  const pcapCount = Math.max(1, Math.ceil(totalBytes / (5 * 1024 * 1024)))
  const captureFiles = Array.from({ length: pcapCount }, (_, index) => ({
    originalName: `${sessionId}-part-${String(index + 1).padStart(2, '0')}.pcap`,
    size: Math.max(1024, Math.round(totalBytes / pcapCount)),
  }))
  const reconstruction = {
    status: 'complete',
    method: 'dummy-tcp-stream-reassembly',
    sourceFiles: captureFiles.map((file) => file.originalName),
    sessionsReconstructed: Math.max(1, captureFiles.length * 18),
    message: 'Generated lab captures were grouped and reconstructed before traffic analysis.',
  }
  for (const file of captureFiles) await writeFile(path.join(sessionDirectory, file.originalName), Buffer.from(`Dummy PCAP capture for ${sessionId}\n`))
  const session = { id: sessionId, files: captureFiles, folder: `data/uploads/${folderName}`, reconstruction, attachments: savedFiles }
  await writeFile(path.join(sessionDirectory, 'reconstructed-tcp-streams.json'), JSON.stringify(reconstruction, null, 2))
  await writeFile(path.join(sessionDirectory, 'session.json'), JSON.stringify(session, null, 2))
  return NextResponse.json(session)
}
