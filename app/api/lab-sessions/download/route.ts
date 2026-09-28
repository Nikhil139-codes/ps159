import { readdir, readFile } from 'node:fs/promises'
import path from 'node:path'
import { NextResponse } from 'next/server'

const uploadsRoot = path.join(process.cwd(), 'data', 'uploads')

// ─── GET /api/lab-sessions/download?session=<id> ─────────────────────────────
// Returns the raw PCAPNG file bytes for download.

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url)
  const sessionId = searchParams.get('session')
  if (!sessionId) {
    return NextResponse.json({ error: 'session parameter required' }, { status: 400 })
  }

  try {
    // Find session folder
    const folders = await readdir(uploadsRoot, { withFileTypes: true }).catch(() => [])
    const folder = folders.find(
      (entry) =>
        entry.isDirectory() &&
        (entry.name.includes(sessionId) || entry.name.endsWith(`-${sessionId}`)),
    )

    if (!folder) {
      return NextResponse.json({ error: 'Session not found' }, { status: 404 })
    }

    const sessionPath = path.join(uploadsRoot, folder.name, 'session.json')
    const session = JSON.parse(await readFile(sessionPath, 'utf8'))

    // Find the PCAPNG file
    const pcapngFile = session.files?.find(
      (f: { storedName?: string; originalName: string }) =>
        (f.storedName ?? f.originalName).endsWith('.pcapng'),
    )

    if (!pcapngFile) {
      return NextResponse.json({ error: 'PCAPNG file not found in session' }, { status: 404 })
    }

    const storedName = pcapngFile.storedName ?? pcapngFile.originalName
    const pcapngPath = path.join(uploadsRoot, folder.name, storedName)
    const pcapngBuffer = await readFile(pcapngPath)

    return new Response(pcapngBuffer, {
      headers: {
        'Content-Type': 'application/vnd.tcpdump.pcap',
        'Content-Disposition': `attachment; filename="${storedName}"`,
        'Content-Length': String(pcapngBuffer.length),
      },
    })
  } catch (err) {
    return NextResponse.json(
      { error: err instanceof Error ? err.message : 'Download failed' },
      { status: 500 },
    )
  }
}
