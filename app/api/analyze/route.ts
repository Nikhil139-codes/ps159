import { readdir, readFile, writeFile } from 'node:fs/promises'
import path from 'node:path'
import { NextResponse } from 'next/server'
import { runAnalysis } from '@/lib/analysis-pipeline'

const uploadsRoot = path.join(process.cwd(), 'data', 'uploads')

// ─── POST /api/analyze — analyze a stored session's PCAPNG ───────────────────

export async function POST(request: Request) {
  try {
    const { sessionId, runAi = true } = await request.json()
    if (!sessionId) {
      return NextResponse.json({ error: 'sessionId required' }, { status: 400 })
    }

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

    const folderPath = path.join(uploadsRoot, folder.name)
    const sessionData = JSON.parse(await readFile(path.join(folderPath, 'session.json'), 'utf8'))

    // Check if analysis already exists and is not stale
    try {
      const existingAnalysis = JSON.parse(
        await readFile(path.join(folderPath, 'analysis.json'), 'utf8'),
      )
      // Return cached analysis if it already has the full pipeline result
      if (existingAnalysis?.securityScore && existingAnalysis?.findings) {
        return NextResponse.json(existingAnalysis)
      }
    } catch {
      // No cached analysis — proceed
    }

    // Find the PCAPNG/PCAP file
    const pcapFile = sessionData.files?.find(
      (f: { storedName?: string; originalName: string }) => {
        const name = f.storedName ?? f.originalName
        return name.endsWith('.pcapng') || name.endsWith('.pcap')
      },
    )

    if (!pcapFile) {
      return NextResponse.json({ error: 'No PCAP/PCAPNG file in session' }, { status: 400 })
    }

    const storedName = pcapFile.storedName ?? pcapFile.originalName
    const pcapBuffer = await readFile(path.join(folderPath, storedName))

    const source = sessionData.source ?? 'upload'
    const analysis = await runAnalysis({
      pcapBuffer,
      sessionId,
      captureFilename: storedName,
      source,
      runAi,
    })

    // Cache the analysis result
    await writeFile(
      path.join(folderPath, 'analysis.json'),
      JSON.stringify(analysis, null, 2),
    )

    // Update session with analysis reference
    const updatedSession = { ...sessionData, analysis }
    await writeFile(
      path.join(folderPath, 'session.json'),
      JSON.stringify(updatedSession, null, 2),
    )

    return NextResponse.json(analysis)
  } catch (err) {
    return NextResponse.json(
      { error: err instanceof Error ? err.message : 'Analysis failed' },
      { status: 500 },
    )
  }
}

// ─── GET /api/analyze?session=<id> — return cached analysis ──────────────────

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url)
  const sessionId = searchParams.get('session')
  if (!sessionId) {
    return NextResponse.json({ error: 'session parameter required' }, { status: 400 })
  }

  try {
    const folders = await readdir(uploadsRoot, { withFileTypes: true }).catch(() => [])
    const folder = folders.find(
      (entry) =>
        entry.isDirectory() &&
        (entry.name.includes(sessionId) || entry.name.endsWith(`-${sessionId}`)),
    )

    if (!folder) {
      return NextResponse.json({ error: 'Session not found' }, { status: 404 })
    }

    const analysisPath = path.join(uploadsRoot, folder.name, 'analysis.json')
    const analysis = JSON.parse(await readFile(analysisPath, 'utf8'))
    return NextResponse.json(analysis)
  } catch {
    return NextResponse.json({ error: 'Analysis not found — run POST first' }, { status: 404 })
  }
}
