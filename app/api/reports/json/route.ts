import { readdir, readFile } from 'node:fs/promises'
import path from 'node:path'
import { NextResponse } from 'next/server'
import type { CanonicalAnalysis } from '@/lib/types'
import { buildCanonicalReport } from '@/lib/forensic-report'

const uploadsRoot = path.join(process.cwd(), 'data', 'uploads')

export async function GET(request: Request) {
  const sessionId = new URL(request.url).searchParams.get('session')
  if (!sessionId) {
    return NextResponse.json({ error: 'Session ID is required.' }, { status: 400 })
  }

  try {
    const folders = await readdir(uploadsRoot, { withFileTypes: true }).catch(() => [])
    const folder = folders.find(
      (entry) => entry.isDirectory() && (entry.name.includes(sessionId) || entry.name.endsWith(`-${sessionId}`))
    )
    if (!folder) {
      return NextResponse.json({ error: 'Session not found.' }, { status: 404 })
    }

    const folderPath = path.join(uploadsRoot, folder.name)
    let analysis: CanonicalAnalysis | null = null

    try {
      analysis = JSON.parse(await readFile(path.join(folderPath, 'analysis.json'), 'utf8'))
    } catch {
      const session = JSON.parse(await readFile(path.join(folderPath, 'session.json'), 'utf8'))
      analysis = session.analysis ?? null
    }

    if (!analysis) {
      return NextResponse.json({ error: 'Analysis not found for this session.' }, { status: 404 })
    }

    const report = buildCanonicalReport(analysis)
    const exportObject = {
      analysis,
      canonicalReport: report,
    }

    const jsonString = JSON.stringify(exportObject, null, 2)

    return new Response(jsonString, {
      headers: {
        'Content-Type': 'application/json',
        'Content-Disposition': `attachment; filename="SecureMailScope_${sessionId}_report.json"`,
      },
    })
  } catch (err) {
    return NextResponse.json(
      { error: err instanceof Error ? err.message : 'Failed to export analysis JSON' },
      { status: 500 }
    )
  }
}
