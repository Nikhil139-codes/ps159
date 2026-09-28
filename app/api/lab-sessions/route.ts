import { mkdir, readFile, writeFile } from 'node:fs/promises'
import path from 'node:path'
import { NextResponse } from 'next/server'
import { generatePcapng } from '@/lib/pcapng-generator'
import { runAnalysis } from '@/lib/analysis-pipeline'
import type { LabConfiguration } from '@/lib/types'
import { SCHEMA_VERSION, GENERATOR_VERSION, deriveForwardSecrecy } from '@/lib/types'

const uploadsRoot = path.join(process.cwd(), 'data', 'uploads')

// ─── POST /api/lab-sessions — generate lab session + real PCAPNG ─────────────

export async function POST(request: Request) {
  const body = await request.json()
  const files = Array.isArray(body.files) ? body.files : []

  // ── Build canonical LabConfiguration from request body ──
  const sessionId = `mail-lab-${Date.now()}-${crypto.randomUUID()}`
  const now = new Date().toISOString()

  // Derive forward secrecy from key exchange (not trusting a user-supplied flag)
  const keyExchange = body.keyExchange ?? 'ECDHE'
  const tlsVersion = body.tlsVersion ?? 'TLS1.3'
  const forwardSecrecy = deriveForwardSecrecy(keyExchange, tlsVersion)

  // Determine STARTTLS mode
  const starttls = body.starttls !== false && body.tlsMode !== 'None'
  const starttlsMode = !starttls
    ? 'disabled'
    : body.starttlsRequired === false
    ? 'enabled_optional'
    : 'enabled_required'

  // Determine port from protocol if not provided
  const protocol = body.protocol ?? 'SMTP'
  const defaultPort = protocol === 'SMTP' ? 587 : protocol === 'IMAP' ? 993 : 995
  const port = Number(body.port) || defaultPort

  // Determine cipher suite
  const cipherSuite = body.cipherSuite ?? (tlsVersion === 'TLS1.3'
    ? 'TLS_AES_256_GCM_SHA384'
    : 'ECDHE-RSA-AES256-GCM-SHA384')

  // Cert scenario derived from certificateProfile
  const certProfile = body.certificateProfile ?? 'valid'
  const certScenarioMap: Record<string, LabConfiguration['certificate']['scenario']> = {
    valid: 'valid',
    Valid: 'valid',
    expired: 'expired',
    Expired: 'expired',
    'self_signed': 'self_signed',
    'Self-signed': 'self_signed',
    'self-signed': 'self_signed',
    invalid_chain: 'invalid_chain',
    'Invalid chain': 'invalid_chain',
    weak_key: 'weak_key',
    weak_signature: 'weak_signature',
    not_yet_valid: 'not_yet_valid',
  }
  const certScenario = certScenarioMap[certProfile] ?? 'valid'

  // Compute cert dates based on scenario
  const certValidFrom = certScenario === 'not_yet_valid'
    ? new Date(Date.now() + 30 * 24 * 3600 * 1000).toISOString().split('T')[0]  // 30 days future
    : new Date(Date.now() - 365 * 24 * 3600 * 1000).toISOString().split('T')[0] // 1 year ago
  const certValidUntil = certScenario === 'expired'
    ? new Date(Date.now() - 7 * 24 * 3600 * 1000).toISOString().split('T')[0]  // 7 days ago
    : new Date(Date.now() + 365 * 24 * 3600 * 1000).toISOString().split('T')[0] // 1 year future

  // Public key length
  const pkAlgorithm = body.certKeyAlgorithm ?? 'RSA'
  const pkLength = body.certKeyLength
    ? Number(body.certKeyLength)
    : pkAlgorithm === 'RSA'
    ? (certScenario === 'weak_key' ? 1024 : 2048)
    : 256

  const labConfig: LabConfiguration = {
    schemaVersion: SCHEMA_VERSION,
    sessionId,
    email: {
      protocol,
      server: body.server ?? 'mail.lab.local',
      port,
      starttls,
      starttlsMode,
    },
    tls: {
      version: tlsVersion,
      cipherSuite,
      keyExchange,
      namedGroup: body.namedGroup ?? 'X25519',
      forwardSecrecy,
    },
    certificate: {
      enabled: body.certificateEnabled !== false,
      commonName: body.certCommonName ?? `mail.${body.server ?? 'lab.local'}`,
      issuer: certScenario === 'self_signed'
        ? `mail.${body.server ?? 'lab.local'}`
        : 'SecureMailScope Test CA',
      validFrom: certValidFrom,
      validUntil: certValidUntil,
      publicKeyAlgorithm: pkAlgorithm,
      publicKeyLength: pkLength,
      signatureAlgorithm: body.certSignatureAlgorithm ?? (
        certScenario === 'weak_signature' ? 'SHA1withRSA' : 'SHA256withRSA'
      ),
      chainValid: certScenario !== 'invalid_chain' && certScenario !== 'self_signed',
      scenario: certScenario,
    },
    testScenario: body.testScenario ?? 'custom',
    metadata: {
      createdAt: now,
      generatorVersion: GENERATOR_VERSION,
      source: 'SecureMailScope Email Lab',
      recipient: body.recipient,
      subject: body.subject,
    },
  }

  // ── Create session directory ──────────────────────────────────────────────
  const folderName = `email-lab-${sessionId}`
  const sessionDirectory = path.join(uploadsRoot, folderName)
  await mkdir(sessionDirectory, { recursive: true })

  // ── Generate real PCAPNG ──────────────────────────────────────────────────
  const pcapngBuffer = generatePcapng(labConfig)
  const pcapngFilename = `${sessionId}.pcapng`
  const pcapngPath = path.join(sessionDirectory, pcapngFilename)
  await writeFile(pcapngPath, pcapngBuffer)

  // ── Save attached file metadata (not real files — metadata only) ──────────
  const savedFiles = files.map((file: { name?: string; size?: number }, index: number) => ({
    originalName: file.name || `attachment-${index + 1}`,
    size: Number(file.size) || 0,
  }))

  // ── Build capture file record ─────────────────────────────────────────────
  const captureFiles = [
    {
      originalName: pcapngFilename,
      storedName: pcapngFilename,
      size: pcapngBuffer.length,
    },
  ]

  const reconstruction = {
    status: 'complete',
    method: 'simulated-testbed-pcapng',
    sourceFiles: captureFiles.map((f) => f.storedName),
    sessionsReconstructed: 1,
    message: 'SecureMailScope simulated testbed PCAPNG with encrypted configuration metadata.',
  }

  // ── Run analysis on the generated PCAPNG ─────────────────────────────────
  const analysis = await runAnalysis({
    pcapBuffer: pcapngBuffer,
    sessionId,
    captureFilename: pcapngFilename,
    source: 'email-lab',
    runAi: false, // skip AI on generation — run on analysis page
  })

  // ── Persist everything ────────────────────────────────────────────────────
  const session = {
    id: sessionId,
    files: captureFiles,
    folder: `data/uploads/${folderName}`,
    reconstruction,
    attachments: savedFiles,
    source: 'email-lab' as const,
    analysis,
    labConfig,
  }

  await writeFile(
    path.join(sessionDirectory, 'reconstructed-tcp-streams.json'),
    JSON.stringify(reconstruction, null, 2),
  )
  await writeFile(
    path.join(sessionDirectory, 'session.json'),
    JSON.stringify(session, null, 2),
  )
  await writeFile(
    path.join(sessionDirectory, 'lab-config.json'),
    JSON.stringify(labConfig, null, 2),
  )
  await writeFile(
    path.join(sessionDirectory, 'analysis.json'),
    JSON.stringify(analysis, null, 2),
  )

  return NextResponse.json(session)
}

// ─── GET /api/lab-sessions?id=<sessionId> — read session + PCAPNG ────────────

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url)
  const id = searchParams.get('id')
  if (!id) return NextResponse.json({ error: 'id required' }, { status: 400 })

  try {
    // Find session folder
    const { readdir } = await import('node:fs/promises')
    const folders = await readdir(uploadsRoot, { withFileTypes: true }).catch(() => [])
    const folder = folders.find(
      (entry) => entry.isDirectory() && (entry.name.includes(id) || entry.name.endsWith(`-${id}`))
    )
    if (!folder) return NextResponse.json({ error: 'Session not found' }, { status: 404 })

    const sessionPath = path.join(uploadsRoot, folder.name, 'session.json')
    const session = JSON.parse(await readFile(sessionPath, 'utf8'))
    return NextResponse.json(session)
  } catch {
    return NextResponse.json({ error: 'Session not found' }, { status: 404 })
  }
}
