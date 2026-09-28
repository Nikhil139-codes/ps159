import { readdir, readFile } from 'node:fs/promises'
import path from 'node:path'
import { buildCanonicalReport, type Session } from '@/lib/forensic-report'
import type { CanonicalAnalysis } from '@/lib/types'

const uploadsRoot = path.join(process.cwd(), 'data', 'uploads')

async function resolveSessionAndAnalysis(
  sessionId: string,
  origin: string
): Promise<{ session: Session; analysis: CanonicalAnalysis | null } | null> {
  try {
    const folders = await readdir(uploadsRoot, { withFileTypes: true }).catch(() => [])
    const folder = folders.find(
      (entry) =>
        entry.isDirectory() &&
        (entry.name.includes(sessionId) || entry.name.endsWith(`-${sessionId}`))
    )
    if (folder) {
      const folderPath = path.join(uploadsRoot, folder.name)
      const sessionData = JSON.parse(await readFile(path.join(folderPath, 'session.json'), 'utf8')) as Session
      let analysisData: CanonicalAnalysis | null = null
      try {
        analysisData = JSON.parse(await readFile(path.join(folderPath, 'analysis.json'), 'utf8'))
      } catch {
        analysisData = sessionData.analysis ?? null
      }
      return { session: sessionData, analysis: analysisData }
    }
  } catch {
    // filesystem read fallback
  }

  try {
    const res = await fetch(`${origin}/api/uploads?id=${encodeURIComponent(sessionId)}`, {
      cache: 'no-store',
    })
    if (res.ok) {
      const sessionData = (await res.json()) as Session
      return { session: sessionData, analysis: sessionData.analysis ?? null }
    }
  } catch {
    // ignore
  }

  return null
}

function generatePdf(pagesContent: string[][]): string {
  const escapePdf = (val: string) =>
    val.replaceAll('\\', '\\\\').replaceAll('(', '\\(').replaceAll(')', '\\)')

  const pageCount = pagesContent.length
  const fontObjIndex = 3
  let currentObjIndex = 4

  const pageObjIndices: number[] = []
  const pageObjects: { pageObjIndex: number; contentObjIndex: number; stream: string }[] = []

  for (let i = 0; i < pageCount; i++) {
    const pObj = currentObjIndex++
    const cObj = currentObjIndex++
    pageObjIndices.push(pObj)

    const lines = pagesContent[i]
    // 44 lines per page maximum with 14pt line spacing
    const stream = `BT\n/F1 9 Tf\n40 750 Td\n${lines
      .map((line, idx) => `${idx ? '0 -15 Td\n' : ''}(${escapePdf(line.slice(0, 95))}) Tj`)
      .join('\n')}\nET`

    pageObjects.push({ pageObjIndex: pObj, contentObjIndex: cObj, stream })
  }

  const objects: { index: number; body: string }[] = [
    { index: 1, body: '<< /Type /Catalog /Pages 2 0 R >>' },
    {
      index: 2,
      body: `<< /Type /Pages /Kids [${pageObjIndices.map((n) => `${n} 0 R`).join(' ')}] /Count ${pageCount} >>`,
    },
    { index: 3, body: '<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>' },
  ]

  for (const po of pageObjects) {
    objects.push({
      index: po.pageObjIndex,
      body: `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 ${fontObjIndex} 0 R >> >> /Contents ${po.contentObjIndex} 0 R >>`,
    })
    objects.push({
      index: po.contentObjIndex,
      body: `<< /Length ${po.stream.length} >>\nstream\n${po.stream}\nendstream`,
    })
  }

  objects.sort((a, b) => a.index - b.index)

  let pdf = '%PDF-1.4\n'
  const offsets: number[] = [0]

  for (const obj of objects) {
    offsets.push(Buffer.byteLength(pdf, 'utf8'))
    pdf += `${obj.index} 0 obj\n${obj.body}\nendobj\n`
  }

  const xref = Buffer.byteLength(pdf, 'utf8')
  pdf += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n${offsets
    .slice(1)
    .map((offset) => `${String(offset).padStart(10, '0')} 00000 n `)
    .join('\n')}\ntrailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF`

  return pdf
}

export async function GET(request: Request) {
  const sessionId = new URL(request.url).searchParams.get('session')
  if (!sessionId) {
    return new Response('A reconstructed capture session is required.', { status: 400 })
  }

  const resolved = await resolveSessionAndAnalysis(sessionId, new URL(request.url).origin)
  if (!resolved || !resolved.analysis) {
    return new Response('Session or capture analysis data not found.', { status: 404 })
  }

  const { session, analysis } = resolved
  const report = buildCanonicalReport(analysis, session)

  // ── Page 1: Executive Summary, Capture Overview, Protocol & TLS Analysis ────
  const page1: string[] = [
    '========================================================================================',
    '        SECUREMAILSCOPE | CRYPTOGRAPHIC SECURITY POSTURE ASSESSMENT REPORT              ',
    '========================================================================================',
    `Capture File: ${report.captureOverview.filename}`,
    `Session ID:   ${report.executiveSummary.sessionId}`,
    `Analysis Time: ${report.executiveSummary.analysisTimestamp}`,
    '',
    '------------------------------- 1. EXECUTIVE SUMMARY -----------------------------------',
    `Security Score:        ${report.executiveSummary.securityScore} / 100 (Grade: ${report.executiveSummary.grade}, Posture: ${report.executiveSummary.riskLevel})`,
    `Policy Compliance:     ${report.executiveSummary.overallConfigStatus}`,
    `Capture Integrity:     ${report.captureOverview.metadataIntegrity}`,
    `Executive Summary:     ${report.executiveSummary.aiSummary}`,
    '',
    '------------------------------- 2. CAPTURE OVERVIEW ------------------------------------',
    `Packet Count:          ${report.captureOverview.packetCount} packets`,
    `Capture Duration:      ${report.captureOverview.durationSeconds.toFixed(1)} seconds`,
    `Capture Format:        ${report.captureOverview.format}`,
    `Network Flow:          ${report.captureOverview.source} -> ${report.captureOverview.destination}`,
    '',
    '---------------------- 3. EMAIL PROTOCOL & TCP STREAM ANALYSIS -------------------------',
    `Detected Protocol:     ${report.protocolAnalysis.protocol} on Port ${report.protocolAnalysis.port} (${report.protocolAnalysis.confidence} confidence)`,
    `STARTTLS State:        ${report.protocolAnalysis.starttlsState}`,
    `STARTTLS Description:  ${report.protocolAnalysis.starttlsDescription}`,
    `STARTTLS Advertised:   ${report.protocolAnalysis.starttlsAdvertised ? 'YES' : 'NO'} | Negotiated: ${report.protocolAnalysis.starttlsNegotiated ? 'YES' : 'NO'} | Required: ${report.protocolAnalysis.starttlsRequired ? 'YES' : 'NO'}`,
    `TCP Streams Count:     ${report.tcpStreamAnalysis.totalStreams} stream(s) reconstructed (${report.tcpStreamAnalysis.status})`,
    '',
    '------------------------------ 4. TLS LAYER ANALYSIS -----------------------------------',
    `Negotiated TLS Version: ${report.tlsAnalysis.version}`,
    `Selected Cipher Suite:  ${report.tlsAnalysis.cipherSuite}`,
    `Key Exchange Algorithm: ${report.tlsAnalysis.keyExchange} (Named Group: ${report.tlsAnalysis.namedGroup})`,
    `Forward Secrecy (PFS):  ${report.tlsAnalysis.forwardSecrecy ? 'ENABLED (Ephemeral Key Exchange)' : 'DISABLED (Static Key / Vulnerable)'}`,
    `Handshake Completion:  ${report.tlsAnalysis.handshakeComplete ? 'YES (Handshake Completed Successfully)' : 'NO (Handshake Incomplete)'}`,
    '',
    '========================================================================================',
    '                                     Page 1 of 4                                        ',
    '========================================================================================',
  ]

  // ── Page 2: Certificate Analysis, 17 Security Categories, Cryptographic Strength ────
  const page2: string[] = [
    '========================================================================================',
    '                       SECUREMAILSCOPE | CRYPTOGRAPHIC AUDIT REPORT                     ',
    '========================================================================================',
    '',
    '-------------------------- 5. X.509 CERTIFICATE ANALYSIS -------------------------------',
  ]

  if (report.certificateAnalysis.present) {
    page2.push(
      `Subject Common Name:   ${report.certificateAnalysis.commonName}`,
      `Issuing CA:            ${report.certificateAnalysis.issuer} (${report.certificateAnalysis.selfSigned ? 'SELF-SIGNED' : 'CA-ISSUED'})`,
      `Validity Window:       ${report.certificateAnalysis.validFrom} to ${report.certificateAnalysis.validUntil}`,
      `Expiration Check:      ${report.certificateAnalysis.expired ? 'EXPIRED (FAIL)' : report.certificateAnalysis.notYetValid ? 'NOT YET VALID (FAIL)' : 'VALID'}`,
      `Public Key:            ${report.certificateAnalysis.publicKeyAlgorithm} ${report.certificateAnalysis.publicKeyLength} bits`,
      `Signature Algorithm:   ${report.certificateAnalysis.signatureAlgorithm}`,
      `Trust Chain Status:    ${report.certificateAnalysis.chainValid ? 'TRUSTED / VALID CHAIN' : 'UNTRUSTED / INVALID CHAIN'}`,
    )
  } else {
    page2.push('Certificate Status:    Not observable in capture stream')
  }

  page2.push(
    '',
    '------------ 6. CRYPTOGRAPHIC POSTURE ACROSS 17 SECURITY CATEGORIES --------------------',
  )
  for (let i = 0; i < report.cryptographicAssessment.categories.length; i++) {
    const cat = report.cryptographicAssessment.categories[i]
    page2.push(
      `[${String(i + 1).padStart(2, '0')}] ${cat.category.padEnd(35)} : [${cat.status.padEnd(7)}] ${cat.details.slice(0, 40)}`
    )
  }

  page2.push(
    '',
    '-------- 7. CRYPTOGRAPHIC SECURITY STRENGTH (NIST SP 800-57 Part 1 Rev. 5) ------------',
  )
  for (const item of report.cryptographicAssessment.strengthItems) {
    page2.push(
      `* ${item.component.padEnd(18)} : ${item.algorithm.padEnd(20)} | Strength: ${item.estimatedSecurityStrength.padEnd(25)} | [${item.status}]`
    )
  }

  page2.push(
    '',
    '========================================================================================',
    '                                     Page 2 of 4                                        ',
    '========================================================================================',
  )

  // ── Page 3: Configuration Compliance, Security Score Breakdown, Findings ──
  const page3: string[] = [
    '========================================================================================',
    '                       SECUREMAILSCOPE | CRYPTOGRAPHIC AUDIT REPORT                     ',
    '========================================================================================',
    '',
    '----------- 8. CONFIGURATION COMPLIANCE (CONFIGURED POLICY VS OBSERVED) ----------------',
  ]

  for (const row of report.configurationCompliance.rows.slice(0, 10)) {
    page3.push(
      `${row.parameter.padEnd(22)}: Configured: ${row.configured.padEnd(16)} | Observed: ${row.observed.padEnd(16)} [${row.status}]`
    )
  }

  page3.push(
    '',
    '------------------- 9. SECURITY SCORE DEDUCTIONS BREAKDOWN ------------------------------',
    `Overall Score: ${report.securityScore.total}/100 | Grade: ${report.securityScore.grade} | Posture: ${report.securityScore.level}`,
  )

  if (report.securityScore.deductions.length === 0) {
    page3.push('  * No score deductions. All observable parameters satisfy standards.')
  } else {
    for (const d of report.securityScore.deductions) {
      page3.push(`  * [-${String(d.points).padStart(2, '0')} pts] [${d.severity.padEnd(8)}] ${d.reason.slice(0, 68)}`)
    }
  }

  page3.push(
    '',
    `-------------------------- 10. SECURITY FINDINGS (${report.findings.length}) ---------------------------`,
  )

  if (report.findings.length === 0) {
    page3.push('  * Zero security findings identified in this session.')
  } else {
    for (const f of report.findings.slice(0, 5)) {
      page3.push(`[${f.id}] [${f.severity}] ${f.title}`)
      page3.push(`  Evidence: ${JSON.stringify(f.evidence).slice(0, 80)}`)
      page3.push(`  Action:   ${f.recommendation.slice(0, 80)}`)
    }
  }

  page3.push(
    '',
    '========================================================================================',
    '                                     Page 3 of 4                                        ',
    '========================================================================================',
  )

  // ── Page 4: Anomalies, AI Assessment, Recommendations, Standards & References ──
  const page4: string[] = [
    '========================================================================================',
    '                       SECUREMAILSCOPE | CRYPTOGRAPHIC AUDIT REPORT                     ',
    '========================================================================================',
    '',
    '------------------------------ 11. ANOMALY DETECTION -----------------------------------',
  ]

  if (report.anomalies.length === 0) {
    page4.push('  * No anomalous downgrade attempts or protocol discrepancies identified.')
  } else {
    for (const a of report.anomalies) {
      page4.push(`  * [${a.severity}] ${a.type}: ${a.evidence}`)
    }
  }

  page4.push(
    '',
    '--------------------------- 12. AI SECURITY ASSESSMENT ---------------------------------',
  )
  if (report.aiAssessment.available) {
    page4.push(`  Summary: ${report.aiAssessment.executiveSummary.slice(0, 85)}`)
    if (report.aiAssessment.riskNarrative) {
      page4.push(`  Risk:    ${report.aiAssessment.riskNarrative.slice(0, 85)}`)
    }
  } else {
    page4.push('  AI assessment unavailable. Showing deterministic security assessment.')
  }

  page4.push(
    '',
    '-------------------- 13. PRIORITIZED REMEDIATION RECOMMENDATIONS -----------------------',
  )
  for (let i = 0; i < Math.min(6, report.recommendations.length); i++) {
    page4.push(`  ${i + 1}. ${report.recommendations[i].slice(0, 85)}`)
  }

  page4.push(
    '',
    '----------------------- 14. STANDARDS & NORMATIVE REFERENCES ---------------------------',
  )
  for (const ref of report.references) {
    page4.push(`  * ${ref.name.padEnd(25)} : ${ref.document.slice(0, 40)} (${ref.section})`)
  }

  page4.push(
    '',
    '========================================================================================',
    '                                     Page 4 of 4                                        ',
    '========================================================================================',
  )

  const pdfOutput = generatePdf([page1, page2, page3, page4])

  return new Response(pdfOutput, {
    headers: {
      'Content-Type': 'application/pdf',
      'Content-Disposition': `attachment; filename="SecureMailScope_${sessionId}_report.pdf"`,
    },
  })
}
