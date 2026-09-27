import { buildForensicReport, type Session } from '@/lib/forensic-report'

export async function GET(request: Request) {
  const sessionId = new URL(request.url).searchParams.get('session')
  const sessionResponse = sessionId ? await fetch(`${new URL(request.url).origin}/api/uploads?id=${encodeURIComponent(sessionId)}`, { cache: 'no-store' }).catch(() => null) : null
  if (!sessionResponse?.ok) return new Response('A reconstructed capture session is required.', { status: 400 })
  const session = await sessionResponse.json() as Session
  const report = buildForensicReport(session)
  const lines = [
    'SecureMailScope | Forensic Report',
    `PCAP: ${report.pcapName}`,
    `Generated: ${report.analysisTime}`,
    '',
    'Capture overview',
    `Files: ${report.attachments.count} PCAP files reconstructed`,
    `Duration: ${report.captureDuration}`, `Packets: ${report.totalPackets}`, `Sessions: ${report.totalSessions}`,
    `TCP streams: ${report.tcpStreams} reconstructed`,
    `Attachments: ${report.attachments.count} files | ${(report.attachments.totalBytes / 1024 / 1024).toFixed(2)} MB total`,
    '', 'Protocol analysis',
    `SMTP: ${report.protocols.smtp} | IMAP: ${report.protocols.imap} | POP3: ${report.protocols.pop3}`,
    `STARTTLS: ${report.protocols.starttls} | TLS: ${report.protocols.tls}`,
    '', 'Security findings',
    ...report.findings.map((finding) => `${finding.severity}: ${finding.title} — ${finding.evidence}`),
    '', 'AI assessment', `Risk score: ${report.riskScore} (${report.riskLevel})`, `Anomaly sessions: ${report.anomalySessions}`,
    '', 'Recommendations', ...report.findings.map((finding) => finding.recommendation),
  ]
  const escapePdf = (value: string) => value.replaceAll('\\', '\\\\').replaceAll('(', '\\(').replaceAll(')', '\\)')
  const stream = `BT\n/F1 11 Tf\n50 760 Td\n${lines.map((line, index) => `${index ? '0 -18 Td\n' : ''}(${escapePdf(line)}) Tj`).join('\n')}\nET`
  const objects = [
    '<< /Type /Catalog /Pages 2 0 R >>',
    '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
    '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>',
    `<< /Length ${stream.length} >>\nstream\n${stream}\nendstream`,
    '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>',
  ]
  let pdf = '%PDF-1.4\n'
  const offsets = [0]
  objects.forEach((object, index) => { offsets.push(Buffer.byteLength(pdf, 'utf8')); pdf += `${index + 1} 0 obj\n${object}\nendobj\n` })
  const xref = Buffer.byteLength(pdf, 'utf8')
  pdf += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n${offsets.slice(1).map((offset) => `${String(offset).padStart(10, '0')} 00000 n `).join('\n')}\ntrailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF`
  return new Response(pdf, { headers: { 'Content-Type': 'application/pdf', 'Content-Disposition': 'attachment; filename="securemailscope-forensic-report.pdf"' } })
}
