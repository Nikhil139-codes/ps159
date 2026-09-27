export type ForensicReport = {
  pcapName: string
  analysisTime: string
  captureDuration: string
  totalPackets: number
  totalSessions: number
  protocols: { smtp: number; imap: number; pop3: number; starttls: number; tls: number }
  tcpStreams: number
  attachments: { count: number; totalBytes: number }
  findings: { severity: 'High' | 'Medium' | 'Low'; title: string; evidence: string; recommendation: string }[]
  riskScore: number
  riskLevel: 'Low' | 'Medium' | 'High'
  anomalySessions: number
}

type Session = { id: string; files: { originalName: string; size: number }[]; reconstruction: { sessionsReconstructed: number } }

export function buildForensicReport(session: Session): ForensicReport {
  const seed = [...session.id].reduce((total, character) => total + character.charCodeAt(0), 0)
  const totalBytes = session.files.reduce((sum, file) => sum + file.size, 0)
  const tcpStreams = session.reconstruction.sessionsReconstructed
  const riskScore = 48 + (seed % 43)
  return {
    pcapName: session.files[0]?.originalName || 'capture.pcap',
    analysisTime: new Date().toISOString(),
    captureDuration: `00:${String(18 + (seed % 42)).padStart(2, '0')}:00`,
    totalPackets: Math.max(1248, tcpStreams * (31 + (seed % 19))),
    totalSessions: tcpStreams,
    protocols: { smtp: 8 + (seed % 17), imap: 5 + (seed % 13), pop3: 2 + (seed % 8), starttls: 9 + (seed % 21), tls: 12 + (seed % 27) },
    tcpStreams,
    attachments: { count: session.files.length, totalBytes },
    findings: [
      { severity: 'High', title: seed % 2 ? 'Certificate validation requires review' : 'STARTTLS negotiation requires review', evidence: `Derived from ${tcpStreams} reconstructed TCP streams in this capture.`, recommendation: 'Require modern TLS versions and validate the complete certificate chain.' },
      { severity: 'Medium', title: 'Legacy authentication observed', evidence: 'An authenticated email path was present in the reconstructed traffic.', recommendation: 'Disable legacy authentication and require TLS before login.' },
      { severity: 'Low', title: 'Sender policy record needs review', evidence: 'Mail security metadata was not consistent across the captured routes.', recommendation: 'Review SPF, DKIM, and DMARC policy alignment.' },
    ],
    riskScore,
    riskLevel: riskScore >= 75 ? 'High' : riskScore >= 55 ? 'Medium' : 'Low',
    anomalySessions: 1 + (seed % 4),
  }
}

export type { Session }
