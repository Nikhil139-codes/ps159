import { readdir, readFile } from 'node:fs/promises'
import path from 'node:path'
import { NextResponse } from 'next/server'
import type { CanonicalAnalysis } from '@/lib/types'
import { buildCanonicalReport } from '@/lib/forensic-report'

const uploadsRoot = path.join(process.cwd(), 'data', 'uploads')

function escapeHtml(str: string | number | boolean | null | undefined): string {
  if (str === null || str === undefined) return ''
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;')
}

export async function GET(request: Request) {
  const sessionId = new URL(request.url).searchParams.get('session')
  if (!sessionId) {
    return NextResponse.json({ error: 'Session ID is required.' }, { status: 400 })
  }

  try {
    const folders = await readdir(uploadsRoot, { withFileTypes: true }).catch(() => [])
    const folder = folders.find(
      (entry) =>
        entry.isDirectory() &&
        (entry.name.includes(sessionId) || entry.name.endsWith(`-${sessionId}`))
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

    const gradeColor =
      report.executiveSummary.grade === 'A'
        ? '#15803d'
        : report.executiveSummary.grade === 'B'
        ? '#1d4ed8'
        : report.executiveSummary.grade === 'C'
        ? '#b45309'
        : '#b91c1c'

    const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>SecureMailScope Forensic Report - ${escapeHtml(report.executiveSummary.sessionId)}</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; margin: 0; padding: 32px; color: #1e293b; background: #f8fafc; line-height: 1.5; }
    .container { max-width: 960px; margin: 0 auto; background: #ffffff; padding: 40px; border-radius: 12px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.08); }
    header { border-bottom: 2px solid #e2e8f0; padding-bottom: 20px; margin-bottom: 28px; }
    .logo-badge { display: inline-block; background: #173b64; color: #ffffff; padding: 4px 10px; border-radius: 6px; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.08em; margin-bottom: 8px; }
    h1 { margin: 0 0 6px 0; font-size: 24px; color: #0f172a; }
    .subtitle { color: #64748b; font-size: 13px; margin: 0; }
    .score-box { display: flex; gap: 24px; background: #f1f5f9; border-radius: 10px; padding: 24px; margin-bottom: 32px; align-items: center; border: 1px solid #e2e8f0; }
    .grade { font-size: 56px; font-weight: 900; color: ${gradeColor}; line-height: 1; min-width: 80px; text-align: center; }
    .score-details h3 { margin: 0 0 6px 0; font-size: 18px; color: #0f172a; }
    .score-details p { margin: 0 0 4px 0; color: #475569; font-size: 13px; }
    h2 { font-size: 16px; color: #0f172a; border-bottom: 2px solid #e2e8f0; padding-bottom: 8px; margin-top: 36px; margin-bottom: 16px; text-transform: uppercase; letter-spacing: 0.05em; }
    table { width: 100%; border-collapse: collapse; margin-bottom: 20px; font-size: 12px; }
    th, td { text-align: left; padding: 8px 12px; border-bottom: 1px solid #e2e8f0; }
    th { background: #f8fafc; color: #475569; font-weight: 600; text-transform: uppercase; font-size: 10px; letter-spacing: 0.05em; }
    .badge { display: inline-block; padding: 2px 7px; border-radius: 9999px; font-size: 10px; font-weight: 700; text-transform: uppercase; }
    .badge-pass, .badge-match, .badge-strong, .badge-success { background: #dcfce7; color: #15803d; }
    .badge-fail, .badge-mismatch, .badge-deprecated, .badge-critical, .badge-high, .badge-danger { background: #fee2e2; color: #b91c1c; }
    .badge-warning, .badge-medium { background: #fef3c7; color: #b45309; }
    .badge-not_observable, .badge-neutral, .badge-info, .badge-low { background: #f1f5f9; color: #475569; }
    .finding-card { border: 1px solid #e2e8f0; border-radius: 8px; padding: 16px; margin-bottom: 14px; background: #ffffff; }
    .finding-title { font-weight: 700; font-size: 14px; color: #0f172a; display: flex; align-items: center; justify-content: space-between; }
    .finding-meta { font-size: 11px; color: #64748b; margin-top: 4px; }
    .finding-desc { font-size: 12px; color: #334155; margin-top: 6px; }
    .finding-field { margin-top: 6px; font-size: 12px; }
    .finding-field span { font-weight: 600; color: #475569; }
    .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 20px; }
    .grid-3 { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 12px; margin-bottom: 20px; }
    .stat-card { background: #f8fafc; padding: 12px 14px; border-radius: 8px; border: 1px solid #edf2f7; font-size: 12px; }
    .stat-label { font-size: 10px; font-weight: 700; text-transform: uppercase; color: #64748b; margin-bottom: 4px; }
    .stat-value { font-weight: 600; color: #0f172a; word-break: break-all; }
    .recommendations-list { padding-left: 20px; font-size: 13px; color: #334155; line-height: 1.6; }
    .footer { margin-top: 48px; padding-top: 20px; border-top: 1px solid #e2e8f0; font-size: 11px; color: #94a3b8; text-align: center; }
    @media print {
      body { background: #ffffff; padding: 0; }
      .container { box-shadow: none; padding: 0; }
    }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div class="logo-badge">SECUREMAILSCOPE &bull; FORENSIC AUDIT DELIVERABLE</div>
      <h1>Cryptographic Security Posture Assessment Report</h1>
      <p class="subtitle">Session ID: <code>${escapeHtml(report.executiveSummary.sessionId)}</code> &bull; Generated: ${escapeHtml(report.executiveSummary.analysisTimestamp)}</p>
    </header>

    <!-- 1. Executive Summary -->
    <div class="score-box">
      <div class="grade">${escapeHtml(report.executiveSummary.grade)}</div>
      <div class="score-details">
        <h3>Security Posture: ${escapeHtml(report.executiveSummary.riskLevel)} (${escapeHtml(report.executiveSummary.securityScore)} / 100)</h3>
        <p>Target Capture: <strong>${escapeHtml(report.captureOverview.filename)}</strong> (${escapeHtml(report.captureOverview.packetCount)} packets, ${escapeHtml(report.captureOverview.format)})</p>
        <p>Integrity: <strong>${escapeHtml(report.captureOverview.metadataIntegrity)}</strong> &bull; Policy Compliance: <strong>${escapeHtml(report.executiveSummary.overallConfigStatus)}</strong></p>
      </div>
    </div>

    <!-- 2. AI Assessment Summary -->
    <h2>1. Executive Summary &amp; AI Risk Narrative</h2>
    <p style="font-size: 13px; line-height: 1.6; color: #334155;">${escapeHtml(report.executiveSummary.aiSummary)}</p>
    ${report.aiAssessment.riskNarrative ? `<p style="font-size: 12px; color: #64748b; font-style: italic; background: #f8fafc; padding: 10px; border-radius: 6px; border-left: 3px solid #173b64;">${escapeHtml(report.aiAssessment.riskNarrative)}</p>` : ''}

    <!-- 3. Capture Overview -->
    <h2>2. Capture Overview</h2>
    <div class="grid-3">
      <div class="stat-card"><div class="stat-label">File Name</div><div class="stat-value">${escapeHtml(report.captureOverview.filename)}</div></div>
      <div class="stat-card"><div class="stat-label">Capture Format</div><div class="stat-value">${escapeHtml(report.captureOverview.format)}</div></div>
      <div class="stat-card"><div class="stat-label">Packet Count</div><div class="stat-value">${escapeHtml(report.captureOverview.packetCount)} packets</div></div>
      <div class="stat-card"><div class="stat-label">Capture Duration</div><div class="stat-value">${escapeHtml(report.captureOverview.durationSeconds.toFixed(1))}s</div></div>
      <div class="stat-card"><div class="stat-label">Network Source</div><div class="stat-value">${escapeHtml(report.captureOverview.source)}</div></div>
      <div class="stat-card"><div class="stat-label">Network Destination</div><div class="stat-value">${escapeHtml(report.captureOverview.destination)}</div></div>
    </div>

    <!-- 4. Email Protocol & TCP Stream Analysis -->
    <h2>3. Email Protocol &amp; TCP Stream Analysis</h2>
    <table>
      <thead>
        <tr><th>Attribute</th><th>Observed Value</th><th>Status / Context</th></tr>
      </thead>
      <tbody>
        <tr><td>Detected Protocol</td><td><strong>${escapeHtml(report.protocolAnalysis.protocol)}</strong> (Port ${escapeHtml(report.protocolAnalysis.port)})</td><td>Confidence: ${escapeHtml(report.protocolAnalysis.confidence)}</td></tr>
        <tr><td>STARTTLS State</td><td>${escapeHtml(report.protocolAnalysis.starttlsState)}</td><td>${escapeHtml(report.protocolAnalysis.starttlsDescription)}</td></tr>
        <tr><td>STARTTLS Advertised</td><td>${report.protocolAnalysis.starttlsAdvertised ? 'Yes' : 'No'}</td><td>${report.protocolAnalysis.starttlsAdvertised ? 'Offered in EHLO' : 'Not Advertised'}</td></tr>
        <tr><td>STARTTLS Negotiated</td><td>${report.protocolAnalysis.starttlsNegotiated ? 'Yes' : 'No'}</td><td>${report.protocolAnalysis.starttlsNegotiated ? 'TLS Upgrade Completed' : 'Plaintext Transport'}</td></tr>
        <tr><td>TCP Stream Count</td><td>${escapeHtml(report.tcpStreamAnalysis.totalStreams)} reconstructed stream(s)</td><td>${escapeHtml(report.tcpStreamAnalysis.status)}</td></tr>
      </tbody>
    </table>

    <!-- 5. TLS Analysis -->
    <h2>4. TLS Layer Analysis</h2>
    <table>
      <thead>
        <tr><th>TLS Parameter</th><th>Observed Value</th><th>Assessment</th></tr>
      </thead>
      <tbody>
        <tr><td>TLS Version</td><td><strong>${escapeHtml(report.tlsAnalysis.version)}</strong></td><td>${report.tlsAnalysis.version === 'TLS1.3' ? 'Modern / Recommended' : report.tlsAnalysis.version === 'TLS1.2' ? 'Standard' : 'Deprecated (RFC 8996)'}</td></tr>
        <tr><td>Cipher Suite</td><td><code>${escapeHtml(report.tlsAnalysis.cipherSuite)}</code></td><td>${report.tlsAnalysis.cipherSuite.includes('GCM') || report.tlsAnalysis.cipherSuite.includes('POLY1305') ? 'AEAD Strong' : 'Review Needed'}</td></tr>
        <tr><td>Key Exchange</td><td>${escapeHtml(report.tlsAnalysis.keyExchange)} (${escapeHtml(report.tlsAnalysis.namedGroup)})</td><td>${report.tlsAnalysis.keyExchange === 'RSA' ? 'Static / No Forward Secrecy' : 'Ephemeral Key Exchange'}</td></tr>
        <tr><td>Forward Secrecy (PFS)</td><td>${report.tlsAnalysis.forwardSecrecy ? 'ENABLED' : 'DISABLED'}</td><td>${report.tlsAnalysis.forwardSecrecy ? 'Protects past sessions' : 'Vulnerable to future decryption'}</td></tr>
        <tr><td>Handshake Status</td><td>${report.tlsAnalysis.handshakeComplete ? 'Completed' : 'Incomplete'}</td><td>${report.tlsAnalysis.handshakeComplete ? 'Normal Completion' : 'Handshake Interrupted'}</td></tr>
      </tbody>
    </table>

    <!-- 6. Certificate Analysis -->
    <h2>5. X.509 Certificate Analysis</h2>
    ${!report.certificateAnalysis.present ? '<p style="font-size: 13px; color: #64748b;">Not observable from capture.</p>' : `
    <table>
      <thead>
        <tr><th>Field</th><th>Observed Value</th><th>Compliance Check</th></tr>
      </thead>
      <tbody>
        <tr><td>Subject (Common Name)</td><td>${escapeHtml(report.certificateAnalysis.commonName)}</td><td>Present</td></tr>
        <tr><td>Issuer (CA)</td><td>${escapeHtml(report.certificateAnalysis.issuer)}</td><td>${report.certificateAnalysis.selfSigned ? 'Self-Signed (Untrusted)' : 'CA Issued'}</td></tr>
        <tr><td>Validity Range</td><td>${escapeHtml(report.certificateAnalysis.validFrom)} to ${escapeHtml(report.certificateAnalysis.validUntil)}</td><td>${report.certificateAnalysis.expired ? '<span style="color:#b91c1c; font-weight:700;">EXPIRED</span>' : 'Active Period'}</td></tr>
        <tr><td>Public Key</td><td>${escapeHtml(report.certificateAnalysis.publicKeyAlgorithm)} ${escapeHtml(report.certificateAnalysis.publicKeyLength)} bits</td><td>${report.certificateAnalysis.publicKeyLength >= 2048 ? 'Compliant (>= 2048 bits)' : 'Weak / Disallowed (< 2048 bits)'}</td></tr>
        <tr><td>Signature Algorithm</td><td>${escapeHtml(report.certificateAnalysis.signatureAlgorithm)}</td><td>${report.certificateAnalysis.signatureAlgorithm.includes('SHA1') ? 'Weak / Collision Risk' : 'Secure Hash'}</td></tr>
        <tr><td>Chain Status</td><td>${report.certificateAnalysis.chainValid ? 'Valid Trust Chain' : 'Invalid / Incomplete Chain'}</td><td>${report.certificateAnalysis.chainValid ? 'Trusted' : 'Untrusted'}</td></tr>
      </tbody>
    </table>
    `}

    <!-- 7. Cryptographic Posture Across 17 Categories -->
    <h2>6. Cryptographic Posture Across 17 Security Categories</h2>
    <table>
      <thead>
        <tr><th>#</th><th>Security Category</th><th>Evaluation Status</th><th>Details</th></tr>
      </thead>
      <tbody>
        ${report.cryptographicAssessment.categories.map((c, i) => `
          <tr>
            <td>${i + 1}</td>
            <td><strong>${escapeHtml(c.category)}</strong></td>
            <td><span class="badge badge-${c.status.toLowerCase()}">${escapeHtml(c.status)}</span></td>
            <td>${escapeHtml(c.details)}</td>
          </tr>
        `).join('')}
      </tbody>
    </table>

    <!-- 8. Cryptographic Security Strength (NIST SP 800-57) -->
    <h2>7. Cryptographic Security Strength (NIST SP 800-57 Part 1 Rev. 5)</h2>
    <table>
      <thead>
        <tr><th>Component</th><th>Algorithm</th><th>Key Parameter</th><th>Security Strength</th><th>Status</th></tr>
      </thead>
      <tbody>
        ${report.cryptographicAssessment.strengthItems.map((item) => `
          <tr>
            <td><strong>${escapeHtml(item.component)}</strong></td>
            <td>${escapeHtml(item.algorithm)}</td>
            <td>${escapeHtml(item.parameter)}</td>
            <td><strong>${escapeHtml(item.estimatedSecurityStrength)}</strong></td>
            <td><span class="badge badge-${item.status.toLowerCase()}">${escapeHtml(item.status)}</span></td>
          </tr>
        `).join('')}
      </tbody>
    </table>

    <!-- 9. Configuration Compliance (Configured vs Observed) -->
    <h2>8. Configuration Compliance (Configured vs Observed)</h2>
    <table>
      <thead>
        <tr><th>Parameter</th><th>Configured Policy</th><th>Observed Wire Traffic</th><th>Compliance Status</th><th>Standard</th></tr>
      </thead>
      <tbody>
        ${report.configurationCompliance.rows.map((row) => `
          <tr>
            <td><strong>${escapeHtml(row.parameter)}</strong></td>
            <td><code>${escapeHtml(row.configured)}</code></td>
            <td><code>${escapeHtml(row.observed)}</code></td>
            <td><span class="badge badge-${row.status.toLowerCase()}">${escapeHtml(row.status)}</span></td>
            <td>${escapeHtml(row.standardReference)}</td>
          </tr>
        `).join('')}
      </tbody>
    </table>

    <!-- 10. Security Score & Deductions -->
    <h2>9. Security Scoring &amp; Deduction Breakdown</h2>
    <p style="font-size: 13px;">Final Deterministic Score: <strong>${escapeHtml(report.securityScore.total)} / 100</strong> (Grade ${escapeHtml(report.securityScore.grade)}, Posture: ${escapeHtml(report.securityScore.level)})</p>
    ${report.securityScore.deductions.length === 0 ? '<p style="font-size: 12px; color: #15803d;">Zero score deductions. All cryptographic parameters meet baseline standards.</p>' : `
    <table>
      <thead>
        <tr><th>Severity</th><th>Impact Reason</th><th>Deduction</th></tr>
      </thead>
      <tbody>
        ${report.securityScore.deductions.map((d) => `
          <tr>
            <td><span class="badge badge-${d.severity.toLowerCase()}">${escapeHtml(d.severity)}</span></td>
            <td>${escapeHtml(d.reason)}</td>
            <td><strong style="color: #b91c1c;">-${escapeHtml(d.points)} pts</strong></td>
          </tr>
        `).join('')}
      </tbody>
    </table>
    `}

    <!-- 11. Security Findings -->
    <h2>10. Security Findings (${report.findings.length})</h2>
    ${report.findings.length === 0 ? '<p style="font-size: 13px; color: #15803d;">No security findings identified in this session.</p>' : report.findings.map((f) => `
      <div class="finding-card">
        <div class="finding-title">
          <span>${escapeHtml(f.title)}</span>
          <span class="badge badge-${f.severity.toLowerCase()}">${escapeHtml(f.severity)} (-${escapeHtml(f.deduction)} pts)</span>
        </div>
        <div class="finding-meta">ID: <code>${escapeHtml(f.id)}</code> &bull; Category: ${escapeHtml(f.category)}</div>
        <div class="finding-desc">${escapeHtml(f.description)}</div>
        <div class="finding-field"><span>Observed Evidence:</span> <code>${escapeHtml(typeof f.evidence === 'string' ? f.evidence : JSON.stringify(f.evidence))}</code></div>
        <div class="finding-field"><span>Security Impact:</span> ${escapeHtml(f.impact)}</div>
        <div class="finding-field"><span>Remediation Recommendation:</span> <strong>${escapeHtml(f.recommendation)}</strong></div>
      </div>
    `).join('')}

    <!-- 11. Attack Simulation Assessment -->
    <h2>11. Attack Simulation Assessment (Simulated Adversary Modeling)</h2>
    <div style="background: #fff5f5; border: 1px solid #fecaca; border-radius: 8px; padding: 12px; margin-bottom: 16px; font-size: 12px; color: #991b1b;">
      <strong>NOTICE (SIMULATION ONLY):</strong> Attack scenarios are simulated in an isolated model and do not represent actual exploitation or live intrusion.
    </div>
    ${report.attackSimulationAssessment && report.attackSimulationAssessment.scenarios.length > 0 ? report.attackSimulationAssessment.scenarios.map((sim) => `
      <div class="finding-card" style="border-left: 3px solid #173b64;">
        <div class="finding-title">
          <span>${escapeHtml(sim.scenarioTitle)}</span>
          <span class="badge badge-warning">SIMULATION</span>
        </div>
        <div class="finding-meta">Triggering Finding: <strong>${escapeHtml(sim.triggerFinding)}</strong> &bull; Command: <code>${escapeHtml(sim.command)}</code></div>
        <div class="finding-desc">${escapeHtml(sim.simulatedOutcome)}</div>
        <div class="finding-field"><span>Predicted Threat Flow:</span> <code>${escapeHtml(sim.attackPathSummary)}</code></div>
        <div class="finding-field"><span>Root Cause:</span> ${escapeHtml(sim.rootCause)}</div>
        <div class="finding-field"><span>Remediation Recommendation:</span> <strong>${escapeHtml(sim.remediation)}</strong></div>
      </div>
    `).join('') : '<p style="font-size: 13px; color: #15803d;">No critical attack simulation vectors applicable to current cryptographic controls.</p>'}

    <!-- 12. Anomalies -->
    <h2>12. Anomaly Detection</h2>
    ${report.anomalies.length === 0 ? '<p style="font-size: 13px; color: #15803d;">No anomalous behavior or protocol downgrade attempts detected.</p>' : report.anomalies.map((a) => `
      <div class="finding-card" style="border-left: 3px solid #b91c1c;">
        <div class="finding-title"><span>${escapeHtml(a.type)}</span><span class="badge badge-danger">${escapeHtml(a.severity)}</span></div>
        <div class="finding-desc">${escapeHtml(a.evidence)}</div>
        ${a.configured ? `<div class="finding-field"><span>Configured:</span> <code>${escapeHtml(a.configured)}</code> &bull; <span>Observed:</span> <code>${escapeHtml(a.observed)}</code></div>` : ''}
      </div>
    `).join('')}

    <!-- 13. Recommendations -->
    <h2>12. Prioritized Remediation Recommendations</h2>
    <ol class="recommendations-list">
      ${report.recommendations.length > 0 ? report.recommendations.map((r) => `<li>${escapeHtml(r)}</li>`).join('') : '<li>Maintain current security configurations and monitor for protocol updates.</li>'}
    </ol>

    <!-- 14. Standards & References -->
    <h2>13. Standards &amp; Normative References</h2>
    <table>
      <thead>
        <tr><th>Authority / Standard</th><th>Document Title</th><th>Relevant Section</th></tr>
      </thead>
      <tbody>
        ${report.references.map((ref) => `
          <tr>
            <td><strong>${escapeHtml(ref.name)}</strong></td>
            <td>${escapeHtml(ref.document)}</td>
            <td>${escapeHtml(ref.section)}</td>
          </tr>
        `).join('')}
      </tbody>
    </table>

    <div class="footer">
      Generated automatically by SecureMailScope &bull; Cryptographic Forensic Security Console<br>
      Deliverable Document ID: SecureMailScope_${escapeHtml(report.executiveSummary.sessionId)}_report.html
    </div>
  </div>
</body>
</html>`

    return new Response(html, {
      headers: {
        'Content-Type': 'text/html; charset=utf-8',
        'Content-Disposition': `attachment; filename="SecureMailScope_${sessionId}_report.html"`,
      },
    })
  } catch (err) {
    return NextResponse.json(
      { error: err instanceof Error ? err.message : 'Failed to generate HTML report' },
      { status: 500 }
    )
  }
}
