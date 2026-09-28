import { readdir, readFile } from 'node:fs/promises'
import path from 'node:path'
import { NextResponse } from 'next/server'
import type { CanonicalAnalysis } from '@/lib/types'
import { getGroqApiKey } from '@/lib/env'


const uploadsRoot = path.join(process.cwd(), 'data', 'uploads')

async function getSessionAnalysis(sessionId: string): Promise<CanonicalAnalysis | null> {
  try {
    const folders = await readdir(uploadsRoot, { withFileTypes: true }).catch(() => [])
    const folder = folders.find(
      (entry) => entry.isDirectory() && (entry.name.includes(sessionId) || entry.name.endsWith(`-${sessionId}`))
    )
    if (!folder) return null

    const folderPath = path.join(uploadsRoot, folder.name)
    try {
      return JSON.parse(await readFile(path.join(folderPath, 'analysis.json'), 'utf8'))
    } catch {
      const session = JSON.parse(await readFile(path.join(folderPath, 'session.json'), 'utf8'))
      return session.analysis ?? null
    }
  } catch {
    return null
  }
}

function answerFromAnalysis(question: string, analysis: CanonicalAnalysis): string {
  const q = question.toLowerCase()
  const { findings, securityScore, observed, recommendations } = analysis

  if (q.includes('highest-risk') || q.includes('high') || q.includes('critical') || q.includes('severe')) {
    const highFindings = findings.filter((f) => f.severity === 'CRITICAL' || f.severity === 'HIGH')
    if (highFindings.length > 0) {
      return `The highest-risk findings identified in this capture are:\n` +
        highFindings.map((f, i) => `${i + 1}. [${f.severity}] ${f.title}: ${f.description} (Evidence: ${typeof f.evidence === 'string' ? f.evidence : f.evidence?.observed || 'observed traffic'}, Impact: ${f.impact})`).join('\n\n')
    }
    return `No critical or high-severity findings were detected in this session. The current security score is ${securityScore.total}/100 (Grade: ${securityScore.grade}). Lowest-level findings: ${findings.map(f => f.title).join(', ') || 'None'}.`
  }

  if (q.includes('fix first') || q.includes('recommend') || q.includes('priority')) {
    if (recommendations.length > 0) {
      return `Top priority remediation actions recommended for this capture:\n` +
        recommendations.slice(0, 4).map((r, i) => `${i + 1}. ${r}`).join('\n')
    }
    return `Security posture is in good standing. Maintain TLS 1.3 standards and monitor certificate expiration.`
  }

  if (q.includes('authentication') || q.includes('auth') || q.includes('plaintext') || q.includes('credential')) {
    const authFinding = findings.find(f => f.id.includes('AUTH') || f.title.toLowerCase().includes('auth') || f.description.toLowerCase().includes('plaintext'))
    if (authFinding) {
      return `Authentication analysis: ${authFinding.title}. Evidence: ${typeof authFinding.evidence === 'string' ? authFinding.evidence : authFinding.evidence?.observed || 'Observed in network stream'}. Recommendation: ${authFinding.recommendation}`
    }
    if (observed.starttls.plaintextPhaseObserved) {
      return `Plaintext SMTP commands (such as MAIL FROM / EHLO) were observed before TLS was negotiated. Recommend enforcing STARTTLS strictly.`
    }
    return `No unencrypted authentication credentials or plaintext auth data leaks were observed in this reconstructed traffic session.`
  }

  if (q.includes('certificate') || q.includes('cert') || q.includes('expire') || q.includes('ca')) {
    const cert = observed.certificate
    if (!cert.present) return `No TLS server certificate was observable in this capture stream.`
    return `Certificate details for CN "${cert.commonName}": Issued by "${cert.issuer}". Valid from ${cert.validFrom} to ${cert.validUntil}. Status: ${cert.expired ? 'EXPIRED' : 'Active/Valid'}. Trust chain: ${cert.chainValid ? 'Trusted' : 'Untrusted / Self-signed'}. Algorithm: ${cert.publicKeyAlgorithm} (${cert.publicKeyLength} bits).`
  }

  if (q.includes('score') || q.includes('grade') || q.includes('posture')) {
    return `Cryptographic security score is ${securityScore.total}/100, receiving Grade ${securityScore.grade} (${securityScore.level}). Main deductions: ${securityScore.deductions.map(d => `${d.reason} (-${d.points} pts)`).join('; ') || 'None'}.`
  }

  // General grounded summary
  const summaryParts: string[] = [
    `Session ${analysis.session.id}: Protocol ${observed.protocol.detected} (Port ${observed.protocol.port}), TLS version ${observed.tls.version}, cipher ${observed.tls.cipherSuite}, PFS ${observed.tls.forwardSecrecy ? 'active' : 'disabled'}.`,
    `Security score: ${securityScore.total}/100 (Grade ${securityScore.grade}).`,
    `${findings.length} findings recorded: ${findings.slice(0, 3).map(f => f.title).join('; ')}.`,
  ]
  return summaryParts.join(' ')
}

export async function POST(request: Request) {
  try {
    const body = await request.json()
    const question = typeof body.question === 'string' ? body.question.trim() : ''
    const sessionId = typeof body.sessionId === 'string' ? body.sessionId.trim() : ''

    if (!question || question.length > 1000) {
      return NextResponse.json({ error: 'Enter a question up to 1,000 characters.' }, { status: 400 })
    }

    let analysis: CanonicalAnalysis | null = null
    if (sessionId) {
      analysis = await getSessionAnalysis(sessionId)
    }

    // If Groq API key is present, try Groq
    const groqApiKey = getGroqApiKey()
    if (groqApiKey && analysis) {


      try {
        const groqPrompt = `You are a cryptographic forensic analyst. Answer the user question based STRICTLY on the analysis data below:\n\n${JSON.stringify({
          capture: analysis.capture,
          observed: analysis.observed,
          score: analysis.securityScore,
          findings: analysis.findings,
          recommendations: analysis.recommendations,
        }, null, 2)}\n\nQuestion: ${question}`

        const groqRes = await fetch('https://api.groq.com/openai/v1/chat/completions', {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${groqApiKey}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            model: 'llama3-8b-8192',
            messages: [{ role: 'user', content: groqPrompt }],
            temperature: 0.2,
            max_tokens: 500,
          }),
        })

        if (groqRes.ok) {
          const gData = await groqRes.json()
          const ans = gData.choices?.[0]?.message?.content
          if (ans) return NextResponse.json({ answer: ans })
        }
      } catch {
        // Fall back to rule-based grounded engine
      }
    }

    if (analysis) {
      const groundedAnswer = answerFromAnalysis(question, analysis)
      return NextResponse.json({ answer: groundedAnswer })
    }

    // Generic fallback if no specific session analysis is loaded
    return NextResponse.json({
      answer: `Analysis context for this query: Please ensure a capture session has been reconstructed in the Email Lab or Upload workspace. Findings and posture scores will be dynamically referenced to provide evidentiary answers.`,
    })
  } catch {
    return NextResponse.json({ error: 'The assistant is unavailable. Please try again.' }, { status: 500 })
  }
}

export const runtime = 'nodejs'
