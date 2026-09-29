import { readdir, readFile } from 'node:fs/promises'
import path from 'node:path'
import { NextResponse } from 'next/server'
import type { CanonicalAnalysis } from '@/lib/types'
import { getGroqApiKey } from '@/lib/env'
import {
  buildAnalysisRAGContext,
  retrieveAnalysisContext,
  generateDeterministicGroundedAnswer,
  type AnalysisRAGContext,
} from '@/lib/rag-knowledge-base'

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

/**
 * Calls Groq chat completion with robust multi-model fallback.
 */
async function callGroqRAG(
  apiKey: string,
  systemPrompt: string,
  userPrompt: string
): Promise<string | null> {
  const modelsToTry = [
    'qwen/qwen3.8-27b',
    'llama-3.3-70b-versatile',
    'llama-3.1-8b-instant',
    'openai/gpt-oss-120b',
  ]

  for (const model of modelsToTry) {
    try {
      const res = await fetch('https://api.groq.com/openai/v1/chat/completions', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${apiKey}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          model,
          messages: [
            { role: 'system', content: systemPrompt },
            { role: 'user', content: userPrompt },
          ],
          temperature: 0.2,
          max_tokens: 800,
        }),
      })

      if (res.ok) {
        const data = await res.json()
        const text = data.choices?.[0]?.message?.content?.trim()
        if (text) return text
      }
    } catch {
      // Try next model
    }
  }
  return null
}

export async function POST(request: Request) {
  try {
    const body = await request.json()
    const question = typeof body.question === 'string' ? body.question.trim() : ''
    const sessionId = typeof body.sessionId === 'string' ? body.sessionId.trim() : ''
    const clientAnalysis = body.analysis as CanonicalAnalysis | undefined

    if (!question || question.length > 1000) {
      return NextResponse.json({ error: 'Enter a question up to 1,000 characters.' }, { status: 400 })
    }

    // Resolve analysis from disk or payload
    let analysis: CanonicalAnalysis | null = null
    if (sessionId) {
      analysis = await getSessionAnalysis(sessionId)
    }
    if (!analysis && clientAnalysis && clientAnalysis.session) {
      analysis = clientAnalysis
    }

    if (!analysis) {
      return NextResponse.json({
        answer: `I cannot determine this from the analyzed capture because no active session or capture file has been loaded. Please reconstruct an email session in the Email Lab or upload a PCAP file to enable forensic queries.`,
        sources: ['SecureMailScope Engine'],
        mode: 'no-session',
      })
    }

    // Step 1: Construct Canonical Structured Context (No Raw PCAP binary)
    const ragContext: AnalysisRAGContext = buildAnalysisRAGContext(analysis)

    // Step 2: Question Understanding & Relevant Context Retrieval
    const retrieved = retrieveAnalysisContext(question, ragContext)

    // Step 3: Check Groq Availability
    const groqApiKey = getGroqApiKey()

    if (groqApiKey) {
      const systemPrompt = `You are SecureMailScope's Expert Cryptographic Forensic Assistant.
Answer arbitrary security, cryptographic, PCAP, standards, and remediation questions strictly grounded in the provided analysis context and retrieved security standards documents.

CRITICAL RULES:
1. NEVER hallucinate values or invent parameters not in the context.
2. If information is unavailable in the analyzed capture, state: "I cannot determine this from the analyzed capture."
3. NEVER assume or claim real network penetration occurred — this is forensic passive capture assessment.
4. Format your answer using this structure when appropriate:

Answer
<Clear direct response to the question>

Evidence from Current Analysis
<Specific observed values, protocols, ports, ciphers, cert parameters, or score deductions>

Security Impact
<Technical risk, architectural flaw, or vulnerability>

Applicable Standard
<Specific standard citation e.g. RFC 8996 Section 1, NIST SP 800-52 Rev. 2 Section 3.1, NIST SP 800-57 Part 1 Rev. 5 Section 5.6.1>

Recommendation
<Clear prioritized remediation actions>`

      const userPrompt = `USER QUESTION:
${question}

RETRIEVED STANDARDS KNOWLEDGE:
${retrieved.relevantDocs.map((d) => `[${d.standard} - ${d.section}]: ${d.title}\n${d.content}`).join('\n\n')}

RELEVANT CURRENT CAPTURE ANALYSIS DATA:
- Capture: ${JSON.stringify(ragContext.capture)}
- Observed Protocol & STARTTLS: ${JSON.stringify(ragContext.protocolAnalysis)}
- Observed TLS: ${JSON.stringify(ragContext.tlsAnalysis)}
- Observed Certificate: ${JSON.stringify(ragContext.certificateAnalysis)}
- Security Score: Total ${ragContext.securityScore.total}/100, Grade ${ragContext.securityScore.grade}, Deductions: ${JSON.stringify(ragContext.securityScore.deductions)}
- Relevant Findings: ${JSON.stringify(retrieved.relevantFindings)}
- Anomalies: ${JSON.stringify(ragContext.anomalies)}
- Configured vs Observed Comparison: ${JSON.stringify(ragContext.comparison)}
- Top Recommendations: ${JSON.stringify(ragContext.recommendations)}`

      const aiResponse = await callGroqRAG(groqApiKey, systemPrompt, userPrompt)

      if (aiResponse) {
        return NextResponse.json({
          answer: aiResponse,
          sources: retrieved.sources,
          mode: 'rag-groq',
        })
      }
    }

    // Step 4: Fallback if Groq unavailable or failed
    const fallback = generateDeterministicGroundedAnswer(question, ragContext, retrieved)
    const formattedAnswer = groqApiKey
      ? `AI explanation unavailable. Showing analysis-based response.\n\n${fallback.answer}`
      : `AI explanation unavailable. Showing analysis-based response.\n\n${fallback.answer}`

    return NextResponse.json({
      answer: formattedAnswer,
      sources: fallback.sources,
      mode: 'deterministic',
    })
  } catch (err) {
    console.error('Report assistant error:', err)
    return NextResponse.json(
      { error: 'The forensic assistant encountered an internal error. Please try again.' },
      { status: 500 }
    )
  }
}

export const runtime = 'nodejs'
