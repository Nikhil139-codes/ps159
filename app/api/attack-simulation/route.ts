import { readdir, readFile } from 'node:fs/promises'
import path from 'node:path'
import { NextResponse } from 'next/server'
import type { CanonicalAnalysis } from '@/lib/types'
import { getGroqApiKey } from '@/lib/env'
import {
  buildAttackSimulation,
  SIMULATION_SCENARIOS,
  type SimulationScenarioId,
  type AttackSimulationObject,
} from '@/lib/attack-simulation-engine'

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
 * Calls Groq chat completion for Attack Simulation analysis with strict safety constraints.
 */
async function callGroqAttackAnalysis(
  apiKey: string,
  scenario: string,
  finding: { id: string; title: string; severity: string },
  evidence: string[],
  analysisData: { protocol: string; tls: string; cipher: string; cert: string; score: number }
): Promise<{ narrative: string; mitigationPlan: string; attackerTactics: string } | null> {
  const modelsToTry = [
    'qwen/qwen3.8-27b',
    'llama-3.3-70b-versatile',
    'llama-3.1-8b-instant',
    'openai/gpt-oss-120b',
  ]

  const systemPrompt = `You are SecureMailScope's Cyber Defense Education AI.
You are generating cybersecurity training simulations based only on the supplied security findings.
Generate non-destructive simulated attack steps.
Do not generate commands that attack real hosts, perform network flooding, intercept live traffic, steal credentials, deploy malware, or exploit external systems.
Focus purely on explaining what an adversary could theoretically attempt, why the identified weakness permits this, and how the defender remediates it according to NIST SP 800-52 Rev. 2 and RFC standards.
Respond strictly in JSON with keys:
"narrative": "Detailed narrative explaining the theoretical attack vector and why this finding is vulnerable (2-3 sentences)",
"attackerTactics": "Theoretical sequence of attacker tactics without real exploit commands (2-3 sentences)",
"mitigationPlan": "Concrete technical guidance for the system administrator to close this vulnerability (2-3 sentences)"`

  const userPrompt = `SCENARIO: ${scenario}
TRIGGERING FINDING: [${finding.severity}] ${finding.title} (${finding.id})
EVIDENCE: ${evidence.join('; ')}
ENVIRONMENT POSTURE:
- Protocol: ${analysisData.protocol}
- Observed TLS: ${analysisData.tls}
- Cipher Suite: ${analysisData.cipher}
- Certificate: ${analysisData.cert}
- Security Score: ${analysisData.score}/100`

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
          max_tokens: 600,
        }),
      })

      if (res.ok) {
        const data = await res.json()
        const content = data.choices?.[0]?.message?.content?.trim()
        if (content) {
          const match = content.match(/\{[\s\S]*\}/)
          if (match) {
            const parsed = JSON.parse(match[0])
            return {
              narrative: parsed.narrative || 'Theoretical simulation of protocol degradation.',
              attackerTactics: parsed.attackerTactics || 'Theoretical reconnaissance followed by protocol manipulation.',
              mitigationPlan: parsed.mitigationPlan || 'Enforce modern TLS standards and eliminate legacy configurations.',
            }
          }
        }
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
    const scenarioId = (body.scenarioId as SimulationScenarioId) || 'tls-downgrade'
    const findingId = typeof body.findingId === 'string' ? body.findingId.trim() : undefined
    const sessionId = typeof body.sessionId === 'string' ? body.sessionId.trim() : undefined
    const clientAnalysis = body.analysis as CanonicalAnalysis | undefined

    let analysis: CanonicalAnalysis | null = null
    if (sessionId) {
      analysis = await getSessionAnalysis(sessionId)
    }
    if (!analysis && clientAnalysis && clientAnalysis.session) {
      analysis = clientAnalysis
    }

    if (!analysis) {
      return NextResponse.json(
        { error: 'No active capture or session analysis available. Please load a capture first.' },
        { status: 400 }
      )
    }

    // Build canonical simulation object
    const simulation: AttackSimulationObject = buildAttackSimulation(analysis, scenarioId, findingId)

    // Optional Groq AI Enrichment
    const apiKey = getGroqApiKey()
    if (apiKey) {
      const ai = await callGroqAttackAnalysis(
        apiKey,
        simulation.scenarioTitle,
        simulation.triggerFinding,
        simulation.evidence,
        {
          protocol: analysis.observed.protocol.detected,
          tls: analysis.observed.tls.version,
          cipher: analysis.observed.tls.cipherSuite,
          cert: analysis.observed.certificate.commonName || 'N/A',
          score: analysis.securityScore.total,
        }
      )
      if (ai) {
        simulation.aiExplanation = ai
      }
    }

    if (!simulation.aiExplanation) {
      simulation.aiExplanation = {
        narrative: `In this theoretical simulation, an on-path adversary attempts to exploit "${simulation.triggerFinding.title}". Because the analyzed mail transport negotiated ${analysis.observed.tls.version} with cipher ${analysis.observed.tls.cipherSuite}, the session exhibits measurable cryptographic weakness.`,
        attackerTactics: `1. Adversary observes wire traffic on port ${analysis.observed.protocol.port}. 2. Adversary crafts manipulated protocol negotiation frames. 3. Target client or server falls back to downgraded controls, exposing plaintext or weak ciphertext.`,
        mitigationPlan: simulation.remediation.immediateFix + ' ' + simulation.remediation.recommendedConfig,
      }
    }

    return NextResponse.json(simulation)
  } catch (err) {
    console.error('Attack simulation error:', err)
    return NextResponse.json(
      { error: 'Failed to generate attack simulation.' },
      { status: 500 }
    )
  }
}

export async function GET(request: Request) {
  // Return list of available simulation scenarios
  const url = new URL(request.url)
  const sessionId = url.searchParams.get('session')

  let analysis: CanonicalAnalysis | null = null
  if (sessionId) {
    analysis = await getSessionAnalysis(sessionId)
  }

  const scenarios = SIMULATION_SCENARIOS.map((s) => {
    const app = analysis ? s.isApplicable(analysis) : { applicable: true }
    return {
      id: s.id,
      name: s.name,
      command: s.command,
      description: s.description,
      category: s.category,
      isApplicable: app.applicable,
      finding: app.finding?.title,
      evidence: app.evidence,
    }
  })

  return NextResponse.json({ scenarios })
}

export const runtime = 'nodejs'
