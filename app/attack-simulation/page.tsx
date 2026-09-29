'use client'

import { Suspense, useEffect, useRef, useState } from 'react'
import Link from 'next/link'
import { useSearchParams } from 'next/navigation'
import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  ChevronRight,
  Clock,
  Compass,
  CornerDownLeft,
  FileCode,
  FileSearch,
  Flame,
  Info,
  Layers,
  Lightbulb,
  Loader2,
  LockKeyhole,
  Play,
  RotateCcw,
  Scale,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Terminal,
  Zap,
} from 'lucide-react'
import { AppShell, PageHeader, StatCard, StatusBadge } from '@/components/app-shell'
import type { CanonicalAnalysis, FindingSeverity } from '@/lib/types'
import {
  getStoredAnalysis,
  saveAnalysisSession,
  handlePageLifecycle,
} from '@/lib/analysis-storage'
import {
  SIMULATION_SCENARIOS,
  SIMULATION_STAGES,
  buildAttackSimulation,
  type AttackSimulationObject,
  type SimulationScenarioId,
  type AttackPathNode,
  type SimulationStageProgress,
} from '@/lib/attack-simulation-engine'

interface TerminalLine {
  id: string
  type: 'input' | 'output' | 'system' | 'error' | 'success'
  text: string
  timestamp: string
}

function AttackSimulationView() {
  const searchParams = useSearchParams()
  const findingFromUrl = searchParams.get('finding')
  const sessionFromUrl = searchParams.get('session')

  const [analysis, setAnalysis] = useState<CanonicalAnalysis | null>(null)
  const [loading, setLoading] = useState(true)

  // Simulation State
  const [selectedScenarioId, setSelectedScenarioId] = useState<SimulationScenarioId>('tls-downgrade')
  const [simulation, setSimulation] = useState<AttackSimulationObject | null>(null)
  const [isSimulating, setIsSimulating] = useState(false)
  const [simProgressSec, setSimProgressSec] = useState(0)
  const [simStages, setSimStages] = useState<SimulationStageProgress[]>(SIMULATION_STAGES.map(s => ({ ...s, status: 'pending' })))
  const [activeStageIndex, setActiveStageIndex] = useState(-1)
  const [jsonLogs, setJsonLogs] = useState<Array<Record<string, unknown>>>([])

  // Terminal State
  const [terminalInput, setTerminalInput] = useState('')
  const [terminalHistory, setTerminalHistory] = useState<TerminalLine[]>([
    {
      id: 'init-1',
      type: 'system',
      text: 'SecureMailScope Isolated Cyber Defense Training Sandbox [v1.0.0]',
      timestamp: new Date().toLocaleTimeString(),
    },
    {
      id: 'init-2',
      type: 'system',
      text: 'NOTICE: SIMULATION ONLY. Real destructive network attacks are strictly disabled.',
      timestamp: new Date().toLocaleTimeString(),
    },
    {
      id: 'init-3',
      type: 'output',
      text: "Type 'help' for available simulation commands or 'list-attacks' to see report-aligned scenarios.",
      timestamp: new Date().toLocaleTimeString(),
    },
  ])

  const terminalBottomRef = useRef<HTMLDivElement>(null)
  const timerIntervalRef = useRef<NodeJS.Timeout | null>(null)

  // Auto-scroll terminal
  useEffect(() => {
    terminalBottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [terminalHistory, isSimulating])

  // Load Analysis
  useEffect(() => {
    handlePageLifecycle()
    let isMounted = true

    async function resolveAnalysis() {
      setLoading(true)

      // 1. Try URL session parameter
      if (sessionFromUrl) {
        try {
          const res = await fetch(`/api/analyze?session=${encodeURIComponent(sessionFromUrl)}`)
          if (res.ok) {
            const data: CanonicalAnalysis = await res.json()
            if (isMounted) {
              setAnalysis(data)
              saveAnalysisSession(data)
              setLoading(false)
              return
            }
          }
          const res2 = await fetch(`/api/uploads?id=${encodeURIComponent(sessionFromUrl)}`)
          if (res2.ok) {
            const sessionData = await res2.json()
            if (sessionData.analysis && isMounted) {
              setAnalysis(sessionData.analysis)
              saveAnalysisSession(sessionData.analysis)
              setLoading(false)
              return
            }
          }
        } catch {
          // fallback below
        }
      }

      // 2. Try sessionStorage
      const stored = getStoredAnalysis()
      if (stored && isMounted) {
        setAnalysis(stored)
        setLoading(false)
        return
      }

      if (isMounted) {
        setAnalysis(null)
        setLoading(false)
      }
    }

    resolveAnalysis()

    return () => {
      isMounted = false
    }
  }, [sessionFromUrl])

  // Automatically pick scenario based on findingFromUrl or report analysis
  useEffect(() => {
    if (!analysis) return

    let targetScenario: SimulationScenarioId = 'tls-downgrade'

    if (findingFromUrl) {
      const f = analysis.findings.find((x) => x.id === findingFromUrl)
      if (f) {
        const cat = f.category.toLowerCase()
        const title = f.title.toLowerCase()
        if (cat.includes('starttls') || title.includes('starttls')) targetScenario = 'starttls-downgrade'
        else if (cat.includes('cipher') || title.includes('3des') || title.includes('cipher')) targetScenario = 'weak-cipher'
        else if (title.includes('expired')) targetScenario = 'expired-cert'
        else if (cat.includes('cert') || title.includes('chain')) targetScenario = 'certificate-failure'
        else if (cat.includes('pfs') || title.includes('forward secrecy')) targetScenario = 'no-pfs'
        else if (title.includes('auth') || title.includes('credential')) targetScenario = 'credential-exposure'
        else if (cat.includes('tls') || title.includes('1.0') || title.includes('1.1')) targetScenario = 'tls-downgrade'
      }
    } else {
      // Find first applicable scenario
      for (const s of SIMULATION_SCENARIOS) {
        if (s.isApplicable(analysis).applicable) {
          targetScenario = s.id
          break
        }
      }
    }

    setSelectedScenarioId(targetScenario)
    const obj = buildAttackSimulation(analysis, targetScenario, findingFromUrl || undefined)
    setSimulation(obj)
  }, [analysis, findingFromUrl])

  // Clean timer on unmount
  useEffect(() => {
    return () => {
      if (timerIntervalRef.current) clearInterval(timerIntervalRef.current)
    }
  }, [])

  function addTerminalLine(type: TerminalLine['type'], text: string) {
    setTerminalHistory((prev) => [
      ...prev,
      {
        id: `line-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
        type,
        text,
        timestamp: new Date().toLocaleTimeString(),
      },
    ])
  }

  // Handle Scenario Switch
  function switchScenario(scenarioId: SimulationScenarioId) {
    if (!analysis) return
    setSelectedScenarioId(scenarioId)
    const obj = buildAttackSimulation(analysis, scenarioId)
    setSimulation(obj)
    // reset stage view
    setSimStages(SIMULATION_STAGES.map((s) => ({ ...s, status: 'pending' })))
    setActiveStageIndex(-1)
    setSimProgressSec(0)
    addTerminalLine('system', `Selected scenario: ${scenarioId} (${obj.scenarioTitle})`)
  }

  // 40-Second Staged Simulation Execution
  async function runSimulation(scenarioId?: SimulationScenarioId) {
    if (!analysis || isSimulating) return
    const targetId = scenarioId || selectedScenarioId

    // Request Groq enrichment in background or construct simulation
    let simObj = buildAttackSimulation(analysis, targetId)
    try {
      const res = await fetch('/api/attack-simulation', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          scenarioId: targetId,
          findingId: simObj.triggerFinding.id,
          analysis,
        }),
      })
      if (res.ok) {
        simObj = await res.json()
      }
    } catch {
      // Use local simulation object
    }

    setSimulation(simObj)
    setSelectedScenarioId(targetId)
    setIsSimulating(true)
    setSimProgressSec(0)
    setJsonLogs([])
    setActiveStageIndex(0)

    addTerminalLine('input', `$ simulate --scenario ${targetId}`)
    addTerminalLine('system', `[SANDBOX] Initializing isolated simulation for: ${simObj.scenarioTitle}`)
    addTerminalLine('system', `[TARGET] Weakness: [${simObj.triggerFinding.severity}] ${simObj.triggerFinding.title}`)
    addTerminalLine('system', `[SIMULATION ONLY] Starting 40-second staged threat projection...`)

    const stages = SIMULATION_STAGES.map((s) => ({ ...s, status: 'pending' as const }))
    setSimStages(stages)

    let currentSec = 0
    if (timerIntervalRef.current) clearInterval(timerIntervalRef.current)

    timerIntervalRef.current = setInterval(() => {
      currentSec += 1
      setSimProgressSec(currentSec)

      // Find current stage
      const stageIdx = SIMULATION_STAGES.findIndex((st, i) => {
        const nextTime = SIMULATION_STAGES[i + 1]?.timeSec ?? 40
        return currentSec >= st.timeSec && currentSec < nextTime
      })

      if (stageIdx !== -1) {
        setActiveStageIndex(stageIdx)
        setSimStages((prev) =>
          prev.map((s, idx) => ({
            ...s,
            status: idx < stageIdx ? 'completed' : idx === stageIdx ? 'active' : 'pending',
          }))
        )

        // Log at start of each stage boundary
        const activeStage = SIMULATION_STAGES[stageIdx]
        if (currentSec === activeStage.timeSec) {
          const logEntry = {
            stage: activeStage.stage,
            timeSec: currentSec,
            status: 'executing',
            finding: simObj.triggerFinding.title,
            control: simObj.rootCause.control,
            simulatedAction: activeStage.description,
            simulationOnly: true,
          }
          setJsonLogs((prev) => [...prev, logEntry])
          addTerminalLine('output', `> [${currentSec}s] ${activeStage.label}: ${activeStage.description}`)
        }
      }

      // Check Completion (40 seconds)
      if (currentSec >= 40) {
        if (timerIntervalRef.current) clearInterval(timerIntervalRef.current)
        setIsSimulating(false)
        setActiveStageIndex(SIMULATION_STAGES.length - 1)
        setSimStages((prev) => prev.map((s) => ({ ...s, status: 'completed' })))

        const finalLog = {
          stage: 'simulation_complete',
          status: 'completed',
          simulationOnly: true,
          outcome: simObj.impact.simulatedOutcome,
          remediationReady: true,
        }
        setJsonLogs((prev) => [...prev, finalLog])

        addTerminalLine('success', `[COMPLETED] 40-second attack simulation finalized.`)
        addTerminalLine('system', `Impact: ${simObj.impact.summary}`)
        addTerminalLine('system', `Remediation generated. View remediation panel below.`)
      }
    }, 1000)
  }

  // Fast forward / Skip to complete for convenience
  function skipToComplete() {
    if (!isSimulating || !simulation) return
    if (timerIntervalRef.current) clearInterval(timerIntervalRef.current)
    setSimProgressSec(40)
    setIsSimulating(false)
    setActiveStageIndex(SIMULATION_STAGES.length - 1)
    setSimStages((prev) => prev.map((s) => ({ ...s, status: 'completed' })))
    addTerminalLine('success', `[SKIPPED] Simulation advanced to completion.`)
    addTerminalLine('system', `Impact: ${simulation.impact.summary}`)
  }

  // Terminal Command Execution
  function handleCommandSubmit(e: React.FormEvent) {
    e.preventDefault()
    const cmd = terminalInput.trim()
    if (!cmd) return
    setTerminalInput('')
    addTerminalLine('input', `$ ${cmd}`)

    const lower = cmd.toLowerCase()

    if (lower === 'clear') {
      setTerminalHistory([])
      return
    }

    if (lower === 'help') {
      addTerminalLine('output', 'Supported simulation commands:')
      addTerminalLine('output', '  help                            - Show this manual')
      addTerminalLine('output', '  status                          - Display current security posture and active simulation')
      addTerminalLine('output', '  show-report                     - Display current PCAP findings and security score')
      addTerminalLine('output', '  list-attacks                    - List all available report-driven attack scenarios')
      addTerminalLine('output', '  simulate --scenario <id>        - Launch ~40-second staged isolated simulation')
      addTerminalLine('output', '  clear                           - Clear the terminal screen')
      addTerminalLine('output', 'Available scenario IDs:')
      addTerminalLine('output', '  tls-downgrade, starttls-downgrade, weak-cipher, certificate-failure, expired-cert, no-pfs, dos-impact')
      return
    }

    if (lower === 'status') {
      if (!analysis) {
        addTerminalLine('error', 'No active capture loaded. Please upload a PCAP or run Email Lab.')
        return
      }
      addTerminalLine(
        'output',
        `Current Posture: Score ${analysis.securityScore.total}/100 (Grade ${analysis.securityScore.grade}) | Protocol: ${analysis.observed.protocol.detected} (Port ${analysis.observed.protocol.port}) | TLS: ${analysis.observed.tls.version}`
      )
      addTerminalLine(
        'output',
        `Active Scenario: ${simulation ? simulation.scenarioTitle : 'None'} (${isSimulating ? 'SIMULATING...' : 'IDLE'})`
      )
      return
    }

    if (lower === 'show-report') {
      if (!analysis) {
        addTerminalLine('error', 'No active capture loaded.')
        return
      }
      addTerminalLine('output', `=== Canonical Security Report: ${analysis.capture.filename} ===`)
      addTerminalLine('output', `Security Score: ${analysis.securityScore.total}/100 | Grade: ${analysis.securityScore.grade}`)
      addTerminalLine('output', `Findings (${analysis.findings.length}):`)
      analysis.findings.slice(0, 5).forEach((f, i) => {
        addTerminalLine('output', `  ${i + 1}. [${f.severity}] ${f.title} (${f.id})`)
      })
      return
    }

    if (lower === 'list-attacks') {
      if (!analysis) {
        addTerminalLine('error', 'No active capture loaded.')
        return
      }
      addTerminalLine('output', 'Report-Driven Attack Scenarios:')
      SIMULATION_SCENARIOS.forEach((s) => {
        const app = s.isApplicable(analysis)
        const mark = app.applicable ? '[RECOMMENDED / EVIDENCE PRESENT]' : '[NO EVIDENCE IN REPORT]'
        addTerminalLine('output', `  • ${s.command.padEnd(38)} ${mark}`)
      })
      return
    }

    if (lower.startsWith('simulate --scenario')) {
      const parts = cmd.split(/\s+/)
      const scenarioArg = parts[2] as SimulationScenarioId
      const found = SIMULATION_SCENARIOS.find((s) => s.id === scenarioArg)
      if (found) {
        runSimulation(found.id)
      } else {
        addTerminalLine('error', `Unknown scenario: "${scenarioArg}". Type 'list-attacks' to see available IDs.`)
      }
      return
    }

    addTerminalLine('error', `Command not recognized: "${cmd}". Type 'help' for available simulation commands.`)
  }

  if (loading) {
    return (
      <AppShell>
        <div className="flex h-64 flex-col items-center justify-center gap-3">
          <Loader2 className="size-8 animate-spin text-[#173b64]" />
          <p className="text-sm text-[#718096]">Loading attack simulation environment...</p>
        </div>
      </AppShell>
    )
  }

  if (!analysis) {
    return (
      <AppShell>
        <PageHeader
          eyebrow="Adversary Simulation"
          title="Attack Simulation Sandbox"
          description="Analyze identified cryptographic weaknesses and safely project theoretical attacker exploitation paths."
        />
        <div className="rounded-2xl border border-[#dce5ef] bg-white p-12 text-center shadow-sm">
          <ShieldAlert className="mx-auto size-12 text-[#5f83ad]" />
          <h2 className="mt-4 text-lg font-bold text-[#173b64]">No Security Assessment Available</h2>
          <p className="mt-2 text-sm text-[#718096] max-w-md mx-auto">
            Please upload a network PCAP or generate a synthetic capture in the Email Lab to initialize the attack simulation engine.
          </p>
          <div className="mt-6 flex justify-center gap-4">
            <Link
              href="/lab"
              className="inline-flex items-center gap-2 rounded-xl bg-[#173b64] px-5 py-2.5 text-sm font-semibold text-white hover:bg-[#122e4e]"
            >
              Go to Email Lab
            </Link>
            <Link
              href="/upload"
              className="inline-flex items-center gap-2 rounded-xl border border-[#dce5ef] bg-white px-5 py-2.5 text-sm font-semibold text-[#173b64] hover:bg-[#f7f9fc]"
            >
              Upload PCAP
            </Link>
          </div>
        </div>
      </AppShell>
    )
  }

  const applicableScenarios = SIMULATION_SCENARIOS.filter((s) => s.isApplicable(analysis).applicable)

  return (
    <AppShell>
      {/* ── Page Header ─────────────────────────────────────── */}
      <PageHeader
        eyebrow="Cyber Defense Simulation & Training"
        title="Attack Simulation Sandbox"
        description="Non-destructive adversary projection engine analyzing the current SecureMailScope security assessment to simulate theoretical attack paths against detected weaknesses."
        action={
          <div className="flex items-center gap-2">
            <span className="rounded-full bg-[#fdeaea] px-3 py-1 text-xs font-bold text-[#bb4e4e] flex items-center gap-1.5">
              <span className="size-2 rounded-full bg-[#bb4e4e] animate-pulse" />
              SIMULATION ONLY
            </span>
          </div>
        }
      />

      {/* ── Top Stat Banner ─────────────────────────────────── */}
      <div className="mb-8 grid grid-cols-2 gap-4 sm:grid-cols-4">
        <StatCard
          label="Current Security Score"
          value={`${analysis.securityScore.total}/100`}
          detail={`Grade ${analysis.securityScore.grade} (${analysis.securityScore.level})`}
          tone={analysis.securityScore.total >= 75 ? 'green' : analysis.securityScore.total >= 50 ? 'orange' : 'red'}
        />
        <StatCard
          label="Risk Level"
          value={analysis.securityScore.total >= 80 ? 'LOW' : analysis.securityScore.total >= 60 ? 'MEDIUM' : 'HIGH'}
          detail="Calculated from wire deductions"
          tone={analysis.securityScore.total >= 80 ? 'green' : analysis.securityScore.total >= 60 ? 'orange' : 'red'}
        />
        <StatCard
          label="Detected Weaknesses"
          value={String(analysis.findings.length)}
          detail={`${analysis.findings.filter(f => f.severity === 'CRITICAL' || f.severity === 'HIGH').length} high/critical findings`}
          tone={analysis.findings.length === 0 ? 'green' : 'orange'}
        />
        <StatCard
          label="Available Simulations"
          value={`${applicableScenarios.length} / ${SIMULATION_SCENARIOS.length}`}
          detail="Report-driven scenarios"
          tone="blue"
        />
      </div>

      {/* ── Scenario Selection & Current Target ─────────────── */}
      <section className="mb-8 rounded-2xl border border-[#dce5ef] bg-white p-6 shadow-sm">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-[#edf0f5] pb-5">
          <div>
            <div className="flex items-center gap-2">
              <Compass className="size-5 text-[#173b64]" />
              <h2 className="font-bold text-[#182230] text-lg">Report-Driven Attack Scenarios</h2>
            </div>
            <p className="mt-1 text-xs text-[#718096]">
              Simulations are dynamically enabled based on confirmed weaknesses in capture &ldquo;{analysis.capture.filename}&rdquo;.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => runSimulation()}
              disabled={isSimulating}
              className="inline-flex items-center gap-2 rounded-xl bg-[#173b64] px-4 py-2.5 text-xs font-bold text-white shadow-sm hover:bg-[#122e4e] disabled:opacity-50 transition-colors"
            >
              {isSimulating ? <Loader2 className="size-4 animate-spin" /> : <Play className="size-4 fill-white" />}
              {isSimulating ? `Simulating (${simProgressSec}s / 40s)` : 'Start 40s Simulation'}
            </button>
            {isSimulating && (
              <button
                onClick={skipToComplete}
                className="rounded-xl border border-[#dce5ef] px-3 py-2 text-xs font-semibold text-[#5f83ad] hover:bg-[#f7fbff]"
              >
                Skip to End
              </button>
            )}
          </div>
        </div>

        {/* Scenario Pills */}
        <div className="mt-5">
          <p className="text-[11px] font-bold uppercase tracking-wider text-[#8290a2] mb-3">
            Select Attack Scenario:
          </p>
          <div className="grid gap-2.5 sm:grid-cols-2 lg:grid-cols-3">
            {SIMULATION_SCENARIOS.map((scenario) => {
              const check = scenario.isApplicable(analysis)
              const isSelected = selectedScenarioId === scenario.id

              return (
                <button
                  key={scenario.id}
                  onClick={() => switchScenario(scenario.id)}
                  className={`text-left rounded-xl border p-3.5 transition-all ${isSelected
                      ? 'border-[#173b64] bg-[#f0f6fc] ring-1 ring-[#173b64]'
                      : check.applicable
                        ? 'border-[#e2eaf2] bg-white hover:border-[#a8c1da] hover:bg-[#fafcfe]'
                        : 'border-[#edf0f5] bg-[#fafbfc] opacity-60'
                    }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-xs text-[#182230]">{scenario.name}</span>
                    {check.applicable ? (
                      <span className="rounded-full bg-[#e5f4ef] px-2 py-0.5 text-[10px] font-bold text-[#247c6b]">
                        AVAILABLE
                      </span>
                    ) : (
                      <span className="rounded-full bg-[#edf1f5] px-2 py-0.5 text-[10px] font-semibold text-[#8290a2]">
                        NO WEAKNESS
                      </span>
                    )}
                  </div>
                  <p className="mt-1 text-[11px] leading-4 text-[#607087] line-clamp-2">
                    {scenario.description}
                  </p>
                  <code className="mt-2 block font-mono text-[10px] text-[#5f83ad]">
                    {scenario.command}
                  </code>
                </button>
              )
            })}
          </div>
        </div>

        {/* Selected Scenario Details */}
        {simulation && (
          <div className="mt-6 rounded-xl border border-[#dce8f5] bg-[#f8fbfe] p-4 sm:p-5">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-xs font-bold text-[#8290a2] uppercase tracking-wider">
                    TARGET WEAKNESS:
                  </span>
                  <StatusBadge
                    tone={
                      simulation.triggerFinding.severity === 'CRITICAL' ||
                        simulation.triggerFinding.severity === 'HIGH'
                        ? 'danger'
                        : 'warning'
                    }
                  >
                    {simulation.triggerFinding.severity}
                  </StatusBadge>
                  <span className="font-mono text-xs text-[#8290a2]">
                    {simulation.triggerFinding.id}
                  </span>
                </div>
                <h3 className="mt-1 font-bold text-base text-[#173b64]">
                  {simulation.triggerFinding.title}
                </h3>
              </div>
              <div className="flex items-center gap-2">
                <span className="rounded-md bg-[#eaf1f9] px-2.5 py-1 text-xs font-mono font-bold text-[#173b64]">
                  {simulation.scenario}
                </span>
              </div>
            </div>

            <div className="mt-3 grid gap-3 sm:grid-cols-2 text-xs">
              <div className="rounded-lg bg-white p-3 border border-[#e5ecf3]">
                <span className="font-bold text-[#8290a2] uppercase tracking-wider text-[10px] block mb-1">
                  Observed Evidence in Capture:
                </span>
                <p className="font-mono text-[#36516d] leading-5">
                  {simulation.evidence[0]}
                </p>
              </div>
              <div className="rounded-lg bg-white p-3 border border-[#e5ecf3]">
                <span className="font-bold text-[#8290a2] uppercase tracking-wider text-[10px] block mb-1">
                  Simulated Exploit Impact:
                </span>
                <p className="text-[#607087] leading-5">
                  {simulation.impact.summary}
                </p>
              </div>
            </div>
          </div>
        )}
      </section>

      {/* ── 40-Second Simulation Stage Progress Bar ─────────── */}
      <section className="mb-8 rounded-2xl border border-[#dce5ef] bg-white p-6 shadow-sm">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-2">
            <Clock className="size-4 text-[#173b64]" />
            <h3 className="font-bold text-sm text-[#182230]">
              40-Second Staged Simulation Progress
            </h3>
          </div>
          <div className="flex items-center gap-2">
            <span className="font-mono font-bold text-xs text-[#173b64]">
              {simProgressSec}s / 40s
            </span>
            <span
              className={`rounded-full px-2 py-0.5 text-[10px] font-bold ${isSimulating
                  ? 'bg-[#fff1df] text-[#a66b1b] animate-pulse'
                  : simProgressSec >= 40
                    ? 'bg-[#e5f4ef] text-[#247c6b]'
                    : 'bg-[#edf1f5] text-[#8290a2]'
                }`}
            >
              {isSimulating ? 'SIMULATING...' : simProgressSec >= 40 ? 'COMPLETE' : 'STANDBY'}
            </span>
          </div>
        </div>

        {/* Progress bar */}
        <div className="w-full h-2.5 rounded-full bg-[#edf1f5] overflow-hidden">
          <div
            className="h-full bg-[#173b64] transition-all duration-300"
            style={{ width: `${Math.min(100, (simProgressSec / 40) * 100)}%` }}
          />
        </div>

        {/* Stages steps */}
        <div className="mt-4 grid grid-cols-2 gap-2 sm:grid-cols-5 text-xs">
          {simStages.map((stage, idx) => (
            <div
              key={stage.stage}
              className={`rounded-xl border p-2.5 transition-all ${stage.status === 'completed'
                  ? 'border-[#cce8dc] bg-[#f4faf7]'
                  : stage.status === 'active'
                    ? 'border-[#173b64] bg-[#edf4fb] ring-1 ring-[#173b64]'
                    : 'border-[#edf0f5] bg-white opacity-70'
                }`}
            >
              <div className="flex items-center justify-between mb-1">
                <span className="font-mono text-[10px] text-[#8290a2]">
                  {stage.timeSec}s
                </span>
                {stage.status === 'completed' ? (
                  <CheckCircle2 className="size-3 text-[#247c6b]" />
                ) : stage.status === 'active' ? (
                  <Loader2 className="size-3 text-[#173b64] animate-spin" />
                ) : (
                  <span className="size-2 rounded-full bg-[#d7e1ec]" />
                )}
              </div>
              <p className="font-bold text-[11px] text-[#182230] truncate">{stage.label}</p>
              <p className="text-[10px] text-[#718096] truncate mt-0.5">{stage.description}</p>
            </div>
          ))}
        </div>
      </section>

      {/* ── Simulated Terminal ──────────────────────────────── */}
      <section className="mb-8 rounded-2xl border border-[#233346] bg-[#0c141f] shadow-lg overflow-hidden text-[#c5d1de]">
        {/* Terminal Titlebar */}
        <div className="flex items-center justify-between border-b border-[#1b2737] bg-[#080d14] px-4 py-3">
          <div className="flex items-center gap-2">
            <span className="size-3 rounded-full bg-[#ff5f56]" />
            <span className="size-3 rounded-full bg-[#ffbd2e]" />
            <span className="size-3 rounded-full bg-[#27c93f]" />
            <span className="ml-3 font-mono text-xs font-semibold text-[#8ca3bd]">
              SecureMailScope Simulation Terminal (sandbox-env)
            </span>
          </div>
          <div className="flex items-center gap-2">
            <span className="rounded bg-[#132030] px-2 py-0.5 text-[10px] font-mono text-[#4db38a]">
              NON-DESTRUCTIVE SIMULATOR
            </span>
          </div>
        </div>

        {/* Terminal Screen */}
        <div className="h-80 overflow-y-auto p-4 font-mono text-xs leading-6">
          {terminalHistory.map((line) => (
            <div
              key={line.id}
              className={`flex items-start gap-2 ${line.type === 'input'
                  ? 'text-[#50e3c2] font-bold'
                  : line.type === 'system'
                    ? 'text-[#8ca3bd]'
                    : line.type === 'error'
                      ? 'text-[#ff6b6b]'
                      : line.type === 'success'
                        ? 'text-[#4cd964]'
                        : 'text-[#d7e1ec]'
                }`}
            >
              <span className="text-[#415369] select-none text-[10px] mt-0.5">[{line.timestamp}]</span>
              <span className="whitespace-pre-wrap">{line.text}</span>
            </div>
          ))}
          {isSimulating && (
            <div className="flex items-center gap-2 text-[#e5a93c] animate-pulse">
              <span className="text-[10px] text-[#415369]">[{new Date().toLocaleTimeString()}]</span>
              <span>&gt; Simulating stage [{simProgressSec}s / 40s]...</span>
            </div>
          )}
          <div ref={terminalBottomRef} />
        </div>

        {/* Command Input Form */}
        <form
          onSubmit={handleCommandSubmit}
          className="flex items-center border-t border-[#1b2737] bg-[#0a1019] px-4 py-2.5"
        >
          <span className="text-[#50e3c2] font-mono text-xs mr-2 font-bold select-none">
            securemailscope@sandbox:~$
          </span>
          <input
            type="text"
            value={terminalInput}
            onChange={(e) => setTerminalInput(e.target.value)}
            placeholder="Type 'simulate --scenario starttls-downgrade', 'help', 'status'..."
            className="flex-1 bg-transparent font-mono text-xs text-white outline-none placeholder:text-[#45576d]"
          />
          <button
            type="submit"
            className="ml-2 rounded-lg bg-[#173b64] px-3 py-1.5 text-[11px] font-mono font-semibold text-white hover:bg-[#1f4e82]"
          >
            Run
          </button>
        </form>

        {/* Quick Command Pills */}
        <div className="flex flex-wrap items-center gap-2 border-t border-[#131e2c] bg-[#070c13] px-4 py-2 text-[11px]">
          <span className="text-[#586c82] font-semibold">Quick simulation commands:</span>
          {['help', 'status', 'list-attacks', 'simulate --scenario tls-downgrade', 'simulate --scenario starttls-downgrade', 'clear'].map((cmd) => (
            <button
              key={cmd}
              type="button"
              onClick={() => {
                setTerminalInput(cmd)
              }}
              className="rounded bg-[#121c29] px-2 py-0.5 font-mono text-[10px] text-[#7895b6] hover:bg-[#1a293c] hover:text-[#50e3c2]"
            >
              {cmd}
            </button>
          ))}
        </div>
      </section>

      {/* ── Attack Simulation Logs (JSON Box) ───────────────── */}
      <section className="mb-8 rounded-2xl border border-[#dce5ef] bg-white p-6 shadow-sm">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-2">
            <FileCode className="size-5 text-[#173b64]" />
            <h3 className="font-bold text-[#182230]">Attack Simulation Logs (JSON Stream)</h3>
          </div>
          <span className="rounded-full bg-[#fdeaea] px-2.5 py-0.5 text-[10px] font-bold text-[#bb4e4e]">
            SIMULATION ONLY
          </span>
        </div>
        <p className="text-xs text-[#718096] mb-3">
          Live structured JSON event feed generated during the staged adversary simulation.
        </p>
        <div className="max-h-60 overflow-y-auto rounded-xl border border-[#edf0f5] bg-[#0f1722] p-4 font-mono text-xs text-[#a0b3c6]">
          {jsonLogs.length === 0 ? (
            <p className="text-[#52657a] italic">
              // Click &ldquo;Start 40s Simulation&rdquo; or execute &lsquo;simulate --scenario &lt;id&gt;&rsquo; in the terminal to view structured JSON logs.
            </p>
          ) : (
            jsonLogs.map((log, idx) => (
              <pre key={idx} className="mb-2 text-[11px] leading-5 text-[#50e3c2]">
                {JSON.stringify(log, null, 2)}
              </pre>
            ))
          )}
        </div>
      </section>

      {/* ── Command Information Panel ───────────────────────── */}
      {simulation && simulation.commands[0] && (
        <section className="mb-8 rounded-2xl border border-[#dce5ef] bg-white p-6 shadow-sm">
          <div className="flex items-center justify-between mb-4 border-b border-[#edf0f5] pb-3">
            <div>
              <h3 className="font-bold text-[#182230] text-base">
                Simulated Command Specification
              </h3>
              <p className="text-xs text-[#718096]">
                Evidentiary rationale and impact profile for the simulated command.
              </p>
            </div>
            <code className="rounded-lg bg-[#f0f5fb] px-3 py-1 text-xs font-mono font-bold text-[#173b64]">
              {simulation.commands[0].command}
            </code>
          </div>

          <div className="grid gap-4 sm:grid-cols-2 text-xs">
            <div className="space-y-3">
              <div>
                <span className="font-bold uppercase tracking-wider text-[10px] text-[#8290a2] block">
                  Command Purpose
                </span>
                <p className="mt-1 text-[#34455a] font-medium leading-5">
                  {simulation.commands[0].purpose}
                </p>
              </div>
              <div>
                <span className="font-bold uppercase tracking-wider text-[10px] text-[#8290a2] block">
                  What It Simulates
                </span>
                <p className="mt-1 text-[#607087] leading-5">
                  {simulation.commands[0].whatItSimulates}
                </p>
              </div>
              <div>
                <span className="font-bold uppercase tracking-wider text-[10px] text-[#8290a2] block">
                  Why It Was Selected
                </span>
                <p className="mt-1 text-[#607087] leading-5">
                  {simulation.commands[0].whySelected}
                </p>
              </div>
            </div>

            <div className="space-y-3">
              <div>
                <span className="font-bold uppercase tracking-wider text-[10px] text-[#8290a2] block">
                  Simulated Security Impact
                </span>
                <p className="mt-1 font-semibold text-[#bb4e4e] leading-5">
                  {simulation.commands[0].expectedImpact}
                </p>
              </div>
              <div>
                <span className="font-bold uppercase tracking-wider text-[10px] text-[#8290a2] block">
                  Applicable Standard
                </span>
                <p className="mt-1 font-mono text-[#173b64] leading-5">
                  {simulation.commands[0].applicableStandard}
                </p>
              </div>
              <div>
                <span className="font-bold uppercase tracking-wider text-[10px] text-[#8290a2] block">
                  Remediation
                </span>
                <p className="mt-1 text-[#247c6b] font-medium leading-5">
                  {simulation.commands[0].remediation}
                </p>
              </div>
            </div>
          </div>
        </section>
      )}

      {/* ── Dynamic Attack Path Tree ────────────────────────── */}
      {simulation && (
        <section className="mb-8 rounded-2xl border border-[#dce5ef] bg-white p-6 shadow-sm">
          <div className="flex items-center justify-between mb-4 border-b border-[#edf0f5] pb-3">
            <div>
              <h3 className="font-bold text-[#182230] text-base flex items-center gap-2">
                <Layers className="size-5 text-[#173b64]" />
                Predicted Attacker Path (Potential Threat Flow)
              </h3>
              <p className="text-xs text-[#718096] mt-0.5">
                Dynamic node tree generated from current finding &ldquo;{simulation.triggerFinding.title}&rdquo;.
              </p>
            </div>
            <span className="text-[10px] font-bold text-[#bb4e4e] bg-[#fff5f5] px-2.5 py-1 rounded-full border border-[#fdd]">
              SIMULATED THREAT PATH
            </span>
          </div>

          <div className="relative pl-6 space-y-6 before:absolute before:left-3 before:top-2 before:bottom-2 before:w-0.5 before:bg-[#dce5ef]">
            {simulation.attackPath.map((node) => (
              <div key={node.step} className="relative flex items-start gap-4">
                {/* Node icon */}
                <span
                  className={`absolute -left-6 flex size-6 items-center justify-center rounded-full text-[10px] font-bold text-white ${node.status === 'OBSERVED'
                      ? 'bg-[#173b64]'
                      : node.status === 'SIMULATED'
                        ? 'bg-[#e07b27]'
                        : 'bg-[#bb4e4e]'
                    }`}
                >
                  {node.step}
                </span>

                <div className="flex-1 rounded-xl border border-[#e5eaf1] bg-[#fbfcfe] p-4 shadow-2xs">
                  <div className="flex flex-wrap items-center justify-between gap-2 mb-1.5">
                    <span className="font-bold text-sm text-[#182230]">{node.title}</span>
                    <div className="flex items-center gap-2">
                      <span className="text-[10px] text-[#8290a2] font-semibold">{node.stage}</span>
                      <span
                        className={`rounded-full px-2 py-0.5 text-[10px] font-bold ${node.status === 'OBSERVED'
                            ? 'bg-[#eaf1f9] text-[#173b64]'
                            : node.status === 'SIMULATED'
                              ? 'bg-[#fff1df] text-[#a66b1b]'
                              : 'bg-[#fdeaea] text-[#bb4e4e]'
                          }`}
                      >
                        {node.status}
                      </span>
                    </div>
                  </div>
                  <p className="text-xs text-[#52657a] leading-5">{node.description}</p>
                </div>
              </div>
            ))}
          </div>

          <p className="mt-4 text-[11px] italic text-[#8290a2] text-center border-t border-[#edf0f5] pt-3">
            Note: This path represents a theoretical attacker attack chain. It is not an assertion of actual intrusion.
          </p>
        </section>
      )}

      {/* ── Root Cause Analysis ─────────────────────────────── */}
      {simulation && (
        <section className="mb-8 rounded-2xl border border-[#dce5ef] bg-white p-6 shadow-sm">
          <div className="flex items-center gap-2 mb-4">
            <Scale className="size-5 text-[#173b64]" />
            <h3 className="font-bold text-[#182230] text-base">Root Cause Analysis</h3>
          </div>
          <div className="grid gap-3 sm:grid-cols-2 text-xs">
            <div className="rounded-xl border border-[#edf0f5] bg-[#f8fbfe] p-4">
              <span className="font-bold uppercase tracking-wider text-[10px] text-[#8290a2] block">
                Failed Security Control:
              </span>
              <p className="mt-1 font-bold text-[#173b64] text-sm">
                {simulation.rootCause.control}
              </p>
              <p className="mt-2 text-[#475569] leading-5">{simulation.rootCause.failure}</p>
            </div>
            <div className="rounded-xl border border-[#edf0f5] bg-[#f8fbfe] p-4">
              <span className="font-bold uppercase tracking-wider text-[10px] text-[#8290a2] block">
                Causal Configuration:
              </span>
              <p className="mt-1 font-mono text-[#334155] leading-5">
                {simulation.rootCause.configuration}
              </p>
              <div className="mt-2 text-[#8290a2]">
                <strong>Evidence:</strong> {simulation.rootCause.evidence}
              </div>
            </div>
          </div>
        </section>
      )}

      {/* ── Remediation Blueprint ───────────────────────────── */}
      {simulation && (
        <section className="mb-8 rounded-2xl border border-[#dce5ef] bg-white p-6 shadow-sm">
          <div className="flex items-center justify-between mb-4 border-b border-[#edf0f5] pb-3">
            <div className="flex items-center gap-2">
              <Lightbulb className="size-5 text-[#a66b1b]" />
              <h3 className="font-bold text-[#182230] text-base">Remediation Blueprint</h3>
            </div>
            <span className="rounded-full bg-[#e5f4ef] px-2.5 py-0.5 text-xs font-bold text-[#247c6b]">
              RECOMMENDED
            </span>
          </div>

          <div className="grid gap-4 sm:grid-cols-3 text-xs">
            <div className="rounded-xl border border-[#f3d5d5] bg-[#fffafa] p-4">
              <span className="font-bold text-[#bb4e4e] uppercase tracking-wider text-[10px] block">
                1. Immediate Fix
              </span>
              <p className="mt-2 font-semibold text-[#182230] leading-5">
                {simulation.remediation.immediateFix}
              </p>
            </div>
            <div className="rounded-xl border border-[#dce9f5] bg-[#f8fbfe] p-4">
              <span className="font-bold text-[#173b64] uppercase tracking-wider text-[10px] block">
                2. Recommended Configuration
              </span>
              <p className="mt-2 font-semibold text-[#182230] leading-5 font-mono">
                {simulation.remediation.recommendedConfig}
              </p>
            </div>
            <div className="rounded-xl border border-[#d7e9e2] bg-[#f7fcf9] p-4">
              <span className="font-bold text-[#247c6b] uppercase tracking-wider text-[10px] block">
                3. Long-Term Hardening
              </span>
              <p className="mt-2 text-[#334155] leading-5">
                {simulation.remediation.longTermHardening}
              </p>
              <span className="mt-3 block font-mono text-[10px] text-[#8290a2]">
                Ref: {simulation.remediation.reference}
              </span>
            </div>
          </div>
        </section>
      )}

      {/* ── AI Assessment / Narrative (Groq) ────────────────── */}
      {simulation?.aiExplanation && (
        <section className="mb-8 rounded-2xl border border-[#dce5ef] bg-white p-6 shadow-sm">
          <div className="flex items-center gap-2 mb-3">
            <Sparkles className="size-5 text-[#2d8d78]" />
            <h3 className="font-bold text-[#182230]">AI Attack Analysis & Threat Insights</h3>
          </div>
          <div className="space-y-3 text-xs leading-6 text-[#34455a]">
            <div className="rounded-xl bg-[#f8fbfe] border border-[#dce8f5] p-4">
              <span className="font-bold text-[10px] uppercase tracking-wider text-[#173b64] block mb-1">
                Adversary Threat Narrative:
              </span>
              <p>{simulation.aiExplanation.narrative}</p>
            </div>
            <div className="rounded-xl bg-[#fffdfa] border border-[#f5ebd8] p-4">
              <span className="font-bold text-[10px] uppercase tracking-wider text-[#a66b1b] block mb-1">
                Theoretical Attacker Tactics:
              </span>
              <p>{simulation.aiExplanation.attackerTactics}</p>
            </div>
          </div>
        </section>
      )}
    </AppShell>
  )
}

export default function AttackSimulationPage() {
  return (
    <Suspense
      fallback={
        <AppShell>
          <div className="flex h-64 items-center justify-center">
            <Loader2 className="size-8 animate-spin text-[#173b64]" />
          </div>
        </AppShell>
      }
    >
      <AttackSimulationView />
    </Suspense>
  )
}
