'use client'

import { FormEvent, useState } from 'react'
import {
  Bot,
  BookOpen,
  ChevronDown,
  ChevronUp,
  Loader2,
  Send,
  Sparkles,
  Zap,
  ShieldCheck,
  AlertTriangle,
  FileText,
  Lightbulb,
} from 'lucide-react'
import type { CanonicalAnalysis } from '@/lib/types'
import { getStoredAnalysis } from '@/lib/analysis-storage'

const SUGGESTIONS = [
  'What is the biggest weakness in this capture?',
  'Why did the security score become 62?',
  'Why is this cipher considered weak?',
  'Explain the certificate problem.',
  'What would happen if TLS 1.0 is enabled?',
  'Which finding should be fixed first and why?',
  'Explain the STARTTLS issue.',
  'Compare configured and observed TLS.',
  'What evidence in the PCAP caused this finding?',
  'Explain this in simple language.',
  'What NIST guidance applies here?',
  'What remediation should be performed?',
  'What could an attacker theoretically attempt against this configuration?',
]

export function ReportAssistant({
  sessionId,
  analysis: propAnalysis,
}: {
  sessionId?: string
  analysis?: CanonicalAnalysis | null
}) {
  const [question, setQuestion] = useState('')
  const [answer, setAnswer] = useState('')
  const [sources, setSources] = useState<string[]>([])
  const [mode, setMode] = useState<'rag-groq' | 'deterministic' | 'no-session' | ''>('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [showSuggestions, setShowSuggestions] = useState(true)

  async function ask(event: FormEvent) {
    event.preventDefault()
    if (!question.trim() || loading) return
    setLoading(true)
    setError('')
    setAnswer('')
    setSources([])
    setMode('')
    setShowSuggestions(false)

    try {
      const currentAnalysis = propAnalysis || getStoredAnalysis()
      const response = await fetch('/api/report-assistant', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          question,
          sessionId: sessionId || currentAnalysis?.session?.id,
          analysis: currentAnalysis,
        }),
      })
      const data = await response.json()
      if (!response.ok) throw new Error(data.error || 'Failed to retrieve answer')
      setAnswer(data.answer)
      setSources(data.sources ?? [])
      setMode(data.mode ?? '')
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'Unable to answer right now.')
    } finally {
      setLoading(false)
    }
  }

  function askSuggestion(s: string) {
    setQuestion(s)
    setShowSuggestions(false)
  }

  // Parse structured answer sections if formatted with standard headers
  const renderStructuredAnswer = (text: string) => {
    // If the answer is structured with Answer / Evidence / Impact / Standard / Recommendation
    const sections: { title: string; content: string; icon: React.ReactNode; color: string }[] = []

    const sectionRegex = /(Answer|Evidence from Current Analysis|Security Impact|Applicable Standard|Recommendation)[\r\n]+([\s\S]*?)(?=(?:Answer|Evidence from Current Analysis|Security Impact|Applicable Standard|Recommendation)[\r\n]+|$)/gi
    let match: RegExpExecArray | null
    let hasSections = false

    while ((match = sectionRegex.exec(text)) !== null) {
      hasSections = true
      const heading = match[1].trim()
      const body = match[2].trim()

      let icon = <FileText className="size-4" />
      let color = 'text-[#173b64] bg-[#f0f4f8] border-[#d8e3ed]'

      if (heading.toLowerCase().includes('answer')) {
        icon = <Sparkles className="size-4 text-[#2d8d78]" />
        color = 'text-[#173b64] bg-white border-[#e2eaf3]'
      } else if (heading.toLowerCase().includes('evidence')) {
        icon = <ShieldCheck className="size-4 text-[#5f83ad]" />
        color = 'text-[#1e3a5f] bg-[#f7fafc] border-[#dce5ef]'
      } else if (heading.toLowerCase().includes('impact')) {
        icon = <AlertTriangle className="size-4 text-[#bb4e4e]" />
        color = 'text-[#7d2828] bg-[#fffafa] border-[#f4dada]'
      } else if (heading.toLowerCase().includes('standard')) {
        icon = <BookOpen className="size-4 text-[#173b64]" />
        color = 'text-[#173b64] bg-[#f8fbfe] border-[#d7e5f2]'
      } else if (heading.toLowerCase().includes('recommendation')) {
        icon = <Lightbulb className="size-4 text-[#a66b1b]" />
        color = 'text-[#6b4716] bg-[#fffdf8] border-[#faebd0]'
      }

      sections.push({ title: heading, content: body, icon, color })
    }

    if (hasSections && sections.length >= 2) {
      return (
        <div className="space-y-3.5">
          {sections.map((sec, i) => (
            <div key={i} className={`rounded-xl border p-4 shadow-xs ${sec.color}`}>
              <div className="flex items-center gap-2 mb-2 font-bold text-xs uppercase tracking-wider">
                {sec.icon}
                <span>{sec.title}</span>
              </div>
              <p className="whitespace-pre-line text-sm leading-6 text-[#243346] font-normal">
                {sec.content}
              </p>
            </div>
          ))}
        </div>
      )
    }

    return <div className="whitespace-pre-line text-sm leading-6 text-[#34455a]">{text}</div>
  }

  return (
    <section className="rounded-2xl border border-[#dce5ef] bg-[#f8fbfe] p-6" aria-labelledby="assistant-title">
      {/* Header */}
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-start gap-3">
          <div className="flex size-10 shrink-0 items-center justify-center rounded-xl bg-[#173b64] text-white">
            <Bot className="size-5" />
          </div>
          <div>
            <h2 id="assistant-title" className="font-bold text-[#173b64]">
              Forensic Report Assistant (RAG)
            </h2>
            <p className="mt-0.5 text-xs text-[#718197]">
              RAG pipeline grounded in wire capture evidence, cryptographic findings, and NIST / RFC standards.
            </p>
          </div>
        </div>
        <div className="flex items-center gap-1.5 rounded-full bg-[#e5f4ef] px-2.5 py-1 text-[10px] font-bold text-[#247c6b]">
          <Sparkles className="size-3" />
          NIST Knowledge
        </div>
      </div>

      {/* Suggestions */}
      <div className="mt-4">
        <button
          type="button"
          onClick={() => setShowSuggestions((v) => !v)}
          className="flex items-center gap-1.5 text-[11px] font-semibold text-[#5f83ad] hover:text-[#173b64]"
        >
          {showSuggestions ? <ChevronUp className="size-3.5" /> : <ChevronDown className="size-3.5" />}
          {showSuggestions ? 'Hide sample questions' : 'Show suggested sample questions'}
        </button>
        {showSuggestions && (
          <div className="mt-3 flex flex-wrap gap-2">
            {SUGGESTIONS.map((item) => (
              <button
                type="button"
                key={item}
                onClick={() => askSuggestion(item)}
                className="rounded-full border border-[#d7e1ec] bg-white px-3 py-1.5 text-[11px] font-medium text-[#52657d] hover:border-[#91a9c2] hover:bg-[#f7fbff] transition-colors"
              >
                {item}
              </button>
            ))}
          </div>
        )}
      </div>

      {/* Input */}
      <form onSubmit={ask} className="mt-4 flex gap-2">
        <input
          value={question}
          onChange={(event) => setQuestion(event.target.value)}
          placeholder="Ask any natural question about this capture, findings, standards, or remediation..."
          aria-label="Ask the forensic report"
          className="min-w-0 flex-1 rounded-xl border border-[#d7e1ec] bg-white px-4 py-3 text-sm outline-none focus:border-[#5f83ad] focus:ring-2 focus:ring-[#5f83ad]/20"
        />
        <button
          disabled={loading || !question.trim()}
          className="inline-flex items-center gap-2 rounded-xl bg-[#173b64] px-4 py-3 text-sm font-semibold text-white disabled:cursor-not-allowed disabled:opacity-50 hover:bg-[#122e4e] transition-colors"
        >
          {loading ? <Loader2 className="size-4 animate-spin" /> : <Send className="size-4" />}
          Ask
        </button>
      </form>

      {/* Answer */}
      {answer && (
        <div className="mt-4 rounded-xl border border-[#dce5ef] bg-white p-5 shadow-sm">
          <div className="mb-3 flex flex-wrap items-center justify-between gap-2 border-b border-[#edf0f5] pb-3">
            <div className="flex items-center gap-2">
              {mode === 'rag-groq' ? (
                <>
                  <Zap className="size-3.5 text-[#2d8d78]" />
                  <span className="text-[10px] font-bold uppercase tracking-wider text-[#2d8d78]">
                    Grounded RAG Answer (Groq LLM)
                  </span>
                </>
              ) : mode === 'deterministic' ? (
                <>
                  <BookOpen className="size-3.5 text-[#5f83ad]" />
                  <span className="text-[10px] font-bold uppercase tracking-wider text-[#5f83ad]">
                    Analysis-Based Grounded Answer
                  </span>
                </>
              ) : (
                <span className="text-[10px] font-bold uppercase tracking-wider text-[#8290a2]">Answer</span>
              )}
            </div>
            {sources.length > 0 && (
              <div className="flex flex-wrap gap-1">
                {sources.map((src) => (
                  <span
                    key={src}
                    className="rounded-full bg-[#eaf1f9] px-2 py-0.5 text-[10px] font-semibold text-[#173b64]"
                  >
                    {src}
                  </span>
                ))}
              </div>
            )}
          </div>
          {renderStructuredAnswer(answer)}
        </div>
      )}

      {error && (
        <p role="alert" className="mt-3 text-sm text-[#bb4e4e]">
          {error}
        </p>
      )}
    </section>
  )
}
