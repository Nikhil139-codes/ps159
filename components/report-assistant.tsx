'use client'

import { FormEvent, useState } from 'react'
import { Bot, Loader2, Send } from 'lucide-react'

const suggestions = ['What are the highest-risk findings?', 'Which sessions exposed authentication data?', 'What should we fix first?']

export function ReportAssistant() {
  const [question, setQuestion] = useState('')
  const [answer, setAnswer] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  async function ask(event: FormEvent) {
    event.preventDefault()
    if (!question.trim() || loading) return
    setLoading(true); setError(''); setAnswer('')
    try {
      const response = await fetch('/api/report-assistant', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ question }) })
      const data = await response.json()
      if (!response.ok) throw new Error(data.error)
      setAnswer(data.answer)
    } catch (caught) { setError(caught instanceof Error ? caught.message : 'Unable to answer right now.') }
    finally { setLoading(false) }
  }

  return <section className="mt-7 rounded-2xl border border-[#dce5ef] bg-[#f8fbfe] p-6" aria-labelledby="assistant-title">
    <div className="flex items-start gap-3"><div className="flex size-10 items-center justify-center rounded-xl bg-[#173b64] text-white"><Bot className="size-5" /></div><div><h2 id="assistant-title" className="font-bold text-[#173b64]">Ask the report</h2><p className="mt-1 text-xs text-[#718197]">A RAG assistant grounded in this generated forensic report.</p></div></div>
    <div className="mt-5 flex flex-wrap gap-2">{suggestions.map((item) => <button type="button" key={item} onClick={() => setQuestion(item)} className="rounded-full border border-[#d7e1ec] bg-white px-3 py-1.5 text-xs font-medium text-[#52657d] hover:border-[#91a9c2]">{item}</button>)}</div>
    <form onSubmit={ask} className="mt-4 flex gap-2"><input value={question} onChange={(event) => setQuestion(event.target.value)} placeholder="Ask about evidence, risk, or recommendations..." aria-label="Ask the forensic report" className="min-w-0 flex-1 rounded-xl border border-[#d7e1ec] bg-white px-4 py-3 text-sm outline-none focus:border-[#5f83ad]" /><button disabled={loading || !question.trim()} className="inline-flex items-center gap-2 rounded-xl bg-[#173b64] px-4 py-3 text-sm font-semibold text-white disabled:cursor-not-allowed disabled:opacity-50">{loading ? <Loader2 className="size-4 animate-spin" /> : <Send className="size-4" />}Ask</button></form>
    {answer && <div className="mt-4 rounded-xl border border-[#dce5ef] bg-white p-4 text-sm leading-6 text-[#34455a]"><p className="mb-1 text-xs font-bold uppercase tracking-wider text-[#2d8d78]">Report-grounded answer</p>{answer}</div>}
    {error && <p role="alert" className="mt-3 text-sm text-[#bb4e4e]">{error}</p>}
  </section>
}
