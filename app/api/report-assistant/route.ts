import { gateway, generateText } from 'ai'
import { NextResponse } from 'next/server'

const reportContext = `Forensic report: enterprise-mail-traffic. Capture contains 14 PCAP files grouped into one capture. 18,432 packets, 1,206 TCP sessions, 42 reconstructed streams. Protocols: SMTP 38%, TLS 34%, DNS 18%, HTTP 10%. STARTTLS was advertised on 6 SMTP sessions and negotiated on 4. Two sessions exposed authentication metadata before TLS. Certificate chain is valid but the leaf certificate expires in 19 days. Findings: 2 high, 4 medium, 7 low. High findings are plaintext SMTP authentication and weak TLS policy on one legacy relay. Recommendations: enforce STARTTLS, disable plaintext AUTH, rotate the expiring certificate, and remove TLS 1.0/1.1 support.`

export async function POST(request: Request) {
  try {
    const body = await request.json()
    const question = typeof body.question === 'string' ? body.question.trim() : ''
    if (!question || question.length > 1000) return NextResponse.json({ error: 'Enter a question up to 1,000 characters.' }, { status: 400 })

    const result = await generateText({
      model: gateway('openai/gpt-5-mini'),
      system: `You are a forensic analyst assistant. Answer only from the report context below. Be concise, explain evidence, and say when the report does not contain enough information. Do not invent packet values. Report context: ${reportContext}`,
      prompt: question,
    })
    return NextResponse.json({ answer: result.text })
  } catch {
    return NextResponse.json({ error: 'The assistant is unavailable. Please try again.' }, { status: 500 })
  }
}

export const runtime = 'nodejs'
