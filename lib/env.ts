import fs from 'node:fs'
import path from 'node:path'

/**
 * Loads environment variables from local.env if present.
 * Ensures GROQ_API_KEY is available server-side without client exposure.
 */
let localEnvLoaded = false

export function loadLocalEnv() {
  if (localEnvLoaded) return
  localEnvLoaded = true

  try {
    const envPath = path.join(process.cwd(), 'local.env')
    if (fs.existsSync(envPath)) {
      const content = fs.readFileSync(envPath, 'utf8')
      const lines = content.split(/\r?\n/)
      for (const line of lines) {
        const trimmed = line.trim()
        if (!trimmed || trimmed.startsWith('#')) continue
        const eqIdx = trimmed.indexOf('=')
        if (eqIdx > 0) {
          const key = trimmed.slice(0, eqIdx).trim()
          let val = trimmed.slice(eqIdx + 1).trim()
          // Remove surrounding quotes if any
          if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
            val = val.slice(1, -1)
          }
          if (key && val && !process.env[key]) {
            process.env[key] = val
          }
        }
      }
    }
  } catch (err) {
    console.error('Failed to load local.env:', err)
  }
}

export function getGroqApiKey(): string | undefined {
  loadLocalEnv()
  return process.env.GROQ_API_KEY?.trim() || undefined
}
