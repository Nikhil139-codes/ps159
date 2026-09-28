import fs from 'node:fs'
import path from 'node:path'

// Load local.env into process.env if present
const localEnvPath = path.join(process.cwd(), 'local.env')
if (fs.existsSync(localEnvPath)) {
  const content = fs.readFileSync(localEnvPath, 'utf8')
  for (const line of content.split(/\r?\n/)) {
    const trimmed = line.trim()
    if (!trimmed || trimmed.startsWith('#')) continue
    const eqIdx = trimmed.indexOf('=')
    if (eqIdx > 0) {
      const key = trimmed.slice(0, eqIdx).trim()
      let val = trimmed.slice(eqIdx + 1).trim()
      if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
        val = val.slice(1, -1)
      }
      if (key && val && !process.env[key]) {
        process.env[key] = val
      }
    }
  }
}

/** @type {import('next').NextConfig} */
const nextConfig = {
  typescript: {
    ignoreBuildErrors: true,
  },
  images: {
    unoptimized: true,
  },
}

export default nextConfig

