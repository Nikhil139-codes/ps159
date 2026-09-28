/**
 * SecureMailScope PCAPNG Generator
 *
 * Creates deterministic PCAPNG files from a LabConfiguration.
 *
 * Architecture:
 *  - Uses PCAPNG format (RFC 2324) to support custom metadata blocks.
 *  - Embeds encrypted LabConfiguration in a Custom Block (type 0x00000BAD).
 *  - The encryption key is read from SECUREMAIL_CONFIG_KEY env var (server-side only).
 *  - Falls back to a deterministic key derived from a fixed salt if env var is absent.
 *
 * IMPORTANT: This is a "Simulated Testbed" — the packet bytes represent
 * realistic SMTP/TLS protocol exchanges as would appear in a real tcpdump
 * capture, but are constructed deterministically from the configuration
 * rather than from a live network interface. All field values (TLS version,
 * cipher suite, certificate metadata, STARTTLS behavior) are derived
 * directly from the LabConfiguration, so configured == observed by design,
 * unless the configuration deliberately specifies a mismatch scenario.
 *
 * Label: "Simulated Testbed" — not live packet capture.
 */

import { createCipheriv, createHash, randomBytes } from 'node:crypto'
import type {
  LabConfiguration,
  EncryptedConfigManifest,
  TlsVersion,
  CipherSuite,
  StarttlsMode,
} from './types'

// ─── Encryption ──────────────────────────────────────────────────────────────

const FIXED_SALT =
  '53656375726544616261736553636f70652d4b657953616c74' // hex: "SecureDatabaseScope-KeySalt"

function getEncryptionKey(): Buffer {
  const envKey = process.env.SECUREMAIL_CONFIG_KEY
  if (envKey) {
    // Derive 32-byte key from the env variable using SHA-256
    return createHash('sha256').update(envKey).digest()
  }
  // Fallback: deterministic key from fixed salt (acceptable for dev/demo)
  return createHash('sha256').update(FIXED_SALT, 'hex').digest()
}

export function encryptConfig(config: LabConfiguration): EncryptedConfigManifest {
  const key = getEncryptionKey()
  const iv = randomBytes(12) // 96-bit IV for AES-256-GCM
  const plaintext = JSON.stringify(config)
  const configHash = createHash('sha256').update(plaintext).digest('hex')
  const cipher = createCipheriv('aes-256-gcm', key, iv)
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()])
  const authTag = cipher.getAuthTag()
  return {
    algorithm: 'AES-256-GCM',
    iv: iv.toString('base64'),
    authTag: authTag.toString('base64'),
    ciphertext: encrypted.toString('base64'),
    configHash,
    schemaVersion: config.schemaVersion,
    sessionId: config.sessionId,
    generatorVersion: config.metadata.generatorVersion,
  }
}

export function decryptConfig(
  manifest: EncryptedConfigManifest,
): { config: LabConfiguration; hashValid: boolean } | { error: string } {
  try {
    const key = getEncryptionKey()
    const iv = Buffer.from(manifest.iv, 'base64')
    const authTag = Buffer.from(manifest.authTag, 'base64')
    const ciphertext = Buffer.from(manifest.ciphertext, 'base64')
    const { createDecipheriv } = require('node:crypto') as typeof import('node:crypto')
    const decipher = createDecipheriv('aes-256-gcm', key, iv)
    decipher.setAuthTag(authTag)
    const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()])
    const plaintext = decrypted.toString('utf8')
    const config = JSON.parse(plaintext) as LabConfiguration
    const recalcHash = createHash('sha256').update(plaintext).digest('hex')
    const hashValid = recalcHash === manifest.configHash
    return { config, hashValid }
  } catch (err) {
    return {
      error: err instanceof Error ? err.message : 'Decryption failed',
    }
  }
}

// ─── PCAPNG Block Builders ────────────────────────────────────────────────────

/** PCAPNG Section Header Block (SHB) — required first block */
function buildSHB(): Buffer {
  const byteOrderMagic = 0x1a2b3c4d
  const majorVersion = 1
  const minorVersion = 0
  const sectionLength = BigInt(-1) // unknown

  // Block type + total length (placeholder) + body + total length (repeated)
  const body = Buffer.alloc(12)
  body.writeUInt32LE(byteOrderMagic, 0)
  body.writeUInt16LE(majorVersion, 4)
  body.writeUInt16LE(minorVersion, 6)
  body.writeBigInt64LE(sectionLength, 4) // overwrite last 8 bytes

  const blockType = 0x0a0d0d0a
  const totalLength = 4 + 4 + body.length + 4 // type + len + body + len
  const block = Buffer.alloc(totalLength)
  block.writeUInt32LE(blockType, 0)
  block.writeUInt32LE(totalLength, 4)
  body.copy(block, 8)
  block.writeUInt32LE(totalLength, 8 + body.length)
  return block
}

/** PCAPNG Interface Description Block (IDB) */
function buildIDB(): Buffer {
  // Link type 1 = Ethernet
  const body = Buffer.alloc(4)
  body.writeUInt16LE(1, 0)   // linktype
  body.writeUInt16LE(0, 2)   // reserved

  const blockType = 0x00000001
  const totalLength = 4 + 4 + body.length + 4
  const block = Buffer.alloc(totalLength)
  block.writeUInt32LE(blockType, 0)
  block.writeUInt32LE(totalLength, 4)
  body.copy(block, 8)
  block.writeUInt32LE(totalLength, 8 + body.length)
  return block
}

/** Build an Enhanced Packet Block (EPB) wrapping raw packet data */
function buildEPB(packetData: Buffer, timestampUs: bigint): Buffer {
  const interfaceId = 0
  const tsHigh = Number(timestampUs / BigInt(0x100000000))
  const tsLow = Number(timestampUs % BigInt(0x100000000))
  const capturedLen = packetData.length
  const originalLen = packetData.length

  // Pad packet data to 32-bit boundary
  const pad = (4 - (capturedLen % 4)) % 4
  const paddedData = pad > 0 ? Buffer.concat([packetData, Buffer.alloc(pad)]) : packetData

  const body = Buffer.alloc(16 + paddedData.length)
  body.writeUInt32LE(interfaceId, 0)
  body.writeUInt32LE(tsHigh, 4)
  body.writeUInt32LE(tsLow, 8)
  body.writeUInt32LE(capturedLen, 12)
  body.writeUInt32LE(originalLen, 16) // Hmm, 16+paddedData won't align, let's fix
  // Actually body layout: ifaceId(4) + tsHigh(4) + tsLow(4) + capLen(4) + origLen(4) = 20 bytes before data
  const body2 = Buffer.alloc(20 + paddedData.length)
  body2.writeUInt32LE(interfaceId, 0)
  body2.writeUInt32LE(tsHigh, 4)
  body2.writeUInt32LE(tsLow, 8)
  body2.writeUInt32LE(capturedLen, 12)
  body2.writeUInt32LE(originalLen, 16)
  paddedData.copy(body2, 20)

  const blockType = 0x00000006
  const totalLength = 4 + 4 + body2.length + 4
  const block = Buffer.alloc(totalLength)
  block.writeUInt32LE(blockType, 0)
  block.writeUInt32LE(totalLength, 4)
  body2.copy(block, 8)
  block.writeUInt32LE(totalLength, 8 + body2.length)
  return block
}

/** PCAPNG Custom Block (type 0x00000BAD) — for SecureMailScope metadata */
function buildCustomBlock(manifest: EncryptedConfigManifest): Buffer {
  const pen = 0x53654d53 // PEN "SeMS" (SecureMailScope) — private enterprise number
  const data = Buffer.from(JSON.stringify(manifest), 'utf8')

  const blockType = 0x00000bad
  const bodyLen = 4 + data.length // PEN + data
  const pad = (4 - (bodyLen % 4)) % 4
  const totalLength = 4 + 4 + 4 + data.length + pad + 4

  const block = Buffer.alloc(totalLength)
  block.writeUInt32LE(blockType, 0)
  block.writeUInt32LE(totalLength, 4)
  block.writeUInt32LE(pen, 8)
  data.copy(block, 12)
  block.writeUInt32LE(totalLength, totalLength - 4)
  return block
}

// ─── Packet builders — Simulated Testbed ─────────────────────────────────────

function buildEthernetIPv4TCP(
  srcMac: Buffer,
  dstMac: Buffer,
  srcIp: number[],
  dstIp: number[],
  srcPort: number,
  dstPort: number,
  tcpFlags: number,
  seq: number,
  ack: number,
  payload: Buffer,
): Buffer {
  // Ethernet header (14 bytes)
  const eth = Buffer.alloc(14)
  dstMac.copy(eth, 0)
  srcMac.copy(eth, 6)
  eth.writeUInt16BE(0x0800, 12) // IPv4

  // IPv4 header (20 bytes minimal)
  const ipPayloadLen = 20 + payload.length // TCP hdr + payload
  const ip = Buffer.alloc(20)
  ip[0] = 0x45 // version=4, IHL=5
  ip[1] = 0x00 // DSCP
  ip.writeUInt16BE(ipPayloadLen + 20, 2) // total length
  ip.writeUInt16BE(0x1234, 4) // identification
  ip.writeUInt16BE(0x4000, 6) // Don't fragment
  ip[8] = 64 // TTL
  ip[9] = 0x06 // protocol TCP
  // checksum = 0 (not computed for simulated testbed)
  srcIp.forEach((b, i) => { ip[12 + i] = b })
  dstIp.forEach((b, i) => { ip[16 + i] = b })

  // TCP header (20 bytes)
  const tcp = Buffer.alloc(20)
  tcp.writeUInt16BE(srcPort, 0)
  tcp.writeUInt16BE(dstPort, 2)
  tcp.writeUInt32BE(seq, 4)
  tcp.writeUInt32BE(ack, 8)
  tcp[12] = 0x50 // data offset = 5 (20 bytes)
  tcp[13] = tcpFlags
  tcp.writeUInt16BE(65535, 14) // window
  // checksum = 0

  return Buffer.concat([eth, ip, tcp, payload])
}

const CLIENT_MAC = Buffer.from([0x02, 0x00, 0x00, 0x00, 0x00, 0x01])
const SERVER_MAC = Buffer.from([0x02, 0x00, 0x00, 0x00, 0x00, 0x02])
const CLIENT_IP = [172, 30, 0, 2]
const SERVER_IP = [172, 30, 0, 3]

const TCP_SYN = 0x02
const TCP_SYN_ACK = 0x12
const TCP_ACK = 0x10
const TCP_PUSH_ACK = 0x18
const TCP_FIN_ACK = 0x11

function text(s: string): Buffer { return Buffer.from(s, 'ascii') }

// ─── TLS record builders (simulated) ─────────────────────────────────────────

/** TLS ClientHello record — content reflects the configured TLS version and cipher */
function buildTlsClientHello(config: LabConfiguration): Buffer {
  const tlsVer = tlsVersionBytes(config.tls.version)
  const cipherBytes = cipherSuiteBytes(config.tls.cipherSuite)
  const namedGroupBytes = namedGroupExtBytes(config.tls.namedGroup)

  // Simplified ClientHello structure
  // TLS record: type(1) + version(2) + length(2) + handshake...
  const random = Buffer.alloc(32, 0xab) // deterministic
  const sessionId = Buffer.alloc(0)
  const ciphers = Buffer.concat([
    Buffer.from([0x00, 0x02]), // cipher list length
    cipherBytes,
  ])
  const compression = Buffer.from([0x01, 0x00]) // 1 method, no compression

  // Extensions: supported_versions, supported_groups, key_share
  const supportedVersionsExt = buildSupportedVersionsExt(config.tls.version)
  const supportedGroupsExt = buildSupportedGroupsExt(namedGroupBytes)
  const extensions = Buffer.concat([supportedVersionsExt, supportedGroupsExt])
  const extLength = Buffer.alloc(2)
  extLength.writeUInt16BE(extensions.length, 0)

  const handshakeBody = Buffer.concat([
    Buffer.from([0x03, 0x03]), // legacy_version = TLS 1.2
    random,
    Buffer.from([sessionId.length]),
    sessionId,
    ciphers,
    compression,
    extLength,
    extensions,
  ])

  const handshake = Buffer.concat([
    Buffer.from([0x01]), // ClientHello
    uint24(handshakeBody.length),
    handshakeBody,
  ])

  const record = Buffer.concat([
    Buffer.from([0x16, ...tlsVer]), // TLS Handshake
    uint16BE(handshake.length),
    handshake,
  ])
  return record
}

/** TLS ServerHello record */
function buildTlsServerHello(config: LabConfiguration): Buffer {
  const tlsVer = tlsVersionBytes(config.tls.version)
  const cipherBytes = cipherSuiteBytes(config.tls.cipherSuite)
  const random = Buffer.alloc(32, 0xcd)

  // In TLS 1.3, legacy_version is 0x0303 and real version is in supported_versions extension.
  // In TLS 1.0 - 1.2, version is directly in legacy_version.
  const legacyVerBytes = config.tls.version === 'TLS1.3'
    ? Buffer.from([0x03, 0x03])
    : Buffer.from(tlsVer)

  let extensions = Buffer.alloc(0)
  if (config.tls.version === 'TLS1.3') {
    const ext = buildServerSupportedVersionExt()
    extensions = Buffer.concat([uint16BE(ext.length), ext])
  }

  const handshakeBody = Buffer.concat([
    legacyVerBytes,
    random,
    Buffer.from([0x00]), // session_id length = 0
    cipherBytes,
    Buffer.from([0x00]), // compression_method
    ...extensions.length > 0 ? [extensions] : [],
  ])

  const handshake = Buffer.concat([
    Buffer.from([0x02]), // ServerHello
    uint24(handshakeBody.length),
    handshakeBody,
  ])

  return Buffer.concat([
    Buffer.from([0x16, ...tlsVer]),
    uint16BE(handshake.length),
    handshake,
  ])
}

/** TLS Certificate record (simulated — cert metadata matches config) */
function buildTlsCertificate(config: LabConfiguration): Buffer {
  // Embed cert info as ASN.1-like placeholder with real field values
  // This is a simulated representation — not a real DER-encoded cert
  const certInfo = JSON.stringify({
    commonName: config.certificate.commonName,
    issuer: config.certificate.issuer,
    validFrom: config.certificate.validFrom,
    validUntil: config.certificate.validUntil,
    publicKeyAlgorithm: config.certificate.publicKeyAlgorithm,
    publicKeyLength: config.certificate.publicKeyLength,
    signatureAlgorithm: config.certificate.signatureAlgorithm,
    chainValid: config.certificate.chainValid,
    scenario: config.certificate.scenario,
    _label: 'SecureMailScope-SimulatedCert-v1',
  })
  const certData = Buffer.from(certInfo, 'utf8')

  const handshakeBody = Buffer.concat([
    uint24(certData.length + 3),       // certificate_list length
    uint24(certData.length),            // cert length
    certData,                           // cert data
  ])

  const handshake = Buffer.concat([
    Buffer.from([0x0b]),               // Certificate
    uint24(handshakeBody.length),
    handshakeBody,
  ])

  const tlsVer = tlsVersionBytes(config.tls.version)
  return Buffer.concat([
    Buffer.from([0x16, ...tlsVer]),
    uint16BE(handshake.length),
    handshake,
  ])
}

// ─── TLS encoding helpers ─────────────────────────────────────────────────────

function tlsVersionBytes(v: TlsVersion): [number, number] {
  switch (v) {
    case 'TLS1.0': return [0x03, 0x01]
    case 'TLS1.1': return [0x03, 0x02]
    case 'TLS1.2': return [0x03, 0x03]
    case 'TLS1.3': return [0x03, 0x04]
    default: return [0x03, 0x03]
  }
}

function cipherSuiteBytes(cs: CipherSuite): Buffer {
  const map: Record<CipherSuite, [number, number]> = {
    'TLS_AES_128_GCM_SHA256': [0x13, 0x01],
    'TLS_AES_256_GCM_SHA384': [0x13, 0x02],
    'TLS_CHACHA20_POLY1305_SHA256': [0x13, 0x03],
    'ECDHE-RSA-AES128-GCM-SHA256': [0xc0, 0x2f],
    'ECDHE-RSA-AES256-GCM-SHA384': [0xc0, 0x30],
    'ECDHE-ECDSA-AES128-GCM-SHA256': [0xc0, 0x2b],
    'ECDHE-ECDSA-AES256-GCM-SHA384': [0xc0, 0x2c],
    'AES128-SHA': [0x00, 0x2f],
    'AES256-SHA': [0x00, 0x35],
    'TLS_RSA_WITH_3DES_EDE_CBC_SHA': [0x00, 0x0a],
  }
  const bytes = map[cs] ?? [0x00, 0x00]
  return Buffer.from(bytes)
}

function namedGroupExtBytes(ng: string): Buffer {
  const map: Record<string, [number, number]> = {
    'X25519': [0x00, 0x1d],
    'X448': [0x00, 0x1e],
    'secp256r1': [0x00, 0x17],
    'secp384r1': [0x00, 0x18],
    'secp521r1': [0x00, 0x19],
  }
  const bytes = map[ng] ?? [0x00, 0x1d]
  return Buffer.from(bytes)
}

function buildSupportedVersionsExt(v: TlsVersion): Buffer {
  // Extension type 0x002b (supported_versions)
  const versionBytes = tlsVersionBytes(v)
  const inner = Buffer.from([0x02, ...versionBytes]) // list of 1 version (2 bytes)
  const ext = Buffer.alloc(6 + inner.length)
  ext.writeUInt16BE(0x002b, 0) // type
  ext.writeUInt16BE(inner.length + 0, 2) // hmm: inner.length includes the length byte
  // Fix: ext = type(2) + ext_len(2) + list_len(1) + version(2)
  const fixed = Buffer.from([0x00, 0x2b, 0x00, 0x03, 0x02, ...versionBytes])
  return fixed
}

function buildServerSupportedVersionExt(): Buffer {
  // For TLS 1.3 ServerHello, supported_versions ext
  return Buffer.from([0x00, 0x2b, 0x00, 0x02, 0x03, 0x04])
}

function buildSupportedGroupsExt(groupBytes: Buffer): Buffer {
  // Extension type 0x000a
  // ext = type(2) + ext_len(2) + groups_list_len(2) + group(2)
  return Buffer.from([0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, groupBytes[0], groupBytes[1]])
}

function uint16BE(n: number): Buffer {
  const b = Buffer.alloc(2)
  b.writeUInt16BE(n, 0)
  return b
}

function uint24(n: number): Buffer {
  return Buffer.from([(n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff])
}

// ─── SMTP protocol helpers ────────────────────────────────────────────────────

function smtpBanner(server: string): Buffer {
  return text(`220 ${server} ESMTP Postfix (Simulated Testbed)\r\n`)
}

function smtpEhloResponse(server: string, offerStarttls: boolean): Buffer {
  let resp = `250-${server}\r\n`
  if (offerStarttls) resp += `250-STARTTLS\r\n`
  resp += `250-SIZE 10240000\r\n`
  resp += `250-AUTH PLAIN LOGIN\r\n`
  resp += `250 ENHANCEDSTATUSCODES\r\n`
  return text(resp)
}

function smtpStarttlsResponse(): Buffer {
  return text(`220 2.0.0 Ready to start TLS\r\n`)
}

// ─── Main generator ───────────────────────────────────────────────────────────

/**
 * Generate a PCAPNG file from a LabConfiguration.
 *
 * The returned Buffer is a valid PCAPNG file that:
 * 1. Contains simulated SMTP/TLS packet exchange matching the configuration
 * 2. Has encrypted LabConfiguration embedded in a Custom Block
 *
 * Label: Simulated Testbed — not live capture.
 */
export function generatePcapng(config: LabConfiguration): Buffer {
  const blocks: Buffer[] = []

  // ── SHB + IDB ──
  blocks.push(buildSHB())
  blocks.push(buildIDB())

  // ── Encrypted config block (first) ──
  const manifest = encryptConfig(config)
  blocks.push(buildCustomBlock(manifest))

  // ── Simulated packet stream ──
  const srcPort = 50000 + (Math.abs(hashStr(config.sessionId)) % 10000)
  const dstPort = config.email.port
  let ts = BigInt(Date.now()) * BigInt(1000) // microseconds
  let clientSeq = 1000
  let serverSeq = 2000

  function addClientPacket(payload: Buffer, flags: number = TCP_PUSH_ACK) {
    const pkt = buildEthernetIPv4TCP(
      CLIENT_MAC, SERVER_MAC,
      CLIENT_IP, SERVER_IP,
      srcPort, dstPort,
      flags, clientSeq, serverSeq,
      payload,
    )
    blocks.push(buildEPB(pkt, ts))
    ts += BigInt(5000) + BigInt(payload.length * 10)
    clientSeq += payload.length || 1
  }

  function addServerPacket(payload: Buffer, flags: number = TCP_PUSH_ACK) {
    const pkt = buildEthernetIPv4TCP(
      SERVER_MAC, CLIENT_MAC,
      SERVER_IP, CLIENT_IP,
      dstPort, srcPort,
      flags, serverSeq, clientSeq,
      payload,
    )
    blocks.push(buildEPB(pkt, ts))
    ts += BigInt(5000) + BigInt(payload.length * 10)
    serverSeq += payload.length || 1
  }

  // TCP 3-way handshake
  addClientPacket(Buffer.alloc(0), TCP_SYN)
  addServerPacket(Buffer.alloc(0), TCP_SYN_ACK)
  addClientPacket(Buffer.alloc(0), TCP_ACK)

  const usesStarttls =
    config.email.starttls &&
    config.email.starttlsMode !== 'disabled' &&
    config.tls.version !== 'None'
  const isStarttlsIssueScenario = config.testScenario === 'starttls_issue'

  const emitTlsHandshakeAndData = () => {
    addClientPacket(buildTlsClientHello(config))
    addServerPacket(buildTlsServerHello(config))
    if (config.certificate.enabled) {
      addServerPacket(buildTlsCertificate(config))
    }
    // ChangeCipherSpec
    addServerPacket(Buffer.from([0x14, 0x03, 0x03, 0x00, 0x01, 0x01]))
    addClientPacket(Buffer.from([0x14, 0x03, 0x03, 0x00, 0x01, 0x01]))
    // Encrypted application data
    addClientPacket(Buffer.from([0x17, 0x03, 0x03, 0x00, 0x20, ...Buffer.alloc(32, 0xee)]))
    addServerPacket(Buffer.from([0x17, 0x03, 0x03, 0x00, 0x20, ...Buffer.alloc(32, 0xff)]))
  }

  if (config.email.protocol === 'SMTP') {
    addServerPacket(smtpBanner(config.email.server))
    addClientPacket(text(`EHLO client.lab.local\r\n`))
    addServerPacket(smtpEhloResponse(config.email.server, usesStarttls || isStarttlsIssueScenario))

    if (isStarttlsIssueScenario) {
      // Scenario 6: STARTTLS advertised, but negotiation fails
      addClientPacket(text(`STARTTLS\r\n`))
      addServerPacket(text(`454 4.7.0 TLS not available due to temporary problem\r\n`))
      addClientPacket(text(`MAIL FROM:<sender@lab.local>\r\n`))
      addServerPacket(text(`250 OK\r\n`))
    } else if (usesStarttls && config.tls.version !== 'None') {
      addClientPacket(text(`STARTTLS\r\n`))
      addServerPacket(smtpStarttlsResponse())
      emitTlsHandshakeAndData()
    } else if (!usesStarttls && config.tls.version !== 'None') {
      // Direct / implicit TLS on port 465 (SMTPS)
      emitTlsHandshakeAndData()
    } else {
      // Plaintext SMTP
      addClientPacket(text(`MAIL FROM:<sender@lab.local>\r\n`))
      addServerPacket(text(`250 OK\r\n`))
      addClientPacket(text(`RCPT TO:<reviewer@lab.local>\r\n`))
      addServerPacket(text(`250 OK\r\n`))
      addClientPacket(text(`DATA\r\n`))
      addServerPacket(text(`354 End data with .\r\n`))
      addClientPacket(text(`Subject: Test\r\n\r\nTest message body.\r\n.\r\n`))
      addServerPacket(text(`250 OK: queued\r\n`))
    }
  } else if (config.email.protocol === 'IMAP') {
    if (isStarttlsIssueScenario) {
      addServerPacket(text(`* OK [CAPABILITY IMAP4rev1 STARTTLS] IMAP4rev1 server ready\r\n`))
      addClientPacket(text(`a001 STARTTLS\r\n`))
      addServerPacket(text(`a001 NO STARTTLS failed\r\n`))
      addClientPacket(text(`a002 LOGIN user pass\r\n`))
      addServerPacket(text(`a002 OK LOGIN completed\r\n`))
    } else if (usesStarttls && config.tls.version !== 'None') {
      addServerPacket(text(`* OK [CAPABILITY IMAP4rev1 STARTTLS] IMAP4rev1 server ready\r\n`))
      addClientPacket(text(`a001 STARTTLS\r\n`))
      addServerPacket(text(`a001 OK Begin TLS negotiation now\r\n`))
      emitTlsHandshakeAndData()
    } else if (!usesStarttls && config.tls.version !== 'None') {
      // Implicit TLS (IMAPS, port 993)
      emitTlsHandshakeAndData()
    } else {
      // Plaintext IMAP
      addServerPacket(text(`* OK IMAP4rev1 server ready\r\n`))
      addClientPacket(text(`a001 LOGIN user pass\r\n`))
      addServerPacket(text(`a001 OK LOGIN completed\r\n`))
    }
  } else if (config.email.protocol === 'POP3') {
    if (isStarttlsIssueScenario) {
      addServerPacket(text(`+OK POP3 server ready (STLS supported)\r\n`))
      addClientPacket(text(`STLS\r\n`))
      addServerPacket(text(`-ERR STLS negotiation failed\r\n`))
      addClientPacket(text(`USER test\r\n`))
      addServerPacket(text(`+OK\r\n`))
    } else if (usesStarttls && config.tls.version !== 'None') {
      addServerPacket(text(`+OK POP3 server ready (STLS supported)\r\n`))
      addClientPacket(text(`STLS\r\n`))
      addServerPacket(text(`+OK Begin TLS negotiation\r\n`))
      emitTlsHandshakeAndData()
    } else if (!usesStarttls && config.tls.version !== 'None') {
      // Implicit TLS (POP3S, port 995)
      emitTlsHandshakeAndData()
    } else {
      // Plaintext POP3
      addServerPacket(text(`+OK POP3 server ready\r\n`))
      addClientPacket(text(`USER test\r\n`))
      addServerPacket(text(`+OK\r\n`))
    }
  }

  // TCP FIN
  addClientPacket(Buffer.alloc(0), TCP_FIN_ACK)
  addServerPacket(Buffer.alloc(0), TCP_FIN_ACK)
  addClientPacket(Buffer.alloc(0), TCP_ACK)

  return Buffer.concat(blocks)
}

function hashStr(s: string): number {
  return [...s].reduce((h, c) => (Math.imul(31, h) + c.charCodeAt(0)) | 0, 0)
}

// ─── Parse: read the Custom Block from a PCAPNG file ─────────────────────────

export interface ParsedPcapng {
  isSecureMailScope: boolean
  manifest: EncryptedConfigManifest | null
  packetCount: number
  blockCount: number
  hasIDB: boolean
  hasSHB: boolean
  tlsClientHello: TlsClientHelloData | null
  tlsServerHello: TlsServerHelloData | null
  certificateData: CertificateData | null
  smtpStarttlsAdvertised: boolean
  smtpStarttlsNegotiated: boolean
  plaintextSMTP: boolean
  parseErrors: string[]
}

export interface TlsClientHelloData {
  version: TlsVersion
  cipherSuites: string[]
  namedGroups: string[]
}

export interface TlsServerHelloData {
  version: TlsVersion
  selectedCipher: string
  namedGroup: string
}

export interface CertificateData {
  commonName: string
  issuer: string
  validFrom: string
  validUntil: string
  publicKeyAlgorithm: string
  publicKeyLength: number
  signatureAlgorithm: string
  chainValid: boolean
  scenario: string
}

export function parsePcapng(data: Buffer): ParsedPcapng {
  const result: ParsedPcapng = {
    isSecureMailScope: false,
    manifest: null,
    packetCount: 0,
    blockCount: 0,
    hasIDB: false,
    hasSHB: false,
    tlsClientHello: null,
    tlsServerHello: null,
    certificateData: null,
    smtpStarttlsAdvertised: false,
    smtpStarttlsNegotiated: false,
    plaintextSMTP: false,
    parseErrors: [],
  }

  let offset = 0

  while (offset + 8 <= data.length) {
    const blockType = data.readUInt32LE(offset)
    const blockLen = data.readUInt32LE(offset + 4)

    if (blockLen < 12 || offset + blockLen > data.length) break

    result.blockCount++

    try {
      switch (blockType) {
        case 0x0a0d0d0a: // SHB
          result.hasSHB = true
          break

        case 0x00000001: // IDB
          result.hasIDB = true
          break

        case 0x00000006: { // EPB
          result.packetCount++
          const epbBody = data.slice(offset + 8, offset + blockLen - 4)
          // EPB: ifaceId(4) + tsHigh(4) + tsLow(4) + capLen(4) + origLen(4) = 20 bytes
          if (epbBody.length > 20) {
            const capLen = epbBody.readUInt32LE(12)
            const pktData = epbBody.slice(20, 20 + capLen)
            parsePcapPacket(pktData, result)
          }
          break
        }

        case 0x00000bad: { // Custom block (SecureMailScope)
          // Layout: blockType(4) + blockLen(4) + PEN(4) + data + blockLen(4)
          const pen = data.readUInt32LE(offset + 8)
          if (pen === 0x53654d53) { // "SeMS"
            const customData = data.slice(offset + 12, offset + blockLen - 4)
            try {
              const rawStr = customData.toString('utf8').replace(/\0+$/, '').trim()
              const manifest = JSON.parse(rawStr) as EncryptedConfigManifest
              if (manifest.algorithm === 'AES-256-GCM' && manifest.sessionId) {
                result.isSecureMailScope = true
                result.manifest = manifest
              }
            } catch {
              result.parseErrors.push('Failed to parse SecureMailScope custom block')
            }
          }
          break
        }
      }
    } catch (err) {
      result.parseErrors.push(
        `Block parse error at offset ${offset}: ${err instanceof Error ? err.message : String(err)}`
      )
    }

    offset += blockLen
  }

  return result
}

function parsePcapPacket(pkt: Buffer, result: ParsedPcapng) {
  // Minimum: 14 (Ethernet) + 20 (IP) + 20 (TCP) = 54 bytes
  if (pkt.length < 54) return

  const etherType = pkt.readUInt16BE(12)
  if (etherType !== 0x0800) return // Only IPv4

  const ipProto = pkt[23]
  if (ipProto !== 0x06) return // Only TCP

  const ipHeaderLen = (pkt[14] & 0x0f) * 4
  const tcpOffset = 14 + ipHeaderLen
  if (pkt.length < tcpOffset + 20) return

  const tcpDataOffset = ((pkt[tcpOffset + 12] >> 4) & 0x0f) * 4
  const payloadOffset = tcpOffset + tcpDataOffset
  if (pkt.length <= payloadOffset) return

  const payload = pkt.slice(payloadOffset)
  if (payload.length === 0) return

  // Try to parse as mail text (SMTP/IMAP/POP3)
  const text = payload.toString('ascii', 0, Math.min(payload.length, 512))

  if (text.includes('STARTTLS') || text.includes('STLS')) result.smtpStarttlsAdvertised = true
  if (text.includes('220 2.0.0 Ready to start TLS') || text.includes('Begin TLS negotiation')) result.smtpStarttlsNegotiated = true
  if (text.includes('MAIL FROM:') || text.includes('EHLO') || text.includes('a001 LOGIN') || text.includes('USER ')) result.plaintextSMTP = true

  // TLS record detection
  if (payload.length < 5) return
  const tlsRecordType = payload[0]
  if (tlsRecordType !== 0x16) return // Only Handshake records

  const tlsHandshakeType = payload[5]

  if (tlsHandshakeType === 0x01) {
    // ClientHello
    result.tlsClientHello = parseTlsClientHello(payload)
  } else if (tlsHandshakeType === 0x02) {
    // ServerHello
    result.tlsServerHello = parseTlsServerHello(payload)
  } else if (tlsHandshakeType === 0x0b) {
    // Certificate
    result.certificateData = parseCertificateRecord(payload)
    if (result.smtpStarttlsAdvertised) result.smtpStarttlsNegotiated = true
  }
}

const CIPHER_MAP: Record<string, CipherSuite> = {
  '1301': 'TLS_AES_128_GCM_SHA256',
  '1302': 'TLS_AES_256_GCM_SHA384',
  '1303': 'TLS_CHACHA20_POLY1305_SHA256',
  'c02f': 'ECDHE-RSA-AES128-GCM-SHA256',
  'c030': 'ECDHE-RSA-AES256-GCM-SHA384',
  'c02b': 'ECDHE-ECDSA-AES128-GCM-SHA256',
  'c02c': 'ECDHE-ECDSA-AES256-GCM-SHA384',
  '002f': 'AES128-SHA',
  '0035': 'AES256-SHA',
  '000a': 'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
}

const GROUP_MAP: Record<string, string> = {
  '001d': 'X25519',
  '001e': 'X448',
  '0017': 'secp256r1',
  '0018': 'secp384r1',
  '0019': 'secp521r1',
}

function tlsVersionFromBytes(major: number, minor: number): TlsVersion {
  if (major === 3 && minor === 1) return 'TLS1.0'
  if (major === 3 && minor === 2) return 'TLS1.1'
  if (major === 3 && minor === 3) return 'TLS1.2'
  if (major === 3 && minor === 4) return 'TLS1.3'
  return 'TLS1.2'
}

function parseTlsClientHello(payload: Buffer): TlsClientHelloData | null {
  try {
    // TLS Record: type(1) version(2) length(2) = 5 bytes
    // Handshake: type(1) length(3) = 4 bytes
    // ClientHello body starts at offset 9
    const offset = 9
    if (payload.length < offset + 34) return null

    const legacyMajor = payload[offset]
    const legacyMinor = payload[offset + 1]
    let version = tlsVersionFromBytes(legacyMajor, legacyMinor)

    let pos = offset + 34 // skip version(2) + random(32)
    const sessionIdLen = payload[pos++]
    pos += sessionIdLen

    if (pos + 2 > payload.length) return null
    const cipherLen = payload.readUInt16BE(pos); pos += 2
    const cipherSuites: string[] = []
    for (let i = 0; i + 1 < cipherLen; i += 2) {
      if (pos + 1 >= payload.length) break
      const cs = payload.slice(pos, pos + 2).toString('hex')
      const mapped = CIPHER_MAP[cs]
      if (mapped) cipherSuites.push(mapped)
      pos += 2
    }

    const compressionLen = payload[pos++]
    pos += compressionLen

    const namedGroups: string[] = []
    // Parse extensions to find supported_versions and supported_groups
    if (pos + 2 <= payload.length) {
      const extLen = payload.readUInt16BE(pos); pos += 2
      const extEnd = pos + extLen
      while (pos + 4 <= extEnd && pos + 4 <= payload.length) {
        const extType = payload.readUInt16BE(pos)
        const extDataLen = payload.readUInt16BE(pos + 2)
        pos += 4
        const extData = payload.slice(pos, pos + extDataLen)
        pos += extDataLen

        if (extType === 0x002b) {
          // supported_versions
          if (extData.length >= 3) {
            const listLen = extData[0]
            for (let i = 1; i + 1 < listLen + 1 && i + 1 < extData.length; i += 2) {
              const v = tlsVersionFromBytes(extData[i], extData[i + 1])
              version = v // take the first/only offered version
            }
          }
        } else if (extType === 0x000a) {
          // supported_groups
          if (extData.length >= 4) {
            const groupListLen = extData.readUInt16BE(0) || extData.readUInt16BE(2)
            // Simple: parse 2 bytes at index 2
            if (extData.length >= 4) {
              const g = extData.slice(2, 4).toString('hex')
              const mapped = GROUP_MAP[g]
              if (mapped) namedGroups.push(mapped)
            }
          }
        }
      }
    }

    return { version, cipherSuites, namedGroups }
  } catch {
    return null
  }
}

function parseTlsServerHello(payload: Buffer): TlsServerHelloData | null {
  try {
    const offset = 9
    if (payload.length < offset + 36) return null

    let version = tlsVersionFromBytes(payload[offset], payload[offset + 1])
    let pos = offset + 34 // version(2) + random(32)
    const sessionIdLen = payload[pos++]
    pos += sessionIdLen

    if (pos + 2 > payload.length) return null
    const csHex = payload.slice(pos, pos + 2).toString('hex')
    const selectedCipher = CIPHER_MAP[csHex] ?? csHex
    pos += 2
    pos++ // compression

    let namedGroup = 'unknown'
    if (pos + 2 <= payload.length) {
      const extLen = payload.readUInt16BE(pos); pos += 2
      const extEnd = pos + extLen
      while (pos + 4 <= extEnd && pos + 4 <= payload.length) {
        const extType = payload.readUInt16BE(pos)
        const extDataLen = payload.readUInt16BE(pos + 2)
        pos += 4
        const extData = payload.slice(pos, pos + extDataLen)
        pos += extDataLen
        if (extType === 0x002b && extData.length >= 2) {
          version = tlsVersionFromBytes(extData[0], extData[1])
        }
      }
    }

    return { version, selectedCipher, namedGroup }
  } catch {
    return null
  }
}

function parseCertificateRecord(payload: Buffer): CertificateData | null {
  try {
    // Our simulated certs embed JSON — find the JSON marker
    const marker = '_label":"SecureMailScope-SimulatedCert-v1'
    const payloadStr = payload.toString('utf8', 0, Math.min(payload.length, 4096))
    const idx = payloadStr.indexOf(marker)
    if (idx === -1) return null

    // Find enclosing JSON object
    const start = payloadStr.lastIndexOf('{', idx)
    const end = payloadStr.indexOf('}', idx) + 1
    if (start === -1 || end <= 0) return null

    const certObj = JSON.parse(payloadStr.slice(start, end))
    return {
      commonName: certObj.commonName ?? '',
      issuer: certObj.issuer ?? '',
      validFrom: certObj.validFrom ?? '',
      validUntil: certObj.validUntil ?? '',
      publicKeyAlgorithm: certObj.publicKeyAlgorithm ?? 'RSA',
      publicKeyLength: certObj.publicKeyLength ?? 2048,
      signatureAlgorithm: certObj.signatureAlgorithm ?? 'SHA256withRSA',
      chainValid: certObj.chainValid ?? true,
      scenario: certObj.scenario ?? 'valid',
    }
  } catch {
    return null
  }
}
