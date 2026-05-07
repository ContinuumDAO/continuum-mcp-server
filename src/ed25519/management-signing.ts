import { promises as fs } from "fs"
import path from "path"
import { createPrivateKey, createPublicKey, sign as signWithPrivateKey, KeyObject } from "crypto"
import { importUnencryptedOpenSshEd25519PrivateKeyFromPem } from "./openssh-ed25519.js"

export type ManagementKeyOption = {
  id: string
  kind: "EdDSA"
  value: string
  nonce: number
  label?: string
}

export type LocalManagementKeyEntry = {
  fileName: string
  publicKeyRaw: string
  publicKeyHex?: string
}

type ToMcpApiError = (message: string, data?: unknown) => Error
type QueryParamValue = string | number | boolean | null | undefined
type QueryParams = Record<string, QueryParamValue>
type MgtGet = <T>(
  route: string,
  params?: string | URLSearchParams | QueryParams,
  target?: { host?: string; port?: string | number },
) => Promise<T>

export async function resolvePreferredManagementKeyOption(
  keyOptions: ManagementKeyOption[],
  deps: {
    keyRoot: string
    toMcpApiError: ToMcpApiError
    mgtGET: MgtGet
  },
): Promise<ManagementKeyOption> {
  const { keyRoot, toMcpApiError, mgtGET } = deps
  const preferred = await getPreferredSignerPublicKeyHex({ mgtGET, toMcpApiError })
  const failures: Array<{ key: string; reason: string }> = []
  if (preferred) {
    try {
      const normalizedPreferred = normalizeEd25519PublicKeyToHex(preferred, toMcpApiError)
      const selected = keyOptions.find((opt) => normalizeEd25519PublicKeyToHex(opt.value, toMcpApiError) === normalizedPreferred)
      if (!selected) {
        throw toMcpApiError("Preferred signer is not in allowed management keys", {
          preferredSigner: normalizedPreferred,
          allowedKeys: keyOptions.map((k) => k.value),
        })
      }
      await ensureLocalKeyPairForPublicKey(normalizedPreferred, { keyRoot, toMcpApiError })
      return selected
    } catch (error) {
      failures.push({ key: preferred, reason: error instanceof Error ? error.message : String(error) })
    }
  }
  for (const opt of keyOptions) {
    try {
      await ensureLocalKeyPairForPublicKey(opt.value, { keyRoot, toMcpApiError })
      return opt
    } catch (error) {
      failures.push({ key: opt.value, reason: error instanceof Error ? error.message : String(error) })
    }
  }
  throw toMcpApiError(
    "No preferred signer is set, and no allowed management key has a usable local private key in KEY_ROOT/management_keys",
    { failures },
  )
}

export async function getPreferredSignerPublicKeyHex(
  deps: { mgtGET: MgtGet; toMcpApiError: ToMcpApiError },
): Promise<string | undefined> {
  const { mgtGET, toMcpApiError } = deps
  try {
    const raw = await mgtGET<unknown>("/getPreferredSigner")
    if (typeof raw === "string") {
      const s = raw.trim()
      return s ? normalizeEd25519PublicKeyToHex(s, toMcpApiError) : undefined
    }
    if (raw && typeof raw === "object") {
      const obj = raw as Record<string, unknown>
      const candidate = [obj.publicKeyHex, obj.publicKey, obj.key].find((v) => typeof v === "string") as string | undefined
      if (!candidate || candidate.trim().length === 0) {
        return undefined
      }
      return normalizeEd25519PublicKeyToHex(candidate, toMcpApiError)
    }
    return undefined
  } catch {
    return undefined
  }
}

export async function ensureLocalKeyPairForPublicKey(
  publicKey: string,
  deps: { keyRoot: string; toMcpApiError: ToMcpApiError },
): Promise<{ fileName: string; publicKeyPath: string; privateKeyPath: string }> {
  const { keyRoot, toMcpApiError } = deps
  const keyDir = path.join(keyRoot, "management_keys")
  const normalizedTarget = normalizeEd25519PublicKeyToHex(publicKey, toMcpApiError)
  let entries: string[]
  try {
    entries = await fs.readdir(keyDir)
  } catch (error) {
    throw toMcpApiError("Key directory not found", { keyDirectory: keyDir, reason: error instanceof Error ? error.message : String(error) })
  }
  const pubFiles = entries.filter((e) => e.endsWith(".pub"))
  let matched: { fileName: string; publicKeyPath: string; privateKeyPath: string } | undefined
  for (const pubFile of pubFiles) {
    const publicKeyPath = path.join(keyDir, pubFile)
    let raw: string
    try {
      raw = (await fs.readFile(publicKeyPath, "utf8")).trim()
    } catch {
      continue
    }
    let normalized: string
    try {
      normalized = normalizeEd25519PublicKeyToHex(raw, toMcpApiError)
    } catch {
      continue
    }
    if (normalized === normalizedTarget) {
      const fileName = pubFile.slice(0, -4)
      matched = { fileName, publicKeyPath, privateKeyPath: path.join(keyDir, fileName) }
      break
    }
  }
  if (!matched) {
    throw toMcpApiError("Preferred signer key does not exist locally in KEY_ROOT/management_keys", {
      preferredKey: normalizedTarget,
      keyDirectory: keyDir,
    })
  }

  let secret: string
  try {
    secret = (await fs.readFile(matched.privateKeyPath, "utf8")).trim()
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error)
    if ((error as NodeJS.ErrnoException)?.code === "ENOENT") {
      throw toMcpApiError("Preferred signer key does not have a corresponding private key", {
        preferredKey: normalizedTarget,
        expectedPrivateKeyPath: matched.privateKeyPath,
      })
    }
    throw toMcpApiError("Preferred signer private key is inaccessible", {
      preferredKey: normalizedTarget,
      privateKeyPath: matched.privateKeyPath,
      reason,
    })
  }

  const parsed = parseManagementPrivateKey(secret, matched.privateKeyPath, toMcpApiError)
  const derived = derivePublicKeyHexFromPrivateKey(parsed)
  if (derived !== normalizedTarget) {
    throw toMcpApiError("Preferred signer private key does not match the specified public key", {
      preferredKey: normalizedTarget,
      derivedPublicKey: derived,
      privateKeyPath: matched.privateKeyPath,
      publicKeyPath: matched.publicKeyPath,
    })
  }
  return matched
}

export function normalizeEd25519PublicKeyToHex(value: string, toMcpApiError: ToMcpApiError): string {
  const trimmed = value.trim()
  const normalizedHex = normalizeKeyValue(trimmed)
  if (/^[a-fA-F0-9]{64}$/.test(normalizedHex)) {
    return normalizedHex
  }

  const parts = trimmed.split(/\s+/)
  if (parts.length >= 2 && parts[0] === "ssh-ed25519") {
    try {
      const blob = Buffer.from(parts[1], "base64")
      let offset = 0
      const readUint32 = (): number => {
        if (offset + 4 > blob.length) {
          throw new Error("truncated OpenSSH key blob")
        }
        const x = blob.readUInt32BE(offset)
        offset += 4
        return x
      }
      const readBytes = (length: number): Buffer => {
        if (offset + length > blob.length) {
          throw new Error("truncated OpenSSH key blob")
        }
        const slice = blob.subarray(offset, offset + length)
        offset += length
        return slice
      }
      const typeLen = readUint32()
      const type = readBytes(typeLen).toString("utf8")
      if (type !== "ssh-ed25519") {
        throw new Error("unsupported OpenSSH key type")
      }
      const keyLen = readUint32()
      const keyBytes = readBytes(keyLen)
      if (keyBytes.length !== 32) {
        throw new Error("OpenSSH Ed25519 key must be 32 bytes")
      }
      return keyBytes.toString("hex")
    } catch (error) {
      throw toMcpApiError("Invalid OpenSSH Ed25519 public key format", {
        reason: error instanceof Error ? error.message : String(error),
      })
    }
  }
  throw toMcpApiError("Unsupported public key format; expected 32-byte hex or ssh-ed25519 OpenSSH key")
}

export async function listLocalManagementPublicKeys(
  keyRoot: string,
  toMcpApiError: ToMcpApiError,
): Promise<LocalManagementKeyEntry[]> {
  const keyDir = path.join(keyRoot, "management_keys")
  let entries: string[] = []
  try {
    entries = await fs.readdir(keyDir)
  } catch {
    return []
  }

  const pubFiles = entries.filter((entry) => entry.endsWith(".pub"))
  const results: LocalManagementKeyEntry[] = []
  for (const pubFile of pubFiles) {
    const fileName = pubFile.slice(0, -4)
    const pubPath = path.join(keyDir, pubFile)
    try {
      const raw = (await fs.readFile(pubPath, "utf8")).trim()
      let publicKeyHex: string | undefined
      try {
        publicKeyHex = normalizeEd25519PublicKeyToHex(raw, toMcpApiError)
      } catch {
        publicKeyHex = undefined
      }
      results.push({ fileName, publicKeyRaw: raw, publicKeyHex })
    } catch {
      // ignore unreadable/invalid keys
    }
  }
  return results
}

export function buildManagementSigningMessage(bodyWithEmptySig: Record<string, unknown>): string {
  return JSON.stringify(bodyWithEmptySig)
}

export async function signManagementMessage(
  option: ManagementKeyOption,
  message: string,
  deps: {
    keyRoot: string
    toMcpApiError: ToMcpApiError
    assertAgentCanSignManagementRequests: () => Promise<void>
  },
): Promise<string> {
  const { keyRoot, toMcpApiError, assertAgentCanSignManagementRequests } = deps
  await assertAgentCanSignManagementRequests()
  const localFileName = await resolveLocalFileNameForOption(option, keyRoot, toMcpApiError)
  const { filePath, secret, format } = localFileName
    ? await loadAndParseManagementPrivateKeyFromFileName(localFileName, keyRoot, toMcpApiError)
    : await loadAndParseManagementPrivateKey(option, keyRoot, toMcpApiError)
  try {
    const signatureBytes = format === "OPENSSH"
      ? signEd25519OpenSsh(secret, message)
      : format === "PEM"
        ? signEd25519Pem(secret, message)
        : signEd25519DerHex(secret, message)
    return signatureBytes.toString("hex")
  } catch (error) {
    throw toMcpApiError("Failed to sign with EdDSA private key", {
      filePath,
      reason: error instanceof Error ? error.message : String(error),
      hint: "Use PEM PKCS#8 (-----BEGIN PRIVATE KEY-----) or DER PKCS#8 hex in key file",
    })
  }
}

export async function getPrivateKeyStatus(
  option: ManagementKeyOption,
  deps: {
    keyRoot: string
    toMcpApiError: ToMcpApiError
  },
): Promise<{ available: boolean; reason?: string }> {
  const { keyRoot, toMcpApiError } = deps
  try {
    await loadAndParseManagementPrivateKey(option, keyRoot, toMcpApiError)
    return { available: true }
  } catch (error) {
    return { available: false, reason: error instanceof Error ? error.message : String(error) }
  }
}

export async function assertAgentCanSignManagementRequests(deps: {
  keyRoot: string
  mgtGET: MgtGet
  toMcpApiError: ToMcpApiError
}): Promise<void> {
  const { keyRoot, mgtGET, toMcpApiError } = deps
  const configuredKeys = await mgtGET<Array<{ publicKey: string; label: string }>>("/getAllowedEd25519MgtKeys")
  if (configuredKeys.length === 0) {
    throw toMcpApiError(
      "No EdDSA management keys are configured. Configure a bootstrap Ed25519 key before agent-signed management requests.",
    )
  }

  if (configuredKeys.length === 1) {
    const bootstrap = configuredKeys[0]
    try {
      await loadManagementPrivateKey(
        {
          id: `eddsa:${bootstrap.publicKey}`,
          kind: "EdDSA",
          value: bootstrap.publicKey,
          nonce: 0,
          label: bootstrap.label,
        },
        keyRoot,
        toMcpApiError,
      )
    } catch (error) {
      throw toMcpApiError(
        "Only one EdDSA management key is configured (bootstrap), but its private key is missing beside the bootstrap .pub file in KEY_ROOT/management_keys.",
        {
          publicKey: bootstrap.publicKey,
          reason: error instanceof Error ? error.message : String(error),
        },
      )
    }
  }
}

function normalizeKeyValue(value: string): string {
  return value.trim().toLowerCase().replace(/^0x/, "")
}

async function loadManagementPrivateKey(
  option: ManagementKeyOption,
  keyRoot: string,
  toMcpApiError: ToMcpApiError,
): Promise<{ filePath: string; secret: string }> {
  const keyDir = path.join(keyRoot, "management_keys")
  let entries: string[]
  try {
    entries = await fs.readdir(keyDir)
  } catch (error) {
    throw toMcpApiError("Key directory not found", {
      keyDirectory: keyDir,
      reason: error instanceof Error ? error.message : String(error),
    })
  }

  const pubFiles = entries.filter((entry) => entry.endsWith(".pub"))
  if (pubFiles.length === 0) {
    throw toMcpApiError("No public key files found for selected key type", {
      keyDirectory: keyDir,
      expectedPattern: "*.pub",
    })
  }

  const selectedNormalized = normalizeEd25519PublicKeyToHex(option.value, toMcpApiError)
  for (const pubFilename of pubFiles) {
    const pubPath = path.join(keyDir, pubFilename)
    let pubContent: string
    try {
      pubContent = (await fs.readFile(pubPath, "utf8")).trim()
    } catch {
      continue
    }

    const pubNormalized = normalizeEd25519PublicKeyToHex(pubContent, toMcpApiError)
    if (pubNormalized !== selectedNormalized) {
      continue
    }

    const privatePath = path.join(keyDir, pubFilename.slice(0, -4))
    try {
      const secret = (await fs.readFile(privatePath, "utf8")).trim()
      return { filePath: privatePath, secret }
    } catch {
      throw toMcpApiError("Matching public key found, but private key file is missing", {
        selectedKey: option.value,
        publicKeyPath: pubPath,
        expectedPrivateKeyPath: privatePath,
      })
    }
  }

  throw toMcpApiError("No matching public key file found for selected key", {
    selectedKey: option.value,
    keyDirectory: keyDir,
  })
}

async function loadManagementPrivateKeyByFileName(fileName: string, keyRoot: string, toMcpApiError: ToMcpApiError): Promise<{ filePath: string; secret: string }> {
  const keyDir = path.join(keyRoot, "management_keys")
  const filePath = path.join(keyDir, fileName)
  try {
    const secret = (await fs.readFile(filePath, "utf8")).trim()
    return { filePath, secret }
  } catch (error) {
    throw toMcpApiError("Private key file could not be read", {
      filePath,
      reason: error instanceof Error ? error.message : String(error),
    })
  }
}

async function resolveLocalFileNameForOption(option: ManagementKeyOption, keyRoot: string, toMcpApiError: ToMcpApiError): Promise<string | undefined> {
  const localKeys = await listLocalManagementPublicKeys(keyRoot, toMcpApiError)
  const normalized = normalizeEd25519PublicKeyToHex(option.value, toMcpApiError)
  return localKeys.find((entry) => entry.publicKeyHex === normalized)?.fileName
}

/** Node/OpenSSL 3.6+ often rejects `BEGIN OPENSSH PRIVATE KEY` via createPrivateKey; decode when needed. */
function loadEd25519KeyObjectFromArmoredPem(armored: string): KeyObject {
  try {
    const keyObject = createPrivateKey(armored)
    assertEd25519KeyObject(keyObject, "armored PEM (OpenSSL)")
    return keyObject
  } catch (first) {
    if (looksLikeOpenSshArmoredPrivateKey(armored)) {
      try {
        const keyObject = importUnencryptedOpenSshEd25519PrivateKeyFromPem(armored)
        assertEd25519KeyObject(keyObject, "OPENSSH PEM (decoded)")
        return keyObject
      } catch (second) {
        const a = first instanceof Error ? first.message : String(first)
        const b = second instanceof Error ? second.message : String(second)
        throw new Error(`Could not load private key (${a}); OpenSSH PEM decode failed (${b})`)
      }
    }
    throw first
  }
}

function signEd25519OpenSsh(privateKeyOpenSshPem: string, message: string): Buffer {
  const keyObject = loadEd25519KeyObjectFromArmoredPem(privateKeyOpenSshPem)
  return signWithPrivateKey(null, Buffer.from(message, "utf8"), keyObject)
}

function signEd25519Pem(privateKeyPem: string, message: string): Buffer {
  const keyObject = loadEd25519KeyObjectFromArmoredPem(privateKeyPem)
  return signWithPrivateKey(null, Buffer.from(message, "utf8"), keyObject)
}

function signEd25519DerHex(privateKeyDerHex: string, message: string): Buffer {
  const keyObject = createPrivateKey({
    key: Buffer.from(privateKeyDerHex.replace(/^0x/, ""), "hex"),
    format: "der",
    type: "pkcs8",
  })
  assertEd25519KeyObject(keyObject, "DER PKCS#8")
  return signWithPrivateKey(null, Buffer.from(message, "utf8"), keyObject)
}

function derivePublicKeyHexFromPrivateKey(parsed: { secret: string; format: "OPENSSH" | "PEM" | "DER_HEX" }): string {
  const keyObject = parsed.format === "DER_HEX"
    ? createPrivateKey({
      key: Buffer.from(parsed.secret.replace(/^0x/i, "").replace(/\s+/g, ""), "hex"),
      format: "der",
      type: "pkcs8",
    })
    : loadEd25519KeyObjectFromArmoredPem(parsed.secret)
  assertEd25519KeyObject(keyObject, "derive public from private")
  const pub = createPublicKey(keyObject)
  const jwk = pub.export({ format: "jwk" }) as { x?: string }
  if (!jwk.x) {
    throw new Error("could not derive Ed25519 public key from private key")
  }
  return Buffer.from(jwk.x, "base64url").toString("hex")
}

/** PEM armored labels that indicate a PKCS#8 / OpenSSH-style private key block (case-insensitive). */
const PEM_PRIVATE_KEY_ARMOR_RE = /-----BEGIN [A-Z0-9 \s\-]*PRIVATE KEY-----/i

function looksLikeArmoredPrivateKey(secret: string): boolean {
  return PEM_PRIVATE_KEY_ARMOR_RE.test(secret)
}

function looksLikeOpenSshArmoredPrivateKey(secret: string): boolean {
  return /-----BEGIN OPENSSH PRIVATE KEY-----/i.test(secret)
}

function assertEd25519KeyObject(keyObject: KeyObject, context: string): void {
  const t = keyObject.asymmetricKeyType
  if (t !== "ed25519") {
    throw new Error(`${context}: expected Ed25519 private key (asymmetricKeyType=ed25519), received ${String(t ?? "unknown")}`)
  }
}

/** Parse and validate PEM/OpenSSH armored key material; returns format tag for routing (signers are equivalent). */
function parseEd25519ArmoredPrivateKey(secret: string, filePath: string): {
  filePath: string
  secret: string
  format: "OPENSSH" | "PEM"
} {
  let keyObject: KeyObject
  try {
    keyObject = loadEd25519KeyObjectFromArmoredPem(secret)
  } catch (error) {
    throw new Error(
      `PEM armored private key could not be loaded: ${error instanceof Error ? error.message : String(error)}`,
    )
  }
  try {
    signWithPrivateKey(null, Buffer.from("", "utf8"), keyObject)
  } catch (error) {
    throw new Error(
      `Ed25519 signing probe failed for armored key: ${error instanceof Error ? error.message : String(error)}`,
    )
  }
  const format = looksLikeOpenSshArmoredPrivateKey(secret) ? "OPENSSH" : "PEM"
  return { filePath, secret, format }
}

async function loadAndParseManagementPrivateKey(
  option: ManagementKeyOption,
  keyRoot: string,
  toMcpApiError: ToMcpApiError,
): Promise<{
  filePath: string
  secret: string
  format: "OPENSSH" | "PEM" | "DER_HEX"
}> {
  const { filePath, secret } = await loadManagementPrivateKey(option, keyRoot, toMcpApiError)
  return parseManagementPrivateKey(secret, filePath, toMcpApiError)
}

async function loadAndParseManagementPrivateKeyFromFileName(
  fileName: string,
  keyRoot: string,
  toMcpApiError: ToMcpApiError,
): Promise<{
  filePath: string
  secret: string
  format: "OPENSSH" | "PEM" | "DER_HEX"
}> {
  const { filePath, secret } = await loadManagementPrivateKeyByFileName(fileName, keyRoot, toMcpApiError)
  return parseManagementPrivateKey(secret, filePath, toMcpApiError)
}

function parseManagementPrivateKey(
  secret: string,
  filePath: string,
  toMcpApiError: ToMcpApiError,
): {
  filePath: string
  secret: string
  format: "OPENSSH" | "PEM" | "DER_HEX"
} {
  try {
    const normalized = secret.replace(/^\uFEFF/, "").trim()
    if (looksLikeArmoredPrivateKey(normalized)) {
      return parseEd25519ArmoredPrivateKey(normalized, filePath)
    }

    const hexBody = normalized.replace(/^0x/i, "").trim().replace(/\s+/g, "")
    if (!/^[a-fA-F0-9]+$/.test(hexBody) || hexBody.length % 2 !== 0) {
      throw new Error(
        "Key is not PEM armored and is not an even-length hex string (expected DER PKCS#8 hex without headers)",
      )
    }
    signEd25519DerHex(hexBody, "")
    return { filePath, secret: normalized, format: "DER_HEX" }
  } catch (error) {
    throw toMcpApiError("Private key exists but could not be parsed for Ed25519 signing", {
      filePath,
      reason: error instanceof Error ? error.message : String(error),
      hint:
        "Expected unencrypted Ed25519 key: PEM armored (-----BEGIN ... PRIVATE KEY-----, including OpenSSH blocks with optional Proc-Type preamble) or DER PKCS#8 as hex.",
    })
  }
}
