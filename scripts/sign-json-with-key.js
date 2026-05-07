#!/usr/bin/env node
"use strict"

/**
 * Manual signing helper: reads an Ed25519 private key from disk (same envelopes as the MCP server)
 * and signs a UTF-8 message (your JSON string, used verbatim).
 *
 * Usage:
 *   node scripts/sign-json-with-key.js <path-to-private-key> '<json-string>'
 *   node scripts/sign-json-with-key.js <path-to-private-key> -           # JSON from stdin
 *   MESSAGE_JSON='{"a":1}' node scripts/sign-json-with-key.js <path-to-private-key>
 *
 * Requires `npm run build` first (imports ../build/openssh-ed25519.js for OpenSSH PEM).
 *
 * Stdout: one JSON object (pretty-printed) with signature, algorithm, and detected key envelope.
 */

const fs = require("node:fs/promises")
const path = require("node:path")
const { createPrivateKey, sign: signWithPrivateKey, KeyObject } = require("node:crypto")

const { importUnencryptedOpenSshEd25519PrivateKeyFromPem } = require(
  path.join(__dirname, "..", "build", "ed25519", "openssh-ed25519.js"),
)

/** PKCS#8 uses `BEGIN PRIVATE KEY` with no extra label token; PKCS#1 uses `BEGIN RSA PRIVATE KEY`, etc. */
const PEM_PRIVATE_KEY_ARMOR_RE = /-----BEGIN [A-Z0-9 \s-]*PRIVATE KEY-----/i

function looksLikeOpenSshArmoredPrivateKey(secret) {
  return /-----BEGIN OPENSSH PRIVATE KEY-----/i.test(secret)
}

function looksLikeArmoredPrivateKey(secret) {
  return PEM_PRIVATE_KEY_ARMOR_RE.test(secret)
}

function assertEd25519KeyObject(keyObject, context) {
  const t = keyObject.asymmetricKeyType
  if (t !== "ed25519") {
    throw new Error(
      `${context}: expected Ed25519 private key (asymmetricKeyType=ed25519), received ${String(t ?? "unknown")}`,
    )
  }
}

function loadEd25519KeyObjectFromArmoredPem(armored) {
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

function parseManagementPrivateKey(secret, filePath) {
  const normalized = secret.replace(/^\uFEFF/, "").trim()

  if (looksLikeArmoredPrivateKey(normalized)) {
    let keyObject
    try {
      keyObject = loadEd25519KeyObjectFromArmoredPem(normalized)
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
    const format = looksLikeOpenSshArmoredPrivateKey(normalized) ? "OPENSSH" : "PEM_PKCS8"
    return { filePath, secret: normalized, keyEnvelope: format }
  }

  const hexBody = normalized.replace(/^0x/i, "").trim().replace(/\s+/g, "")
  if (!/^[a-fA-F0-9]+$/.test(hexBody) || hexBody.length % 2 !== 0) {
    throw new Error(
      "Key is not PEM armored and is not an even-length hex string (expected DER PKCS#8 hex without headers)",
    )
  }
  const keyObjectDer = createPrivateKey({
    key: Buffer.from(hexBody, "hex"),
    format: "der",
    type: "pkcs8",
  })
  assertEd25519KeyObject(keyObjectDer, "DER PKCS#8")
  signWithPrivateKey(null, Buffer.from("", "utf8"), keyObjectDer)

  return { filePath, secret: normalized, keyEnvelope: "DER_HEX_PKCS8", derHexForSigning: hexBody }
}

function signMessage(parsed, messageUtf8) {
  const buf = Buffer.from(messageUtf8, "utf8")
  if (parsed.keyEnvelope === "DER_HEX_PKCS8") {
    const hex = parsed.derHexForSigning
    const keyObject = createPrivateKey({
      key: Buffer.from(hex, "hex"),
      format: "der",
      type: "pkcs8",
    })
    assertEd25519KeyObject(keyObject, "DER PKCS#8")
    return signWithPrivateKey(null, buf, keyObject)
  }

  /** @type {KeyObject} */
  const keyObject = loadEd25519KeyObjectFromArmoredPem(parsed.secret)
  return signWithPrivateKey(null, buf, keyObject)
}

async function main() {
  const argv = process.argv.slice(2)

  if (argv.includes("-h") || argv.includes("--help")) {
    console.error(`Usage:
  node scripts/sign-json-with-key.js <private-key-file> '<json>'
  echo '<json>' | node scripts/sign-json-with-key.js <private-key-file> -

Env (alternative to positional key path):
  KEY_PATH=<file> MESSAGE_JSON='<json>' node scripts/sign-json-with-key.js`)
    process.exit(0)
  }

  const keyPath = process.env.KEY_PATH ?? argv.shift()
  let jsonPayload = process.env.MESSAGE_JSON
  const jsonArg = argv.shift()

  if (jsonPayload === undefined && jsonArg !== undefined && jsonArg !== "") {
    jsonPayload = jsonArg === "-" ? undefined : jsonArg
  }

  let messageUtf8
  if (jsonPayload !== undefined && jsonPayload !== "") {
    messageUtf8 = jsonPayload
  } else if ((jsonArg === "-" || argv.length === 0) && (jsonArg === "-" || !process.stdin.isTTY)) {
    messageUtf8 = await readStdinUtf8()
  } else if (argv.length > 0) {
    console.error(
      JSON.stringify({
        ok: false,
        error: "Unexpected extra arguments",
        extra: argv,
      }),
    )
    process.exit(2)
  } else {
    console.error("Missing JSON payload: second argument (or '-') or MESSAGE_JSON or piped stdin. Use --help.")
    process.exit(2)
  }

  if (!keyPath || typeof messageUtf8 !== "string") {
    console.error("Missing key path. Use KEY_PATH env or pass <private-key-file> first.")
    console.error("(If you passed MESSAGE_JSON-only, omit KEY_PATH and pass key path as first positional arg.)")
    process.exit(2)
  }

  /** When reading stdin, disallow empty payloads (ambiguous). */
  if (messageUtf8.trim() === "") {
    console.error("Empty message cannot be signed.")
    process.exit(2)
  }

  /** Verify canonical JSON parses (optional sanity check); still sign exact bytes supplied. */
  try {
    JSON.parse(messageUtf8)
  } catch {
    console.error("Warning: input is not valid JSON; signing raw UTF-8 string anyway.")
  }

  const rawKey = await fs.readFile(keyPath, "utf8")
  let parsed
  try {
    parsed = parseManagementPrivateKey(rawKey, keyPath)
  } catch (error) {
    console.error(
      JSON.stringify(
        {
          ok: false,
          error: "Failed to parse private key",
          keyPath,
          detail: error instanceof Error ? error.message : String(error),
        },
        null,
        2,
      ),
    )
    process.exit(1)
  }

  try {
    const sig = signMessage(parsed, messageUtf8)
    const out = {
      ok: true,
      keyPath: parsed.filePath,
      privateKeyEnvelope: parsed.keyEnvelope,
      signatureAlgorithm: "Ed25519",
      signingDetails: {
        /** Node's name for pure Ed25519 (not ECDSA-over-Edwards). */
        nodeCryptoScheme: "ed25519",
        messageEncoding: "utf8",
        messageByteLength: Buffer.byteLength(messageUtf8, "utf8"),
      },
      /** 64-byte signature as lowercase hex (no 0x), matching typical management hex fields. */
      signatureHex: sig.toString("hex"),
    }
    console.log(JSON.stringify(out, null, 2))
  } catch (error) {
    console.error(
      JSON.stringify(
        {
          ok: false,
          error: "Sign failed after key parse",
          keyPath,
          privateKeyEnvelope: parsed.keyEnvelope,
          detail: error instanceof Error ? error.message : String(error),
        },
        null,
        2,
      ),
    )
    process.exit(1)
  }
}

async function readStdinUtf8() {
  const chunks = []
  for await (const chunk of process.stdin) {
    chunks.push(chunk)
  }
  return Buffer.concat(chunks).toString("utf8").replace(/^\uFEFF/, "").trimEnd()
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
