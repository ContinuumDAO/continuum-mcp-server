/**
 * OpenSSH "openssh-key-v1" unencrypted Ed25519 PEM ("BEGIN OPENSSH PRIVATE KEY") import.
 * Node.js + OpenSSL 3.6+ commonly reject this envelope via createPrivateKey(); we decode wire
 * format per OpenSSH PROTOCOL.key and import via JWK.
 */
import { createPrivateKey, KeyObject } from "crypto"

export const OPENSSH_V1_MAGIC = Buffer.from("openssh-key-v1\0")

export function readSshString(buf: Buffer, offset: number): { value: Buffer; next: number } {
  if (offset + 4 > buf.length) {
    throw new Error(`SSH string header EOF at offset ${offset}`)
  }
  const len = buf.readUInt32BE(offset)
  const next = offset + 4 + len
  if (next > buf.length || len < 0) {
    throw new Error(`SSH string length ${len} out of range at offset ${offset}`)
  }
  return { value: buf.subarray(offset + 4, next), next }
}

function pemBase64BodyForOpenSshBlock(pemArmored: string): Buffer {
  const m = pemArmored.match(/-----BEGIN OPENSSH PRIVATE KEY-----([\s\S]*?)-----END OPENSSH PRIVATE KEY-----/i)
  if (!m) {
    throw new Error("missing -----BEGIN/END OPENSSH PRIVATE KEY----- PEM block")
  }
  const compact = m[1].replace(/\s+/g, "")
  return Buffer.from(compact, "base64")
}

function assertOpenSshPadding(privList: Buffer, offsetAfterComment: number): void {
  for (let pad = 1, o = offsetAfterComment; o < privList.length; pad++, o++) {
    const expected = pad & 0xff
    if (privList[o] !== expected) {
      throw new Error("invalid OpenSSH private key padding (file may be truncated or encrypted incorrectly)")
    }
  }
}

/** @returns first 32-byte seed and 32-byte public key (from private pair string). */
export function parseUnencryptedOpenSshEd25519FromV1Blob(blob: Buffer): {
  seed32: Buffer
  pub32: Buffer
  comment: string
} {
  if (blob.length < OPENSSH_V1_MAGIC.length || !blob.subarray(0, OPENSSH_V1_MAGIC.length).equals(OPENSSH_V1_MAGIC)) {
    throw new Error("not an openssh-key-v1 blob")
  }

  let offset = OPENSSH_V1_MAGIC.length
  const cipherName = readSshString(blob, offset)
  offset = cipherName.next
  const kdfName = readSshString(blob, offset)
  offset = kdfName.next
  const kdfOptions = readSshString(blob, offset)
  offset = kdfOptions.next

  if (cipherName.value.toString("utf8") !== "none" || kdfName.value.toString("utf8") !== "none") {
    throw new Error(
      "OpenSSH private key is encrypted; use `ssh-keygen -p -N '' -m PKCS8 -f <keyfile>` to write an importable PKCS#8 PEM, or provide an unencrypted key",
    )
  }

  const nKeys = blob.readUInt32BE(offset)
  offset += 4
  if (nKeys !== 1) {
    throw new Error(`OpenSSH file has ${nKeys} keys; only single-key Ed25519 files are supported`)
  }

  /** Public ssh wire blobs (validated against private material). */
  const pubBlob = readSshString(blob, offset)
  offset = pubBlob.next

  const encryptedPrivateListMaybe = readSshString(blob, offset)
  offset = encryptedPrivateListMaybe.next

  const privList = encryptedPrivateListMaybe.value
  if (privList.length < 16) {
    throw new Error("OpenSSH private key list too short")
  }

  const check1 = privList.readUInt32BE(0)
  const check2 = privList.readUInt32BE(4)
  if (check1 !== check2) {
    throw new Error("OpenSSH private key checkints mismatch (wrong passphrase or corrupted file)")
  }

  let inner = 8
  const algo = readSshString(privList, inner)
  inner = algo.next
  const ak = algo.value.toString("utf8")
  if (ak !== "ssh-ed25519") {
    throw new Error(`OpenSSH private key algorithm is ${JSON.stringify(ak)}, expected "ssh-ed25519"`)
  }

  const pubFromPrivate = readSshString(privList, inner)
  inner = pubFromPrivate.next
  if (pubFromPrivate.value.length !== 32) {
    throw new Error(`invalid Ed25519 public key length ${pubFromPrivate.value.length}`)
  }

  const pair = readSshString(privList, inner)
  inner = pair.next
  if (pair.value.length !== 64) {
    throw new Error(`invalid Ed25519 secret+public concat length ${pair.value.length}`)
  }

  const seed32 = Buffer.from(pair.value.subarray(0, 32))
  const duplicatePub32 = Buffer.from(pair.value.subarray(32, 64))
  if (!duplicatePub32.equals(pubFromPrivate.value)) {
    throw new Error("OpenSSH Ed25519 public key mismatch inside private pair (corrupted key)")
  }

  const cm = readSshString(privList, inner)
  inner = cm.next

  /** Wire-format public blob should match pubkey from private serialization. */
  const pubOuter = pubBlob.value
  let po = 0
  const pubAlgo = readSshString(pubOuter, po)
  po = pubAlgo.next
  if (pubAlgo.value.toString("utf8") !== "ssh-ed25519") {
    throw new Error("OpenSSH outer public blob algorithm mismatch")
  }
  const pubOuterKeyBytes = readSshString(pubOuter, po).value
  if (!pubOuterKeyBytes.equals(pubFromPrivate.value)) {
    throw new Error("OpenSSH outer public blob does not match embedded private pubkey (corrupted key)")
  }

  assertOpenSshPadding(privList, inner)

  return {
    seed32,
    pub32: pubFromPrivate.value,
    comment: cm.value.toString("utf8"),
  }
}

function b64Url(buf: Buffer): string {
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "")
}

/** Import unencrypted ssh-keygen/OpenSSH PEM into a native KeyObject (Ed25519 only). */
export function importUnencryptedOpenSshEd25519PrivateKeyFromPem(pemArmored: string): KeyObject {
  const blob = pemBase64BodyForOpenSshBlock(pemArmored.trim())
  const { seed32, pub32 } = parseUnencryptedOpenSshEd25519FromV1Blob(blob)
  return createPrivateKey({
    format: "jwk",
    key: {
      kty: "OKP",
      crv: "Ed25519",
      d: b64Url(seed32),
      x: b64Url(pub32),
    },
  })
}
