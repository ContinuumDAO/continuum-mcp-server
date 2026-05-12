import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js"
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js"
import { promises as fs } from "fs"
import path from "path"
import { generateKeyPairSync } from "crypto"
import { z } from "zod"
import {
  EdDSAPubKeySchema,
  ManagementSigSchema,
  NodeIdSchema,
  NonceSchema,
  SelectedSigningKeySchema,
  type EdDSAPubKey,
  type NodeId,
  type Nonce,
  type Sig,
} from "./types.js"

type ManagementKeyOption = {
  id: string
  kind: "EdDSA"
  value: string
  nonce: Nonce
  label?: string
}

type LocalManagementKeyEntry = {
  fileName: string
  publicKeyRaw: string
  publicKeyHex?: EdDSAPubKey
}

type QueryParamValue = string | number | boolean | null | undefined
type QueryParams = Record<string, QueryParamValue>
type RequestTarget = { host?: string; port?: string | number }

type KeyToolsDeps = {
  server: McpServer
  keyRoot: string
  mgtGET: <T>(path: string, params?: string | URLSearchParams | QueryParams, target?: RequestTarget) => Promise<T>
  mgtPOST: <T>(path: string, body?: BodyInit | object, params?: string | URLSearchParams | QueryParams) => Promise<T>
  toMcpApiError: (message: string, data?: unknown) => Error
  assertAgentCanSignManagementRequests: () => Promise<void>
  normalizeEd25519PublicKeyToHex: (value: string) => string
  fetchManagementKeyOptions: () => Promise<ManagementKeyOption[]>
  resolveManagementSigningKeyOption: (keyOptions: ManagementKeyOption[]) => Promise<ManagementKeyOption>
  getNodeKey: () => Promise<NodeId>
  buildManagementSigningMessage: (bodyWithEmptySig: Record<string, unknown>) => string
  signManagementMessage: (option: ManagementKeyOption, message: string) => Promise<Sig>
  listLocalManagementPublicKeys: () => Promise<LocalManagementKeyEntry[]>
  getPrivateKeyStatus: (option: ManagementKeyOption) => Promise<{ available: boolean; reason?: string }>
  ensureLocalKeyPairForPublicKey: (publicKey: string) => Promise<{ fileName: string; publicKeyPath: string; privateKeyPath: string }>
  getPreferredSignerPublicKeyHex: () => Promise<string | undefined>
}

export function registerKeyTools(deps: KeyToolsDeps): void {
  const {
    server,
    keyRoot,
    mgtGET,
    mgtPOST,
    toMcpApiError,
    assertAgentCanSignManagementRequests,
    normalizeEd25519PublicKeyToHex,
    fetchManagementKeyOptions,
    resolveManagementSigningKeyOption,
    getNodeKey,
    buildManagementSigningMessage,
    signManagementMessage,
    listLocalManagementPublicKeys,
    getPrivateKeyStatus,
    ensureLocalKeyPairForPublicKey,
    getPreferredSignerPublicKeyHex,
  } = deps

  // 0.6 /hasPublicMgtKey
  server.registerTool(
    "has_eddsa_management_key",
    {
      description: "Check whether any EdDSA (Ed25519) key is configured to manage this MPC node client",
      outputSchema: z.object({ hasEdDSAKey: z.boolean() }),
    },
    async (): Promise<CallToolResult> => {
      const output = await mgtGET<boolean>("/hasPublicMgtKey")
      return {
        content: [{ type: "text", text: JSON.stringify({ hasEdDSAKey: output }) }],
        structuredContent: { hasEdDSAKey: output },
      }
    },
  )

  server.registerTool(
    "list_management_keys",
    {
      description: "List configured EdDSA signing keys and their signer index mapping (0=bootstrap, N=added_key_N).",
      outputSchema: z.object({
        preferredSigner: z.string().optional(),
        keys: z.array(
          z.object({
            localFileName: z.string().optional(),
            kind: z.literal("EdDSA"),
            value: z.string(),
            nonce: NonceSchema,
            label: z.string().optional(),
            localPrivateKeyAvailable: z.boolean(),
            localPrivateKeyError: z.string().optional(),
          }),
        ),
      }),
    },
    async (): Promise<CallToolResult> => {
      const keyOptions = await fetchManagementKeyOptions()
      const preferredSigner = await getPreferredSignerPublicKeyHex()
      const localKeys = await listLocalManagementPublicKeys()
      const localFileByPub = new Map(
        localKeys.filter((k) => k.publicKeyHex).map((k) => [k.publicKeyHex as EdDSAPubKey, k.fileName] as const),
      )
      const keys = await Promise.all(
        keyOptions.map(async (key) => {
          const privateKeyStatus = await getPrivateKeyStatus(key)
          const normalizedPublic = normalizeEd25519PublicKeyToHex(key.value) as EdDSAPubKey
          const localFileName = localFileByPub.get(normalizedPublic)
          return {
            ...key,
            localFileName,
            localPrivateKeyAvailable: privateKeyStatus.available,
            localPrivateKeyError: privateKeyStatus.reason,
          }
        }),
      )
      return {
        content: [{
          type: "text",
          text: keys
            .map((k, i) =>
              `${i + 1}. file=${k.localFileName ?? "?"} [${k.kind}] ${k.value} nonce=${k.nonce}${k.label ? ` (${k.label})` : ""} localPrivateKey=${k.localPrivateKeyAvailable ? "ok" : "missing/unusable"}${preferredSigner && normalizeEd25519PublicKeyToHex(k.value) === preferredSigner ? " [PREFERRED]" : ""}`,
            )
            .join("\n"),
        }],
        structuredContent: { preferredSigner, keys },
      }
    },
  )

  server.registerTool(
    "create_eddsa_management_keypair",
    {
      description: "Generate a new Ed25519 keypair in KEY_ROOT/management_keys with auto-generated file name added_key_{N}. This only writes local files.",
      outputSchema: z.object({
        success: z.boolean(),
        fileName: z.string(),
        publicKey: EdDSAPubKeySchema,
        message: z.string(),
        privateKeyPath: z.string(),
        publicKeyPath: z.string(),
      }),
    },
    async (): Promise<CallToolResult> => {
      const currentKeyCount = (await mgtGET<{ publicKey: EdDSAPubKey; label: string }[]>("/getAllowedEd25519MgtKeys")).length
      const fileName = `added_key_${currentKeyCount}`
      const keyDir = path.join(keyRoot, "management_keys")
      await fs.mkdir(keyDir, { recursive: true })

      const privateKeyPath = path.join(keyDir, fileName)
      const publicKeyPath = `${privateKeyPath}.pub`

      const privateExists = await fs.access(privateKeyPath).then(() => true).catch(() => false)
      if (privateExists) {
        throw toMcpApiError("Private key file already exists", { privateKeyPath })
      }
      const publicExists = await fs.access(publicKeyPath).then(() => true).catch(() => false)
      if (publicExists) {
        throw toMcpApiError("Public key file already exists", { publicKeyPath })
      }

      const { privateKey, publicKey } = generateKeyPairSync("ed25519")
      const privatePem = privateKey.export({ format: "pem", type: "pkcs8" }).toString()
      const publicJwk = publicKey.export({ format: "jwk" }) as { x?: string }
      if (!publicJwk.x) {
        throw toMcpApiError("Failed to derive Ed25519 raw public key from generated keypair")
      }
      const newPublicKey = Buffer.from(publicJwk.x, "base64url").toString("hex")

      await fs.writeFile(privateKeyPath, privatePem, { mode: 0o600 })
      await fs.writeFile(publicKeyPath, `${newPublicKey}\n`, { mode: 0o644 })

      const structuredContent = {
        success: true,
        fileName,
        publicKey: newPublicKey,
        message: "Generated Ed25519 management keypair locally.",
        privateKeyPath,
        publicKeyPath,
      }

      return {
        content: [{ type: "text", text: JSON.stringify(structuredContent) }],
        structuredContent,
      }
    },
  )

  server.registerTool(
    "add_eddsa_management_key",
    {
      description: "Add a new Ed25519 public key to allowed management keys via /addManagementKey, signed by preferred signer (or first locally-usable allowed signer).",
      inputSchema: z.object({
        newPublicKey: z.string(),
      }),
      outputSchema: z.object({
        success: z.boolean(),
        publicKey: EdDSAPubKeySchema,
        nodeKey: NodeIdSchema,
        message: z.string(),
      }),
    },
    async ({
      newPublicKey,
    }: {
      newPublicKey: string
    }): Promise<CallToolResult> => {
      await assertAgentCanSignManagementRequests()

      const normalizedNewPublicKey = normalizeEd25519PublicKeyToHex(newPublicKey) as EdDSAPubKey
      const nodeKey = await getNodeKey()
      const keyOptions = await fetchManagementKeyOptions()
      const selectedSigningKey = await resolveManagementSigningKeyOption(keyOptions)
      if (normalizeEd25519PublicKeyToHex(selectedSigningKey.value) === normalizedNewPublicKey) {
        throw toMcpApiError(
          "Signer key cannot be the newly created key being added. Use an existing already-authorized EdDSA signer key.",
          { signerPublicKey: selectedSigningKey.value, newPublicKey: normalizedNewPublicKey },
        )
      }

      const unsignedBody = { newPublicKey: normalizedNewPublicKey, nodeKey, Nonce: selectedSigningKey.nonce, Sig: "" }
      const signingMessage = buildManagementSigningMessage(unsignedBody)
      const signature = await signManagementMessage(selectedSigningKey, signingMessage)
      const body = { ...unsignedBody, Sig: signature }
      await mgtPOST<null>("/addManagementKey", body)

      const structuredContent = {
        success: true,
        publicKey: normalizedNewPublicKey,
        nodeKey,
        message: "Added Ed25519 management key successfully.",
      }

      return {
        content: [{ type: "text", text: JSON.stringify(structuredContent) }],
        structuredContent,
      }
    },
  )

  server.registerTool(
    "set_preferred_management_key",
    {
      description: "Set the preferred Ed25519 management signer. Input only the target publicKeyHex. This tool signs in-route: if a preferred signer is already set and usable, it is used; otherwise the server automatically falls back to the first allowed management key that has a usable local private key. It then verifies the requested preferred key exists locally with matching private key before calling /setPreferredSigner.",
      inputSchema: z.object({
        publicKeyHex: z.string(),
      }),
      outputSchema: z.object({
        success: z.boolean(),
        publicKeyHex: EdDSAPubKeySchema,
        signerPublicKey: EdDSAPubKeySchema,
        nodeKey: NodeIdSchema,
        Nonce: NonceSchema,
        signedMessage: z.string(),
        clientSig: z.string(),
        fileName: z.string(),
        message: z.string(),
      }),
    },
    async ({ publicKeyHex }: { publicKeyHex: string }): Promise<CallToolResult> => {
      const normalized = normalizeEd25519PublicKeyToHex(publicKeyHex) as EdDSAPubKey
      const keyOptions = await fetchManagementKeyOptions()
      const allowed = keyOptions.some((k) => normalizeEd25519PublicKeyToHex(k.value) === normalized)
      if (!allowed) {
        throw toMcpApiError("Preferred signer must already be in allowed management keys", { publicKeyHex: normalized })
      }
      const localMatch = await ensureLocalKeyPairForPublicKey(normalized)
      const selectedSigningKey = await resolveManagementSigningKeyOption(keyOptions)
      const nodeKey = await getNodeKey()
      const unsignedBody = {
        nodeKey,
        Nonce: selectedSigningKey.nonce,
        publicKey: normalized,
        Sig: "",
      }
      const signedMessage = buildManagementSigningMessage(unsignedBody)
      const clientSig = await signManagementMessage(selectedSigningKey, signedMessage)
      // /setPreferredSigner validates SetPreferredSignerPost: requires signedMessage + clientSig (not Sig).
      // Field names for nodeKey/Nonce/publicKey should match the canonical JSON inside signedMessage.
      const body = {
        nodeKey,
        Nonce: selectedSigningKey.nonce,
        publicKey: normalized,
        signedMessage,
        clientSig,
      }
      const apiMessage = await mgtPOST<string>("/setPreferredSigner", body)
      const structuredContent = {
        success: true,
        publicKeyHex: normalized,
        signerPublicKey: normalizeEd25519PublicKeyToHex(selectedSigningKey.value) as EdDSAPubKey,
        nodeKey,
        Nonce: selectedSigningKey.nonce,
        signedMessage,
        clientSig,
        fileName: localMatch.fileName,
        message: apiMessage || "Preferred signer stored",
      }
      return {
        content: [{ type: "text", text: JSON.stringify(structuredContent) }],
        structuredContent,
      }
    },
  )

  server.registerTool(
    "get_preferred_management_key",
    {
      description: "Get the configured preferred signer to use for management signing operations.",
      outputSchema: z.object({
        publicKeyHex: EdDSAPubKeySchema.optional(),
      }),
    },
    async (): Promise<CallToolResult> => {
      const preferred = await getPreferredSignerPublicKeyHex()
      const structuredContent = { publicKeyHex: preferred as EdDSAPubKey | undefined }
      return {
        content: [{ type: "text", text: JSON.stringify(structuredContent) }],
        structuredContent,
      }
    },
  )

  server.registerTool(
    "build_signed_request_plan",
    {
      description: "Management signing helper: build canonical unsigned body and messageToSign using preferred signer (or first locally-usable allowed signer).",
      inputSchema: z.object({
        action: z.string(),
        payload: z.record(z.string(), z.unknown()),
      }),
      outputSchema: z.object({
        action: z.string(),
        selectedSigningKey: SelectedSigningKeySchema,
        unsignedBody: z.record(z.string(), z.unknown()),
        nodeKey: NodeIdSchema,
        messageToSign: z.string(),
      }),
    },
    async ({ action, payload }: {
      action: string
      payload: Record<string, unknown>
    }): Promise<CallToolResult> => {
      const keys = await fetchManagementKeyOptions()
      const selectedSigningKey = await resolveManagementSigningKeyOption(keys)
      const nodeKey = await getNodeKey()
      const unsignedBody = {
        ...payload,
        nodeKey,
        Nonce: selectedSigningKey.nonce,
        Sig: "",
      }
      const messageToSign = buildManagementSigningMessage(unsignedBody)
      return {
        content: [{ type: "text", text: JSON.stringify({ action, selectedSigningKey, nodeKey, unsignedBody, messageToSign }) }],
        structuredContent: { action, selectedSigningKey, nodeKey, unsignedBody, messageToSign },
      }
    },
  )

  server.registerTool(
    "sign_management_message",
    {
      description: "Management signing helper: sign a canonical message using preferred signer (or first locally-usable allowed signer).",
      inputSchema: z.object({
        message: z.string(),
      }),
      outputSchema: z.object({
        signerPublicKey: z.string(),
        signature: ManagementSigSchema,
      }),
    },
    async ({ message }: { message: string }): Promise<CallToolResult> => {
      const keys = await fetchManagementKeyOptions()
      const selectedSigningKey = await resolveManagementSigningKeyOption(keys)
      const signature = await signManagementMessage(selectedSigningKey, message)
      return {
        content: [{ type: "text", text: JSON.stringify({ signerPublicKey: selectedSigningKey.value, signature }) }],
        structuredContent: { signerPublicKey: selectedSigningKey.value, signature },
      }
    },
  )

  // 0.4 /getNodeMgtKey & /getNodeMgtKeyNonce
  // 0.5 /getNodeMgtKeyNonce
  // 0.8 /getPublicMgtKey
  // 0.9 /getPublicMgtKeyNonce
  // 0.10 /verifyMgtKey
  // 0.11.1 /getMessageToSign
  // 0.12 /getAllowedKeyTypes
  // 0.13 /getAllowedMsgCheckTypes
  // Key-related commented blocks from index.ts are intentionally consolidated here.
}
