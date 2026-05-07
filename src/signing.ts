import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js"
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js"
import { z } from "zod"
import { ManagementSigSchema, NonceSchema, type EdDSAPubKey, type Nonce, type Sig } from "./types.js"

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

type SigningToolsDeps = {
  server: McpServer
  fetchManagementKeyOptions: () => Promise<ManagementKeyOption[]>
  listLocalManagementPublicKeys: () => Promise<LocalManagementKeyEntry[]>
  getPrivateKeyStatus: (option: ManagementKeyOption) => Promise<{ available: boolean; reason?: string }>
  normalizeEd25519PublicKeyToHex: (value: string) => string
  getManagementKeyOptionByIndex: (keyOptions: ManagementKeyOption[], signerIndex: number) => Promise<ManagementKeyOption>
  buildManagementSigningMessage: (bodyWithEmptySig: Record<string, unknown>) => string
  signManagementMessage: (option: ManagementKeyOption, message: string) => Promise<Sig>
}

export function registerSigningTools(deps: SigningToolsDeps): void {
  const {
    server,
    fetchManagementKeyOptions,
    listLocalManagementPublicKeys,
    getPrivateKeyStatus,
    normalizeEd25519PublicKeyToHex,
    getManagementKeyOptionByIndex,
    buildManagementSigningMessage,
    signManagementMessage,
  } = deps

  server.registerTool(
    "list_management_signing_keys",
    {
      description: "List configured EdDSA signing keys and their signer index mapping (0=bootstrap, N=added_key_N).",
      outputSchema: z.object({
        keys: z.array(
          z.object({
            signerIndex: z.number().int().nonnegative().optional(),
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
      const localKeys = await listLocalManagementPublicKeys()
      const localFileByPub = new Map(
        localKeys.filter((k) => k.publicKeyHex).map((k) => [k.publicKeyHex as EdDSAPubKey, k.fileName] as const),
      )
      const keys = await Promise.all(
        keyOptions.map(async (key) => {
          const privateKeyStatus = await getPrivateKeyStatus(key)
          const normalizedPublic = normalizeEd25519PublicKeyToHex(key.value) as EdDSAPubKey
          const localFileName = localFileByPub.get(normalizedPublic)
          let signerIndex: number | undefined
          if (localFileName) {
            const addedMatch = localFileName.match(/^added_key_(\d+)$/i)
            signerIndex = addedMatch ? Number(addedMatch[1]) : 0
          }
          return {
            ...key,
            signerIndex,
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
              `${i + 1}. signerIndex=${k.signerIndex ?? "?"} file=${k.localFileName ?? "?"} [${k.kind}] ${k.value} nonce=${k.nonce}${k.label ? ` (${k.label})` : ""} localPrivateKey=${k.localPrivateKeyAvailable ? "ok" : "missing/unusable"}`,
            )
            .join("\n"),
        }],
        structuredContent: { keys },
      }
    },
  )

  server.registerTool(
    "build_signed_request_plan",
    {
      description: "Route-agnostic helper: build canonical unsigned body and messageToSign for signer index (0=bootstrap, N=added_key_N).",
      inputSchema: z.object({
        action: z.string(),
        signerIndex: z.number().int().nonnegative(),
        payload: z.record(z.string(), z.unknown()),
      }),
      outputSchema: z.object({
        action: z.string(),
        selectedSigningKey: z.object({
          id: z.string(),
          kind: z.literal("EdDSA"),
          value: z.string(),
          nonce: NonceSchema,
          label: z.string().optional(),
        }),
        unsignedBody: z.record(z.string(), z.unknown()),
        messageToSign: z.string(),
      }),
    },
    async ({ action, signerIndex, payload }: {
      action: string
      signerIndex: number
      payload: Record<string, unknown>
    }): Promise<CallToolResult> => {
      const keys = await fetchManagementKeyOptions()
      const selectedSigningKey = await getManagementKeyOptionByIndex(keys, signerIndex)
      const unsignedBody = {
        ...payload,
        nonce: selectedSigningKey.nonce,
        sig: "",
      }
      const messageToSign = buildManagementSigningMessage(unsignedBody)
      return {
        content: [{ type: "text", text: JSON.stringify({ action, selectedSigningKey, unsignedBody, messageToSign }) }],
        structuredContent: { action, selectedSigningKey, unsignedBody, messageToSign },
      }
    },
  )

  server.registerTool(
    "sign_management_message",
    {
      description: "Route-agnostic helper: sign a canonical message using signer index (0=bootstrap, N=added_key_N).",
      inputSchema: z.object({
        signerIndex: z.number().int().nonnegative(),
        message: z.string(),
      }),
      outputSchema: z.object({
        signerIndex: z.number().int().nonnegative(),
        signature: ManagementSigSchema,
      }),
    },
    async ({ signerIndex, message }: {
      signerIndex: number
      message: string
    }): Promise<CallToolResult> => {
      const keys = await fetchManagementKeyOptions()
      const selectedSigningKey = await getManagementKeyOptionByIndex(keys, signerIndex)
      const signature = await signManagementMessage(selectedSigningKey, message)
      return {
        content: [{ type: "text", text: JSON.stringify({ signerIndex, signature }) }],
        structuredContent: { signerIndex, signature },
      }
    },
  )
}
