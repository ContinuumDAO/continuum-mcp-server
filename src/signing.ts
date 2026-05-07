import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js"
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js"
import { z } from "zod"
import { ManagementSigSchema, NonceSchema, type Nonce, type Sig } from "./types.js"

type ManagementKeyOption = {
  id: string
  kind: "EdDSA"
  value: string
  nonce: Nonce
  label?: string
}

type SigningToolsDeps = {
  server: McpServer
  fetchManagementKeyOptions: () => Promise<ManagementKeyOption[]>
  getManagementKeyOptionByIndex: (keyOptions: ManagementKeyOption[], signerIndex: number) => Promise<ManagementKeyOption>
  buildManagementSigningMessage: (bodyWithEmptySig: Record<string, unknown>) => string
  signManagementMessage: (option: ManagementKeyOption, message: string) => Promise<Sig>
}

export function registerSigningTools(deps: SigningToolsDeps): void {
  const {
    server,
    fetchManagementKeyOptions,
    getManagementKeyOptionByIndex,
    buildManagementSigningMessage,
    signManagementMessage,
  } = deps

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
