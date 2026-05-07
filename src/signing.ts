import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js"
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js"
import { z } from "zod"
import { ManagementSigSchema, NodeIdSchema, NonceSchema, type NodeId, type Nonce, type Sig } from "./types.js"

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
  resolveManagementSigningKeyOption: (keyOptions: ManagementKeyOption[]) => Promise<ManagementKeyOption>
  getNodeKey: () => Promise<NodeId>
  buildManagementSigningMessage: (bodyWithEmptySig: Record<string, unknown>) => string
  signManagementMessage: (option: ManagementKeyOption, message: string) => Promise<Sig>
}

export function registerSigningTools(deps: SigningToolsDeps): void {
  const {
    server,
    fetchManagementKeyOptions,
    resolveManagementSigningKeyOption,
    getNodeKey,
    buildManagementSigningMessage,
    signManagementMessage,
  } = deps

  server.registerTool(
    "build_signed_request_plan",
    {
      description: "Route-agnostic helper: build canonical unsigned body and messageToSign using preferred signer (or first locally-usable allowed signer).",
      inputSchema: z.object({
        action: z.string(),
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
      description: "Route-agnostic helper: sign a canonical message using preferred signer (or first locally-usable allowed signer).",
      inputSchema: z.object({
        message: z.string(),
      }),
      outputSchema: z.object({
        signerPublicKey: z.string(),
        signature: ManagementSigSchema,
      }),
    },
    async ({ message }: {
      message: string
    }): Promise<CallToolResult> => {
      const keys = await fetchManagementKeyOptions()
      const selectedSigningKey = await resolveManagementSigningKeyOption(keys)
      const signature = await signManagementMessage(selectedSigningKey, message)
      return {
        content: [{ type: "text", text: JSON.stringify({ signerPublicKey: selectedSigningKey.value, signature }) }],
        structuredContent: { signerPublicKey: selectedSigningKey.value, signature },
      }
    },
  )
}
