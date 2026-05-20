/**
 * Saved chain definitions: RPC URLs, gas defaults, block explorers, name/symbol, etc.
 * HTTP routes follow mpc-config `API_IMPLEMENTATION.md` (Chain config details).
 */

import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js"
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js"
import { z } from "zod"
import {
  CHAIN_REGISTRY_API_PATHS,
  ChainRegistryEntrySchema,
  DefaultGetSigFeeSpeedSchema,
  GetChainRegistryDataSchema,
  GetChainRegistryQuerySchema,
  SelectedSigningKeySchema,
  type DefaultGetSigFeeSpeed,
  type GetChainRegistryData,
  type GetChainRegistryQuery,
  type Sig,
} from "../types.js"
import {
  prepareActionSignedManagementRequest,
  SIGNED_ROUTE_TOOL_NOTE,
  type ManagementKeyOption,
} from "../management-signing-flow.js"

type QueryParamValue = string | number | boolean | null | undefined
type QueryParams = Record<string, QueryParamValue>
type RequestTarget = { host?: string; port?: string | number }

type ChainRegistryToolsDeps = {
  server: McpServer
  mgtGET: <T>(path: string, params?: string | URLSearchParams | QueryParams, target?: RequestTarget) => Promise<T>
  mgtPOST: <T>(path: string, body?: BodyInit | object, params?: string | URLSearchParams | QueryParams) => Promise<T>
  toMcpApiError: (message: string, data?: unknown) => Error
  fetchManagementKeyOptions: () => Promise<ManagementKeyOption[]>
  resolveManagementSigningKeyOption: (keyOptions: ManagementKeyOption[]) => Promise<ManagementKeyOption>
  buildManagementSigningMessage: (bodyWithEmptySig: Record<string, unknown>) => string
  signManagementMessage: (option: ManagementKeyOption, message: string) => Promise<Sig>
}

const AddChainRegistryInputSchema = z.object({
  chainName: z.string().min(1),
  chainId: z.union([z.string().min(1), z.number().int().nonnegative()]),
  rpcGateway: z.string().min(1),
  explorer: z.string().optional(),
  legacy: z.boolean().optional(),
  testnet: z.boolean().optional(),
  gasName: z.string().optional(),
  gasLimit: z.number().nonnegative().optional(),
  baseFee: z.number().nullable().optional(),
  priorityFee: z.number().nullable().optional(),
  baseFeeMultiplier: z.number().min(100).optional(),
  gasMultiplier: z.number().optional(),
  gasPrice: z.number().optional(),
  defaultGetSigFeeSpeed: DefaultGetSigFeeSpeedSchema.optional(),
})

export function registerChainRegistryTools(deps: ChainRegistryToolsDeps): void {
  const {
    server,
    mgtGET,
    mgtPOST,
    toMcpApiError,
    fetchManagementKeyOptions,
    resolveManagementSigningKeyOption,
    buildManagementSigningMessage,
    signManagementMessage,
  } = deps

  const signingDeps = {
    fetchManagementKeyOptions,
    resolveManagementSigningKeyOption,
    buildManagementSigningMessage,
    signManagementMessage,
  }

  server.registerTool(
    "add_to_chain_registry",
    {
      description: `Store or update saved chain configuration (RPC, explorer, gas defaults) on this node.${SIGNED_ROUTE_TOOL_NOTE}`,
      inputSchema: AddChainRegistryInputSchema,
      outputSchema: z.object({
        message: z.string(),
        selectedSigningKey: SelectedSigningKeySchema,
        signingMessage: z.string(),
      }),
    },
    async (input: z.infer<typeof AddChainRegistryInputSchema>): Promise<CallToolResult> => {
      const chainIdStr = normalizeChainId(input.chainId)
      const legacy = input.legacy ?? false
      const testnet = input.testnet ?? false

      const { selectedSigningKey, signingMessage, signature } = await prepareActionSignedManagementRequest(
        signingDeps,
        ({ selectedSigningKey }) =>
          buildPostChainDetailsSigningPayload({
            nonce: selectedSigningKey.nonce,
            chainName: input.chainName.trim(),
            chainId: chainIdStr,
            rpcGateway: input.rpcGateway.trim(),
            explorer: input.explorer?.trim(),
            legacy,
            testnet,
            gasName: input.gasName?.trim(),
            gasLimit: input.gasLimit,
            baseFee: input.baseFee,
            priorityFee: input.priorityFee,
            baseFeeMultiplier: input.baseFeeMultiplier,
            gasMultiplier: input.gasMultiplier,
            gasPrice: input.gasPrice,
            defaultGetSigFeeSpeed: input.defaultGetSigFeeSpeed,
          }),
      )

      const postBody: Record<string, unknown> = {
        nonce: selectedSigningKey.nonce,
        chainName: input.chainName.trim(),
        chainId: input.chainId,
        rpcGateway: input.rpcGateway.trim(),
        legacy,
        testnet,
        signedMessage: signingMessage,
        clientSig: signature,
      }
      if (input.explorer !== undefined && input.explorer.length > 0) {
        postBody.explorer = input.explorer.trim()
      }
      if (input.gasName !== undefined && input.gasName.length > 0) {
        postBody.gasName = input.gasName.trim()
      }
      if (input.gasLimit !== undefined) {
        postBody.gasLimit = input.gasLimit
      }
      if (input.baseFee !== undefined) {
        postBody.baseFee = input.baseFee
      }
      if (input.priorityFee !== undefined) {
        postBody.priorityFee = input.priorityFee
      }
      if (input.baseFeeMultiplier !== undefined) {
        postBody.baseFeeMultiplier = input.baseFeeMultiplier
      }
      if (input.gasMultiplier !== undefined) {
        postBody.gasMultiplier = input.gasMultiplier
      }
      if (input.gasPrice !== undefined) {
        postBody.gasPrice = input.gasPrice
      }
      if (input.defaultGetSigFeeSpeed !== undefined) {
        postBody.defaultGetSigFeeSpeed = input.defaultGetSigFeeSpeed
      }

      const message = await mgtPOST<string>(CHAIN_REGISTRY_API_PATHS.add_to_chain_registry, postBody)
      return {
        content: [{ type: "text", text: JSON.stringify({ message, selectedSigningKey, signingMessage }) }],
        structuredContent: { message, selectedSigningKey, signingMessage },
      }
    },
  )

  server.registerTool(
    "remove_from_chain_registry",
    {
      description: `Remove saved chain configuration for one chain ID on this node.${SIGNED_ROUTE_TOOL_NOTE}`,
      inputSchema: z.object({
        chainId: z.union([z.string().min(1), z.number().int().nonnegative()]),
      }),
      outputSchema: z.object({
        message: z.string(),
        selectedSigningKey: SelectedSigningKeySchema,
        signingMessage: z.string(),
      }),
    },
    async ({ chainId }: { chainId: string | number }): Promise<CallToolResult> => {
      const chainIdStr = normalizeChainId(chainId)

      const { selectedSigningKey, signingMessage, signature } = await prepareActionSignedManagementRequest(
        signingDeps,
        ({ selectedSigningKey }) => ({
          nonce: selectedSigningKey.nonce,
          chainId: chainIdStr,
          action: "removeChainDetails",
        }),
      )

      const postBody = {
        nonce: selectedSigningKey.nonce,
        chainId,
        signedMessage: signingMessage,
        clientSig: signature,
      }

      const message = await mgtPOST<string>(CHAIN_REGISTRY_API_PATHS.remove_from_chain_registry, postBody)
      return {
        content: [{ type: "text", text: JSON.stringify({ message, selectedSigningKey, signingMessage }) }],
        structuredContent: { message, selectedSigningKey, signingMessage },
      }
    },
  )

  server.registerTool(
    "get_chain_registry",
    {
      description:
        "List chain configurations saved on this node. Optional chain_id filters to one chain. Returns { chains: [...] } (normalized from GET /getChainDetails).",
      inputSchema: GetChainRegistryQuerySchema,
      outputSchema: GetChainRegistryDataSchema,
    },
    async (query: GetChainRegistryQuery = {}): Promise<CallToolResult> => {
      const params = new URLSearchParams()
      if (query.chain_id !== undefined) {
        params.append("chain_id", query.chain_id)
      }
      const raw = await mgtGET<unknown>(CHAIN_REGISTRY_API_PATHS.get_chain_registry, params)
      const chains = normalizeGetChainDetailsResponse(raw)
      const parsed = GetChainRegistryDataSchema.safeParse({ chains })
      if (!parsed.success) {
        throw toMcpApiError("Invalid getChainDetails response shape", { issues: parsed.error.issues, raw })
      }
      const data: GetChainRegistryData = parsed.data
      return {
        content: [{ type: "text", text: JSON.stringify(data) }],
        structuredContent: data,
      }
    },
  )
}

function normalizeGetChainDetailsResponse(raw: unknown): z.infer<typeof ChainRegistryEntrySchema>[] {
  if (raw === null || raw === undefined) {
    return []
  }
  if (Array.isArray(raw)) {
    return raw as z.infer<typeof ChainRegistryEntrySchema>[]
  }
  if (typeof raw === "object") {
    return [raw as z.infer<typeof ChainRegistryEntrySchema>]
  }
  return []
}

function normalizeChainId(chainId: string | number): string {
  return typeof chainId === "number" ? String(chainId) : chainId.trim()
}

/**
 * Canonical JSON for `POST /postChainDetails` signedMessage (per API_IMPLEMENTATION.md example).
 */
function buildPostChainDetailsSigningPayload(fields: {
  nonce: number
  chainName: string
  chainId: string
  rpcGateway: string
  explorer?: string
  legacy: boolean
  testnet: boolean
  gasName?: string
  gasLimit?: number
  baseFee?: number | null
  priorityFee?: number | null
  baseFeeMultiplier?: number
  gasMultiplier?: number
  gasPrice?: number
  defaultGetSigFeeSpeed?: DefaultGetSigFeeSpeed
}): Record<string, unknown> {
  const payload: Record<string, unknown> = {
    nonce: fields.nonce,
    chainName: fields.chainName,
    chainId: fields.chainId,
    rpcGateway: fields.rpcGateway,
    legacy: fields.legacy,
    testnet: fields.testnet,
  }
  if (fields.explorer !== undefined && fields.explorer.length > 0) {
    payload.explorer = fields.explorer
  }
  if (fields.gasName !== undefined && fields.gasName.length > 0) {
    payload.gasName = fields.gasName
  }
  if (fields.gasLimit !== undefined) {
    payload.gasLimit = fields.gasLimit
  }
  if (fields.baseFee !== undefined) {
    payload.baseFee = fields.baseFee
  }
  if (fields.priorityFee !== undefined) {
    payload.priorityFee = fields.priorityFee
  }
  if (fields.baseFeeMultiplier !== undefined) {
    payload.baseFeeMultiplier = fields.baseFeeMultiplier
  }
  if (fields.gasMultiplier !== undefined) {
    payload.gasMultiplier = fields.gasMultiplier
  }
  if (fields.gasPrice !== undefined) {
    payload.gasPrice = fields.gasPrice
  }
  if (fields.defaultGetSigFeeSpeed !== undefined) {
    payload.defaultGetSigFeeSpeed = fields.defaultGetSigFeeSpeed
  }
  return payload
}

export async function loadNetworksRegistry(): Promise<void> {
  // Reserved for configuring persisted / in-memory chain entries.
}
