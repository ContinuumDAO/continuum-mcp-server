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
  prepareSignedManagementRequest,
  SIGNED_ROUTE_TOOL_NOTE,
  type ManagementKeyOption,
} from "../management-signing-flow.js"
import { buildManagementPostBody } from "../management-post-sig.js"

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
      const nodeKey = await mgtGET<string>("/getNodeKey")

      const { selectedSigningKey, signingMessage, body } = await prepareSignedManagementRequest(
        signingDeps,
        ({ selectedSigningKey }) => {
          const fields: Record<string, unknown> = {
            chainName: input.chainName.trim(),
            chainId: input.chainId,
            rpcGateway: input.rpcGateway.trim(),
            legacy,
            testnet,
          }
          if (input.explorer !== undefined && input.explorer.length > 0) {
            fields.explorer = input.explorer.trim()
          }
          if (input.gasName !== undefined && input.gasName.length > 0) {
            fields.gasName = input.gasName.trim()
          }
          if (input.gasLimit !== undefined) {
            fields.gasLimit = input.gasLimit
          }
          if (input.baseFee !== undefined) {
            fields.baseFee = input.baseFee
          }
          if (input.priorityFee !== undefined) {
            fields.priorityFee = input.priorityFee
          }
          if (input.baseFeeMultiplier !== undefined) {
            fields.baseFeeMultiplier = input.baseFeeMultiplier
          }
          if (input.gasMultiplier !== undefined) {
            fields.gasMultiplier = input.gasMultiplier
          }
          if (input.gasPrice !== undefined) {
            fields.gasPrice = input.gasPrice
          }
          if (input.defaultGetSigFeeSpeed !== undefined) {
            fields.defaultGetSigFeeSpeed = input.defaultGetSigFeeSpeed
          }
          return buildManagementPostBody(selectedSigningKey.nonce, nodeKey, fields)
        },
      )

      const message = await mgtPOST<string>(CHAIN_REGISTRY_API_PATHS.add_to_chain_registry, body)
      return {
        content: [{ type: "text", text: JSON.stringify({ message, selectedSigningKey, signingMessage, chainId: chainIdStr }) }],
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
      const nodeKey = await mgtGET<string>("/getNodeKey")

      const { selectedSigningKey, signingMessage, body } = await prepareSignedManagementRequest(
        signingDeps,
        ({ selectedSigningKey }) =>
          buildManagementPostBody(selectedSigningKey.nonce, nodeKey, { chainId }),
      )

      const message = await mgtPOST<string>(CHAIN_REGISTRY_API_PATHS.remove_from_chain_registry, body)
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

export async function loadNetworksRegistry(): Promise<void> {
  // Reserved for configuring persisted / in-memory chain entries.
}
