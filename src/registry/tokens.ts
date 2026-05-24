/**
 * Saved token contract addresses and their ERC standard (local node only).
 * HTTP routes and shapes follow mpc-config `API_IMPLEMENTATION.md` (Local Token Config)
 * and `TOKEN_STORAGE_SCHEMA.md`.
 */

import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js"
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js"
import { z } from "zod"
import {
  GetTokenRegistryDataSchema,
  GetTokenRegistryQuerySchema,
  SelectedSigningKeySchema,
  TOKEN_REGISTRY_API_PATHS,
  TokenContractInputSchema,
  TokenTypeSchema,
  type GetTokenRegistryData,
  type GetTokenRegistryQuery,
  type Sig,
  type TokenContractInput,
  type TokenType,
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

type TokenRegistryToolsDeps = {
  server: McpServer
  mgtGET: <T>(path: string, params?: string | URLSearchParams | QueryParams, target?: RequestTarget) => Promise<T>
  mgtPOST: <T>(path: string, body?: BodyInit | object, params?: string | URLSearchParams | QueryParams) => Promise<T>
  toMcpApiError: (message: string, data?: unknown) => Error
  fetchManagementKeyOptions: () => Promise<ManagementKeyOption[]>
  resolveManagementSigningKeyOption: (keyOptions: ManagementKeyOption[]) => Promise<ManagementKeyOption>
  buildManagementSigningMessage: (bodyWithEmptySig: Record<string, unknown>) => string
  signManagementMessage: (option: ManagementKeyOption, message: string) => Promise<Sig>
}

export function registerTokenRegistryTools(deps: TokenRegistryToolsDeps): void {
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
    "add_to_token_registry",
    {
      description: `Add or update a saved token contract on this node for a chain type, chain ID, and token standard (ERC20, ERC721, CTMERC20, CTMRWA1).${SIGNED_ROUTE_TOOL_NOTE}`,
      inputSchema: z.object({
        chainType: z.string().min(1).describe("e.g. ethereum, solana, NEAR, stellar, TON (stored lowercase)."),
        chainId: z.union([z.string().min(1), z.number().int().nonnegative()]),
        tokenType: TokenTypeSchema,
        contract: TokenContractInputSchema,
        transferSig: z.string().optional(),
        transferNames: z.array(z.string()).optional(),
      }),
      outputSchema: z.object({
        message: z.string(),
        selectedSigningKey: SelectedSigningKeySchema,
        signingMessage: z.string(),
      }),
    },
    async ({
      chainType,
      chainId,
      tokenType,
      contract,
      transferSig,
      transferNames,
    }: {
      chainType: string
      chainId: string | number
      tokenType: TokenType
      contract: TokenContractInput
      transferSig?: string
      transferNames?: string[]
    }): Promise<CallToolResult> => {
      const normalizedChainType = chainType.trim().toLowerCase()
      const normalizedContract = normalizeTokenContract(contract, normalizedChainType, tokenType)
      const nodeKey = await mgtGET<string>("/getNodeKey")

      const { selectedSigningKey, signingMessage, body } = await prepareSignedManagementRequest(
        signingDeps,
        ({ selectedSigningKey }) => {
          const fields: Record<string, unknown> = {
            chainType: normalizedChainType,
            chainId,
            tokenType,
            contract: normalizedContract,
          }
          if (transferSig !== undefined && transferSig.length > 0) {
            fields.transferSig = transferSig
          }
          if (transferNames !== undefined && transferNames.length > 0) {
            fields.transferNames = transferNames
          }
          return buildManagementPostBody(selectedSigningKey.nonce, nodeKey, fields)
        },
      )

      const message = await mgtPOST<string>(TOKEN_REGISTRY_API_PATHS.add_to_token_registry, body)
      return {
        content: [{ type: "text", text: JSON.stringify({ message, selectedSigningKey, signingMessage }) }],
        structuredContent: { message, selectedSigningKey, signingMessage },
      }
    },
  )

  server.registerTool(
    "remove_from_token_registry",
    {
      description: `Remove a saved token contract from this node. For ERC721, tokenId is required.${SIGNED_ROUTE_TOOL_NOTE}`,
      inputSchema: z.object({
        chainType: z.string().min(1),
        chainId: z.union([z.string().min(1), z.number().int().nonnegative()]),
        tokenType: TokenTypeSchema,
        contractAddress: z.string().min(1),
        tokenId: z.string().optional().describe("Required when tokenType is ERC721."),
      }),
      outputSchema: z.object({
        message: z.string(),
        selectedSigningKey: SelectedSigningKeySchema,
        signingMessage: z.string(),
      }),
    },
    async ({
      chainType,
      chainId,
      tokenType,
      contractAddress,
      tokenId,
    }: {
      chainType: string
      chainId: string | number
      tokenType: TokenType
      contractAddress: string
      tokenId?: string
    }): Promise<CallToolResult> => {
      const normalizedChainType = chainType.trim().toLowerCase()
      const normalizedAddress = normalizeContractAddress(normalizedChainType, contractAddress)

      if (tokenType === "ERC721" && (tokenId === undefined || tokenId.trim().length === 0)) {
        throw toMcpApiError("tokenId is required when tokenType is ERC721", { tokenType, contractAddress })
      }

      const nodeKey = await mgtGET<string>("/getNodeKey")

      const { selectedSigningKey, signingMessage, body } = await prepareSignedManagementRequest(
        signingDeps,
        ({ selectedSigningKey }) => {
          const fields: Record<string, unknown> = {
            chainType: normalizedChainType,
            chainId,
            tokenType,
            contractAddress: normalizedAddress,
          }
          if (tokenType === "ERC721" && tokenId !== undefined) {
            fields.tokenId = tokenId.trim()
          }
          return buildManagementPostBody(selectedSigningKey.nonce, nodeKey, fields)
        },
      )

      const message = await mgtPOST<string>(TOKEN_REGISTRY_API_PATHS.remove_from_token_registry, body)
      return {
        content: [{ type: "text", text: JSON.stringify({ message, selectedSigningKey, signingMessage }) }],
        structuredContent: { message, selectedSigningKey, signingMessage },
      }
    },
  )

  server.registerTool(
    "get_token_registry",
    {
      description:
        "List token contracts saved on this node, grouped by chain type. Optional filters: chainType, chain_id.",
      inputSchema: GetTokenRegistryQuerySchema,
      outputSchema: GetTokenRegistryDataSchema,
    },
    async (query: GetTokenRegistryQuery = {}): Promise<CallToolResult> => {
      const params = new URLSearchParams()
      if (query.chainType !== undefined) {
        params.append("chainType", query.chainType)
      }
      if (query.chain_id !== undefined) {
        params.append("chain_id", query.chain_id)
      }
      const raw = await mgtGET<unknown>(TOKEN_REGISTRY_API_PATHS.get_token_registry, params)
      const parsed = GetTokenRegistryDataSchema.safeParse(raw)
      if (!parsed.success) {
        throw toMcpApiError("Invalid getTokens response shape", { issues: parsed.error.issues, raw })
      }
      const data: GetTokenRegistryData = parsed.data
      return {
        content: [{ type: "text", text: JSON.stringify(data) }],
        structuredContent: data,
      }
    },
  )
}

function normalizeContractAddress(chainType: string, address: string): string {
  const a = address.trim()
  if (chainType === "ethereum" && /^0x[a-fA-F0-9]{40}$/.test(a)) {
    return a.toLowerCase()
  }
  return a
}

function normalizeTokenContract(
  contract: TokenContractInput,
  chainType: string,
  tokenType: TokenType,
): Record<string, unknown> {
  const out: Record<string, unknown> = { ...contract }
  out.contractAddress = normalizeContractAddress(chainType, contract.contractAddress)
  if (tokenType === "ERC721" && contract.tokenId !== undefined) {
    out.tokenId = String(contract.tokenId).trim()
  }
  return out
}

export async function loadTokensRegistry(): Promise<void> {
  // Reserved for configuring persisted / in-memory token entries.
}
