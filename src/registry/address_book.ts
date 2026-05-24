/**
 * Node client saved EOAs (known addresses / address book).
 * HTTP routes and shapes follow mpc-config `API_IMPLEMENTATION.md` (Known Addresses)
 * and `KNOWN_ADDRESSES_SCHEMA.md`.
 */

import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js"
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js"
import { z } from "zod"
import {
  ADDRESS_BOOK_REGISTRY_API_PATHS,
  GetKnownAddressesDataSchema,
  GetKnownAddressesQuerySchema,
  SelectedSigningKeySchema,
  type GetKnownAddressesData,
  type GetKnownAddressesQuery,
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

type AddressBookToolsDeps = {
  server: McpServer
  mgtGET: <T>(path: string, params?: string | URLSearchParams | QueryParams, target?: RequestTarget) => Promise<T>
  mgtPOST: <T>(path: string, body?: BodyInit | object, params?: string | URLSearchParams | QueryParams) => Promise<T>
  toMcpApiError: (message: string, data?: unknown) => Error
  fetchManagementKeyOptions: () => Promise<ManagementKeyOption[]>
  resolveManagementSigningKeyOption: (keyOptions: ManagementKeyOption[]) => Promise<ManagementKeyOption>
  buildManagementSigningMessage: (bodyWithEmptySig: Record<string, unknown>) => string
  signManagementMessage: (option: ManagementKeyOption, message: string) => Promise<Sig>
}

export function registerAddressBookTools(deps: AddressBookToolsDeps): void {
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

  server.registerTool(
    "add_to_address_book_registry",
    {
      description: `Add or update a known address (EOA or contract) in the local address book.${SIGNED_ROUTE_TOOL_NOTE}`,
      inputSchema: z.object({
        chainType: z.string().min(1).describe("The format of address; e.g. 'ethereum', 'solana', 'bitcoin'."),
        address: z.string().min(1),
        name: z.string().optional().describe("Label associated with this address."),
        chainIds: z.array(z.string()).optional(),
        isContract: z.boolean().optional().describe("Whether or not this address is a contract."),
      }),
      outputSchema: z.object({
        message: z.string(),
        selectedSigningKey: SelectedSigningKeySchema,
        signingMessage: z.string(),
      }),
    },
    async ({
      chainType,
      address,
      name,
      chainIds,
      isContract,
    }: {
      chainType: string
      address: string
      name?: string
      chainIds?: string[]
      isContract?: boolean
    }): Promise<CallToolResult> => {
      const nodeKey = await mgtGET<string>("/getNodeKey")
      const { selectedSigningKey, signingMessage, body } =
        await prepareSignedManagementRequest(
          {
            fetchManagementKeyOptions,
            resolveManagementSigningKeyOption,
            buildManagementSigningMessage,
            signManagementMessage,
          },
          ({ selectedSigningKey }) => {
            const fields: Record<string, unknown> = {
              chainType: chainType.trim().toLowerCase(),
              address: normalizeKnownAddressForChain(chainType, address),
            }
            if (name !== undefined && name.length > 0) {
              fields.name = name
            }
            fields.chainIds = chainIds ?? []
            if (isContract !== undefined) {
              fields.isContract = isContract
            }
            return buildManagementPostBody(selectedSigningKey.nonce, nodeKey, fields)
          },
        )
      const message = await mgtPOST<string>(ADDRESS_BOOK_REGISTRY_API_PATHS.add_to_address_book_registry, body)
      return {
        content: [{ type: "text", text: JSON.stringify({ message, selectedSigningKey, signingMessage }) }],
        structuredContent: { message, selectedSigningKey, signingMessage },
      }
    },
  )

  server.registerTool(
    "remove_from_address_book_registry",
    {
      description: `Remove a known address from the local address book for a chain type.${SIGNED_ROUTE_TOOL_NOTE}`,
      inputSchema: z.object({
        chainType: z.string().min(1),
        address: z.string().min(1),
      }),
      outputSchema: z.object({
        message: z.string(),
        selectedSigningKey: SelectedSigningKeySchema,
        signingMessage: z.string(),
      }),
    },
    async ({
      chainType,
      address,
    }: {
      chainType: string
      address: string
    }): Promise<CallToolResult> => {
      const nodeKey = await mgtGET<string>("/getNodeKey")
      const { selectedSigningKey, signingMessage, body } =
        await prepareSignedManagementRequest(
          {
            fetchManagementKeyOptions,
            resolveManagementSigningKeyOption,
            buildManagementSigningMessage,
            signManagementMessage,
          },
          ({ selectedSigningKey }) =>
            buildManagementPostBody(selectedSigningKey.nonce, nodeKey, {
              chainType: chainType.trim().toLowerCase(),
              address: normalizeKnownAddressForChain(chainType, address),
            }),
        )
      const message = await mgtPOST<string>(ADDRESS_BOOK_REGISTRY_API_PATHS.remove_from_address_book_registry, body)
      return {
        content: [{ type: "text", text: JSON.stringify({ message, selectedSigningKey, signingMessage }) }],
        structuredContent: { message, selectedSigningKey, signingMessage },
      }
    },
  )

  server.registerTool(
    "get_address_book_registry",
    {
      description: "List known addresses stored on this node, grouped by chain type. Optional filters: chain_type, chain_id, is_contract (0 = EOA, 1 = contract).",
      inputSchema: GetKnownAddressesQuerySchema,
      outputSchema: GetKnownAddressesDataSchema,
    },
    async (query: GetKnownAddressesQuery): Promise<CallToolResult> => {
      const params = new URLSearchParams()
      if (query.chain_type !== undefined) {
        params.append("chain_type", query.chain_type)
      }
      if (query.chain_id !== undefined) {
        params.append("chain_id", query.chain_id)
      }
      if (query.is_contract !== undefined) {
        params.append("is_contract", query.is_contract)
      }
      const raw = await mgtGET<unknown>(ADDRESS_BOOK_REGISTRY_API_PATHS.get_address_book_registry, params)
      const parsed = GetKnownAddressesDataSchema.safeParse(raw)
      if (!parsed.success) {
        throw toMcpApiError("Invalid getKnownAddresses response shape", { issues: parsed.error.issues, raw })
      }
      const data: GetKnownAddressesData = parsed.data
      return {
        content: [{ type: "text", text: JSON.stringify(data) }],
        structuredContent: data,
      }
    },
  )
}

function normalizeKnownAddressForChain(chainType: string, address: string): string {
  const t = chainType.trim().toLowerCase()
  const a = address.trim()
  if (t === "ethereum" && /^0x[a-fA-F0-9]{40}$/.test(a)) {
    return a.toLowerCase()
  }
  return a
}

export async function loadAddressBookRegistry(): Promise<void> {
  // Reserved for configuring persisted / in-memory EOA entries.
}
