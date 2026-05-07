import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js"
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js"
import { z } from "zod"
import {
  GroupRequestIdSchema,
  ManagementSigSchema,
  NodeIdSchema,
  NonceSchema,
  type GroupRequestId,
  type GroupResult,
  type NodeId,
  type Nonce,
  type Sig,
} from "./types.js"

type QueryParamValue = string | number | boolean | null | undefined
type QueryParams = Record<string, QueryParamValue>
type RequestTarget = { host?: string; port?: string | number }

type ManagementKeyOption = {
  id: string
  kind: "EdDSA"
  value: string
  nonce: Nonce
  label?: string
}

type GroupToolsDeps = {
  server: McpServer
  mgtGET: <T>(path: string, params?: string | URLSearchParams | QueryParams, target?: RequestTarget) => Promise<T>
  mgtPOST: <T>(path: string, body?: BodyInit | object, params?: string | URLSearchParams | QueryParams) => Promise<T>
  toMcpApiError: (message: string, data?: unknown) => Error
  fetchManagementKeyOptions: () => Promise<ManagementKeyOption[]>
  getManagementKeyOptionByIndex: (keyOptions: ManagementKeyOption[], signerIndex: number) => Promise<ManagementKeyOption>
  buildManagementSigningMessage: (bodyWithEmptySig: Record<string, unknown>) => string
  signManagementMessage: (option: ManagementKeyOption, message: string) => Promise<Sig>
}

export function registerGroupTools(deps: GroupToolsDeps): void {
  const {
    server,
    mgtGET,
    mgtPOST,
    toMcpApiError,
    fetchManagementKeyOptions,
    getManagementKeyOptionByIndex,
    buildManagementSigningMessage,
    signManagementMessage,
  } = deps

  server.registerTool(
    "list_available_node_ids",
    {
      description: "List configured node IDs available for group selection, with index and self marker",
      outputSchema: z.object({
        selfNodeId: NodeIdSchema,
        nodes: z.array(z.object({
          index: z.number().int().positive(),
          ip: z.string(),
          nodeId: NodeIdSchema,
          isSelf: z.boolean(),
        })),
        nodeIdByIp: z.record(z.string(), NodeIdSchema),
      }),
    },
    async (): Promise<CallToolResult> => {
      const nodeIdByIp = await fetchNodeIds(mgtGET)
      const selfNodeId = await mgtGET<NodeId>("/getNodeKey")

      const nodes = Object.entries(nodeIdByIp).map(([ip, nodeId], idx) => ({
        index: idx + 1,
        ip,
        nodeId,
        isSelf: nodeId === selfNodeId,
      }))

      const lines = nodes.map((node) =>
        `${node.index}. ${node.nodeId} (${node.ip})${node.isSelf ? " [YOUR NODE]" : ""}`,
      )

      return {
        content: [{
          type: "text",
          text: [
            `Your node ID: ${selfNodeId}`,
            "Available node IDs:",
            ...lines,
          ].join("\n"),
        }],
        structuredContent: {
          selfNodeId,
          nodes,
          nodeIdByIp,
        },
      }
    },
  )

  server.registerTool(
    "create_group_request",
    {
      description: "Create a new MPC group request from explicit node IDs and signer index. Use list_available_node_ids/list_valid_group_node_sets first, then supply nodeIds (must include your node, be from configured nodes, min 2, and not already exist).",
      inputSchema: z.object({
        nodeIds: z.array(NodeIdSchema).min(2),
        signerIndex: z.number().int().nonnegative(),
      }),
      outputSchema: z.object({
        groupRequestId: GroupRequestIdSchema,
        selectedSigningKey: z.object({
          id: z.string(),
          kind: z.literal("EdDSA"),
          value: z.string(),
          nonce: NonceSchema,
          label: z.string().optional(),
        }),
        signingMessage: z.string(),
      }),
    },
    async ({
      nodeIds,
      signerIndex,
    }: {
      nodeIds: NodeId[]
      signerIndex: number
    }): Promise<CallToolResult> => {
      const nodeIdOptions = await fetchNodeIds(mgtGET)
      const selfNodeId = await mgtGET<NodeId>("/getNodeKey")
      const configuredNodeIds = Object.values(nodeIdOptions)
      const configuredSet = new Set(configuredNodeIds)
      const keyList = normalizeNodeIdList(nodeIds)

      const invalidNodeIds = keyList.filter((nodeId) => !configuredSet.has(nodeId))
      if (invalidNodeIds.length > 0) {
        throw toMcpApiError("nodeIds contains values not present in configured nodes", {
          invalidNodeIds,
          configuredNodeIds,
        })
      }

      if (keyList.length < 2) {
        throw toMcpApiError("At least two distinct nodeIds are required", { nodeIds })
      }
      if (!keyList.includes(selfNodeId)) {
        throw toMcpApiError("Selected nodeIds must include the originator node ID", { selfNodeId, nodeIds: keyList })
      }
      if (await groupExistsForNodeIds(keyList, mgtGET)) {
        throw toMcpApiError("A group with this exact node set already exists", { keyList })
      }

      const keyOptions = await fetchManagementKeyOptions()
      const selectedSigningKey = await getManagementKeyOptionByIndex(keyOptions, signerIndex)
      const unsignedBody = buildNewGroupUnsignedBody(keyList, [], selectedSigningKey.nonce)
      const signingMessage = buildManagementSigningMessage(unsignedBody)
      const signature = await signManagementMessage(selectedSigningKey, signingMessage)
      const body = { ...unsignedBody, sig: signature }
      const output = await mgtPOST<GroupRequestId>("/newGroupRequest", body)
      return {
        content: [{ type: "text", text: JSON.stringify({ groupRequestId: output, selectedSigningKey, signingMessage }) }],
        structuredContent: {
          groupRequestId: output,
          selectedSigningKey,
          signingMessage,
        },
      }
    },
  )

  server.registerTool(
    "list_valid_group_node_sets",
    {
      description: "List valid candidate nodeId sets for create_group_request (must include your node, subset of configured nodes, min 2, and not already-existing sets).",
      outputSchema: z.object({
        selfNodeId: NodeIdSchema,
        configuredNodeIds: z.array(NodeIdSchema),
        validPairs: z.array(z.array(NodeIdSchema)),
      }),
    },
    async (): Promise<CallToolResult> => {
      const nodeIdByIp = await fetchNodeIds(mgtGET)
      const selfNodeId = await mgtGET<NodeId>("/getNodeKey")
      const configuredNodeIds = normalizeNodeIdList(Object.values(nodeIdByIp))

      if (!configuredNodeIds.includes(selfNodeId)) {
        throw toMcpApiError("Originator node ID is not present in configured nodes", { selfNodeId, configuredNodeIds })
      }

      const others = configuredNodeIds.filter((id) => id !== selfNodeId)
      const validPairs: NodeId[][] = []
      for (const other of others) {
        const pair = normalizeNodeIdList([selfNodeId, other])
        if (!(await groupExistsForNodeIds(pair, mgtGET))) {
          validPairs.push(pair)
        }
      }

      return {
        content: [{
          type: "text",
          text: [
            `Your node ID: ${selfNodeId}`,
            `Configured node IDs (${configuredNodeIds.length}):`,
            ...configuredNodeIds.map((id, i) => `${i + 1}. ${id}${id === selfNodeId ? " [YOUR NODE]" : ""}`),
            "",
            "Valid 2-node sets that do not already exist:",
            ...(validPairs.length > 0 ? validPairs.map((pair, i) => `${i + 1}. ${pair.join(", ")}`) : ["(none)"]),
          ].join("\n"),
        }],
        structuredContent: {
          selfNodeId,
          configuredNodeIds,
          validPairs,
        },
      }
    },
  )
}

function buildNewGroupUnsignedBody(keyList: NodeId[], brokerArray: string[], nonce: Nonce): {
  nonce: Nonce
  sig: ""
  keyList: NodeId[]
  BrokerArray: string[]
} {
  return {
    nonce,
    sig: "",
    keyList,
    BrokerArray: brokerArray,
  }
}

function normalizeNodeIdList(nodeIds: NodeId[]): NodeId[] {
  return Array.from(new Set(nodeIds)).sort() as NodeId[]
}

function isSameNodeSet(left: NodeId[], right: NodeId[]): boolean {
  const leftNormalized = normalizeNodeIdList(left)
  const rightNormalized = normalizeNodeIdList(right)
  if (leftNormalized.length !== rightNormalized.length) {
    return false
  }
  return leftNormalized.every((value, idx) => value === rightNormalized[idx])
}

async function groupExistsForNodeIds(
  nodeIds: NodeId[],
  mgtGET: <T>(path: string, params?: string | URLSearchParams | QueryParams, target?: RequestTarget) => Promise<T>,
): Promise<boolean> {
  const response = await mgtGET<GroupResult[] | { results?: GroupResult[]; groupResults?: GroupResult[] }>("/listGroupResults")
  const results = Array.isArray(response)
    ? response
    : Array.isArray(response.results)
      ? response.results
      : Array.isArray(response.groupResults)
        ? response.groupResults
        : []

  return results.some((result) => isSameNodeSet(result.KeyList as NodeId[], nodeIds))
}

async function fetchNodeIds(
  mgtGET: <T>(path: string, params?: string | URLSearchParams | QueryParams, target?: RequestTarget) => Promise<T>,
): Promise<Record<string, NodeId>> {
  const configured = await mgtGET<{
    nodes: Array<{ address: string; available: boolean }>
    nodesMap: Record<string, { address: string; available: boolean }>
    total: number
    available: number
    unavailable: number
  }>("/getConfiguredNodeKeys")

  const entries = await Promise.all(
    configured.nodes.map(async (node) => {
      const parsed = new URL(node.address)
      const ip = parsed.hostname
      const nodeId = await mgtGET<NodeId>("/getNodeKey", undefined, {
        host: `${parsed.protocol}//${ip}`,
        port: "18080",
      })
      return [ip, nodeId] as const
    }),
  )

  return Object.fromEntries(entries)
}
