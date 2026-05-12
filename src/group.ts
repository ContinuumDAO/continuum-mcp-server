import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js"
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js"
import { z } from "zod"
import {
  FilterSchema,
  GroupIdSchema,
  GroupRequestSchema,
  GroupResultSchema,
  GroupRequestIdSchema,
  ManagementSigSchema,
  NodeIdSchema,
  SelectedSigningKeySchema,
  type Filter,
  type GroupId,
  type GroupRequest,
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
  resolveManagementSigningKeyOption: (keyOptions: ManagementKeyOption[]) => Promise<ManagementKeyOption>
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
    resolveManagementSigningKeyOption,
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
    "accept_group_request",
    {
      description: "Agree to a pending incoming group request by request ID using preferred signer (or first locally-usable allowed signer). Used by non-originator requested nodes; originator auto-agrees at request creation. A group is formed only after ALL requested nodes agree.",
      inputSchema: z.object({
        requestId: GroupRequestIdSchema,
      }),
      outputSchema: z.object({
        message: z.string(),
        selectedSigningKey: SelectedSigningKeySchema,
        signingMessage: z.string(),
      }),
    },
    async ({ requestId }: { requestId: GroupRequestId }): Promise<CallToolResult> => {
      const requestRaw = await mgtGET<unknown>("/getNewGroupRequestById", new URLSearchParams({ id: requestId }))
      const request = normalizeGroupRequest(requestRaw, "accept_group_request.request", toMcpApiError)
      if (request.status !== "pending") {
        throw toMcpApiError("Group request is not pending; only pending requests can be agreed", {
          requestId,
          status: request.status,
        })
      }

      const keyOptions = await fetchManagementKeyOptions()
      const selectedSigningKey = await resolveManagementSigningKeyOption(keyOptions)
      const nodeKey = await mgtGET<NodeId>("/getNodeKey")
      const unsignedBody = {
        nodeKey,
        requestId,
        Nonce: selectedSigningKey.nonce,
        Sig: "",
      }
      const signingMessage = buildManagementSigningMessage(unsignedBody)
      const signature = await signManagementMessage(selectedSigningKey, signingMessage)
      const body = { ...unsignedBody, Sig: signature }
      const output = await mgtPOST<string>("/newGroupRequestAgree", body)

      return {
        content: [{ type: "text", text: JSON.stringify({ message: output, selectedSigningKey, signingMessage }) }],
        structuredContent: { message: output, selectedSigningKey, signingMessage },
      }
    },
  )

  server.registerTool(
    "create_group_request",
    {
      description: "Create a new MPC group request from explicit node IDs. Group creation requires unanimous agreement from ALL requested nodes; originator is auto-agreed on creation. Uses preferred signer (or first locally-usable allowed signer). Use list_available_node_ids/list_valid_group_node_sets first; nodeIds must include your node, be from configured nodes, min 2, and not already exist.",
      inputSchema: z.object({
        nodeIds: z.array(NodeIdSchema).min(2),
      }),
      outputSchema: z.object({
        groupRequestId: GroupRequestIdSchema,
        selectedSigningKey: SelectedSigningKeySchema,
        signingMessage: z.string(),
      }),
    },
    async ({
      nodeIds,
    }: {
      nodeIds: NodeId[]
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
      const selectedSigningKey = await resolveManagementSigningKeyOption(keyOptions)
      const unsignedBody = buildNewGroupUnsignedBody(keyList, [], selfNodeId, selectedSigningKey.nonce)
      const signingMessage = buildManagementSigningMessage(unsignedBody)
      const signature = await signManagementMessage(selectedSigningKey, signingMessage)
      const body = { ...unsignedBody, Sig: signature }
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

  server.registerTool(
    "list_group_requests",
    {
      description: "List incoming group creation requests.",
      inputSchema: z.object({
        filter: FilterSchema.optional(),
        pagenum: z.number().int().nonnegative().optional(),
        pagesize: z.number().int().positive().optional(),
      }),
      outputSchema: z.object({
        localNodeId: NodeIdSchema,
        requests: z.array(GroupRequestSchema),
        agreementChecks: z.array(z.object({
          requestId: GroupRequestIdSchema,
          originator: NodeIdSchema,
          isOriginatorLocal: z.boolean(),
          agreementRequired: z.boolean(),
          note: z.string(),
        })),
      }),
    },
    async ({ filter, pagenum, pagesize }: { filter?: Filter; pagenum?: number; pagesize?: number }): Promise<CallToolResult> => {
      const params = new URLSearchParams()
      if (filter !== undefined) {
        params.append("filter", filter)
      }
      if (pagenum !== undefined) {
        params.append("pagenum", pagenum.toString())
      }
      if (pagesize !== undefined) {
        params.append("pagesize", pagesize.toString())
      }

      const rawRequests = await mgtGET<unknown[]>("/listNewGroupRequests", params)
      const requests = rawRequests.map((item, idx) => normalizeGroupRequest(item, `list_group_requests[${idx}]`, toMcpApiError))
      const localNodeId = await mgtGET<NodeId>("/getNodeKey")
      const agreementChecks = requests.map((request) => {
        const isOriginatorLocal = request.originator === localNodeId
        return {
          requestId: request.RequestId,
          originator: request.originator,
          isOriginatorLocal,
          agreementRequired: !isOriginatorLocal,
          note: isOriginatorLocal
            ? "Originator is local node; agreement is not required."
            : "Originator is a different node; agreement is required.",
        }
      })
      return {
        content: [{ type: "text", text: JSON.stringify({ localNodeId, requests, agreementChecks }) }],
        structuredContent: { localNodeId, requests, agreementChecks },
      }
    },
  )

  server.registerTool(
    "list_group_results",
    {
      description: "List group creation results.",
      inputSchema: z.object({
        filter: FilterSchema.optional(),
        pagenum: z.number().int().nonnegative().optional(),
        pagesize: z.number().int().positive().optional(),
      }),
      outputSchema: z.object({ results: z.array(GroupResultSchema) }),
    },
    async ({ filter, pagenum, pagesize }: { filter?: Filter; pagenum?: number; pagesize?: number }): Promise<CallToolResult> => {
      const params = new URLSearchParams()
      if (filter !== undefined) {
        params.append("filter", filter)
      }
      if (pagenum !== undefined) {
        params.append("pagenum", pagenum.toString())
      }
      if (pagesize !== undefined) {
        params.append("pagesize", pagesize.toString())
      }

      const results = await fetchGroupResultsList(mgtGET, params, toMcpApiError)
      return {
        content: [{ type: "text", text: JSON.stringify({ results }) }],
        structuredContent: { results },
      }
    },
  )

  server.registerTool(
    "get_group_request_by_id",
    {
      description: "Get a specific group request by request ID.",
      inputSchema: z.object({
        id: GroupRequestIdSchema,
      }),
      outputSchema: z.object({
        request: GroupRequestSchema,
        localNodeId: NodeIdSchema,
        isOriginatorLocal: z.boolean(),
        agreementRequired: z.boolean(),
        note: z.string(),
      }),
    },
    async ({ id }: { id: GroupRequestId }): Promise<CallToolResult> => {
      const params = new URLSearchParams()
      params.append("id", id)
      const rawOutput = await mgtGET<unknown>("/getNewGroupRequestById", params)
      const request = normalizeGroupRequest(rawOutput, "get_group_request_by_id", toMcpApiError)
      const localNodeId = await mgtGET<NodeId>("/getNodeKey")
      const isOriginatorLocal = request.originator === localNodeId
      const output = {
        request,
        localNodeId,
        isOriginatorLocal,
        agreementRequired: !isOriginatorLocal,
        note: isOriginatorLocal
          ? "Originator is local node; agreement is not required."
          : "Originator is a different node; agreement is required.",
      }
      return {
        content: [{ type: "text", text: JSON.stringify(output) }],
        structuredContent: output,
      }
    },
  )

  server.registerTool(
    "get_group_result_by_id",
    {
      description: "Get a specific group result by request ID or group ID.",
      inputSchema: z.object({
        id: GroupRequestIdSchema.optional(),
        group_id: GroupIdSchema.optional(),
      }),
      outputSchema: GroupResultSchema,
    },
    async ({ id, group_id }: { id?: GroupRequestId; group_id?: GroupId }): Promise<CallToolResult> => {
      if ((id === undefined && group_id === undefined) || (id !== undefined && group_id !== undefined)) {
        throw toMcpApiError("Provide exactly one of id or group_id", { id, group_id })
      }
      const params = new URLSearchParams()
      if (id !== undefined) {
        params.append("id", id)
      } else if (group_id !== undefined) {
        params.append("group_id", group_id)
      }

      const raw = await mgtGET<unknown>("/getNewGroupResultById", params)
      const output = normalizeGroupResult(raw, "get_group_result_by_id", toMcpApiError)
      return {
        content: [{ type: "text", text: JSON.stringify(output) }],
        structuredContent: output,
      }
    },
  )
}

function buildNewGroupUnsignedBody(keyList: NodeId[], brokerArray: string[], nodeKey: NodeId, nonce: Nonce): {
  nodeKey: NodeId
  Nonce: Nonce
  Sig: ""
  keyList: NodeId[]
  BrokerArray: string[]
} {
  return {
    nodeKey,
    Nonce: nonce,
    Sig: "",
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

async function fetchGroupResultsList(
  mgtGET: <T>(path: string, params?: string | URLSearchParams | QueryParams, target?: RequestTarget) => Promise<T>,
  params: URLSearchParams,
  toMcpApiError: (message: string, data?: unknown) => Error,
): Promise<GroupResult[]> {
  // Newer API/doc route.
  try {
    const data = await mgtGET<unknown[]>("/listNewGroupResults", params)
    if (Array.isArray(data)) {
      return data.map((item, idx) => normalizeGroupResult(item, `list_group_results.new[${idx}]`, toMcpApiError))
    }
  } catch {
    // Fall through to legacy/group-discovery route.
  }

  // Fallback route seen on some nodes: /listGroupResults -> { groups: [{ groupId, nodeKeys }] }
  const fallback = await mgtGET<unknown>("/listGroupResults", params)
  const groups = extractGroupsArray(fallback)
  return groups.map((g, idx) => normalizeLegacyGroupListEntry(g, `list_group_results.legacy[${idx}]`, toMcpApiError))
}

function extractGroupsArray(payload: unknown): unknown[] {
  if (!payload || typeof payload !== "object") {
    return []
  }
  const obj = payload as Record<string, unknown>
  if (Array.isArray(obj.groups)) {
    return obj.groups
  }
  if (Array.isArray(obj.results)) {
    return obj.results
  }
  return []
}

function normalizeLegacyGroupListEntry(
  value: unknown,
  context: string,
  toMcpApiError: (message: string, data?: unknown) => Error,
): GroupResult {
  if (!value || typeof value !== "object") {
    throw toMcpApiError("Legacy group result item is not an object", { context, value })
  }
  const src = value as Record<string, unknown>
  const groupId = asString(pick(src, ["groupId", "GroupId"]), `${context}.groupId`, toMcpApiError)
  const keyList = asStringArray(pick(src, ["nodeKeys", "KeyList", "keyList"]), `${context}.nodeKeys`, toMcpApiError)
  return {
    requestid: (`legacy_${groupId}` as unknown) as GroupRequestId,
    GroupId: groupId as GroupId,
    KeyList: keyList as NodeId[],
    Addresses: [],
    SigList: {},
    BrokerArray: [],
    timepoint: "",
  }
}

function normalizeGroupResult(
  value: unknown,
  context: string,
  toMcpApiError: (message: string, data?: unknown) => Error,
): GroupResult {
  if (!value || typeof value !== "object") {
    throw toMcpApiError("Group result response item is not an object", { context, value })
  }
  const src = value as Record<string, unknown>
  return {
    requestid: asString(pick(src, ["requestid", "RequestId", "id"]), `${context}.requestid`, toMcpApiError) as GroupRequestId,
    GroupId: asString(pick(src, ["GroupId", "groupId"]), `${context}.GroupId`, toMcpApiError) as GroupId,
    KeyList: asStringArray(pick(src, ["KeyList", "keyList"]), `${context}.KeyList`, toMcpApiError) as NodeId[],
    Addresses: asStringArrayOptional(pick(src, ["Addresses", "addresses"]), `${context}.Addresses`, toMcpApiError),
    SigList: asRecordOptional(pick(src, ["SigList", "sigList"]), `${context}.SigList`, toMcpApiError) as Record<NodeId, Sig>,
    BrokerArray: asStringArrayOptional(pick(src, ["BrokerArray", "brokerArray"]), `${context}.BrokerArray`, toMcpApiError),
    timepoint: asString(pick(src, ["timepoint", "Timepoint"]), `${context}.timepoint`, toMcpApiError),
    originator: asOptionalString(pick(src, ["originator", "Originator"])) as NodeId | undefined,
  }
}

function normalizeGroupRequest(
  value: unknown,
  context: string,
  toMcpApiError: (message: string, data?: unknown) => Error,
): GroupRequest {
  if (!value || typeof value !== "object") {
    throw toMcpApiError("Group request response item is not an object", { context, value })
  }
  const src = value as Record<string, unknown>
  const dataRaw = pick(src, ["NewGroupDataPb", "newGroupDataPb", "newgroupdatapb", "data", "newGroupData"])
  const data = dataRaw && typeof dataRaw === "object"
    ? (dataRaw as Record<string, unknown>)
    : hasAny(src, ["GroupId", "groupId", "KeyList", "keyList", "SigList", "sigList"])
      ? src
      : undefined

  if (!data) {
    throw toMcpApiError("Group request missing NewGroupDataPb payload", { context, keys: Object.keys(src) })
  }

  const normalized: GroupRequest = {
    RequestId: asString(pick(src, ["RequestId", "requestid", "id"]), `${context}.RequestId`, toMcpApiError) as GroupRequestId,
    NewGroupDataPb: {
      GroupId: asString(pick(data, ["GroupId", "groupId"]), `${context}.NewGroupDataPb.GroupId`, toMcpApiError),
      KeyList: asStringArray(pick(data, ["KeyList", "keyList"]), `${context}.NewGroupDataPb.KeyList`, toMcpApiError),
      Addresses: asStringArrayOptional(pick(data, ["Addresses", "addresses"]), `${context}.NewGroupDataPb.Addresses`, toMcpApiError),
      SigList: asRecordOptional(pick(data, ["SigList", "sigList"]), `${context}.NewGroupDataPb.SigList`, toMcpApiError) as Record<NodeId, Sig>,
      BrokerArray: asStringArrayOptional(pick(data, ["BrokerArray", "brokerArray"]), `${context}.NewGroupDataPb.BrokerArray`, toMcpApiError),
    },
    Timepoint: asString(pick(src, ["Timepoint", "timepoint"]), `${context}.Timepoint`, toMcpApiError),
    status: asString(pick(src, ["status"]), `${context}.status`, toMcpApiError) as GroupRequest["status"],
    originator: asString(pick(src, ["originator", "Originator"]), `${context}.originator`, toMcpApiError) as NodeId,
  }

  return normalized
}

function pick(obj: Record<string, unknown>, keys: string[]): unknown {
  for (const k of keys) {
    if (Object.prototype.hasOwnProperty.call(obj, k)) {
      return obj[k]
    }
  }
  return undefined
}

function hasAny(obj: Record<string, unknown>, keys: string[]): boolean {
  return keys.some((k) => Object.prototype.hasOwnProperty.call(obj, k))
}

function asString(value: unknown, field: string, toMcpApiError: (message: string, data?: unknown) => Error): string {
  if (typeof value !== "string" || value.length === 0) {
    throw toMcpApiError("Expected non-empty string field in group request response", { field, value })
  }
  return value
}

function asStringArray(value: unknown, field: string, toMcpApiError: (message: string, data?: unknown) => Error): string[] {
  if (!Array.isArray(value) || value.some((v) => typeof v !== "string")) {
    throw toMcpApiError("Expected string[] field in group request response", { field, value })
  }
  return value
}

function asRecord(value: unknown, field: string, toMcpApiError: (message: string, data?: unknown) => Error): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw toMcpApiError("Expected object field in group request response", { field, value })
  }
  return value as Record<string, unknown>
}

function asStringArrayOptional(value: unknown, field: string, toMcpApiError: (message: string, data?: unknown) => Error): string[] {
  if (value === undefined || value === null) {
    return []
  }
  return asStringArray(value, field, toMcpApiError)
}

function asRecordOptional(value: unknown, field: string, toMcpApiError: (message: string, data?: unknown) => Error): Record<string, unknown> {
  if (value === undefined || value === null) {
    return {}
  }
  return asRecord(value, field, toMcpApiError)
}

function asOptionalString(value: unknown): string | undefined {
  if (value === undefined || value === null || value === "") {
    return undefined
  }
  return typeof value === "string" ? value : undefined
}
