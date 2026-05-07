import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js"
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js"
import { z } from "zod"
import {
  NodeIdSchema,
  PubKeySchema,
  GroupIdSchema,
  MsgCheckSchema,
  KeyTypeSchema,
  KeyGenIdSchema,
  type GroupId,
  type KeyGenId,
  type MsgCheck,
  type Nonce,
  type Sig,
  type Key,
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

type KeyGenToolsDeps = {
  server: McpServer
  mgtGET: <T>(path: string, params?: string | URLSearchParams | QueryParams, target?: RequestTarget) => Promise<T>
  mgtPOST: <T>(path: string, body?: BodyInit | object, params?: string | URLSearchParams | QueryParams) => Promise<T>
  toMcpApiError: (message: string, data?: unknown) => Error
  fetchManagementKeyOptions: () => Promise<ManagementKeyOption[]>
  getManagementKeyOptionByIndex: (keyOptions: ManagementKeyOption[], signerIndex: number) => Promise<ManagementKeyOption>
  buildManagementSigningMessage: (bodyWithEmptySig: Record<string, unknown>) => string
  signManagementMessage: (option: ManagementKeyOption, message: string) => Promise<Sig>
}

const KeyGenRequestSchema = z.object({
  requestid: KeyGenIdSchema,
  GroupId: GroupIdSchema,
  KeyType: KeyTypeSchema,
  MsgCheck: MsgCheckSchema,
  SigList: z.record(NodeIdSchema, z.string()),
  Threshold: z.number().int().nonnegative(),
  timepoint: z.string(),
  status: z.string().optional(),
  originator: NodeIdSchema.optional(),
})

const KeyGenResultSchema = z.object({
  requestid: z.string(),
  pubkeyhex: PubKeySchema.optional(),
  keylist: z.array(NodeIdSchema).optional(),
  groupid: GroupIdSchema.optional(),
  threshold: z.number().int().nonnegative().optional(),
  keytype: KeyTypeSchema.optional(),
  msgcheck: MsgCheckSchema.optional(),
  savedata: z.string().optional(),
  timepoint: z.string(),
  status: z.string().optional(),
})

export function registerKeyGenTools(deps: KeyGenToolsDeps): void {
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
    "create_mpc_keygen_request",
    {
      description: "Initiate a request to members of a given Group ID to generate a new MPC key pair.",
      inputSchema: z.object({
        groupId: GroupIdSchema,
        threshold: z.number().int().nonnegative(),
        msgCheck: MsgCheckSchema,
        keyType: KeyTypeSchema,
        signerIndex: z.number().int().nonnegative(),
      }),
      outputSchema: z.object({
        requestId: KeyGenIdSchema,
        selectedSigningKey: z.object({
          id: z.string(),
          kind: z.literal("EdDSA"),
          value: z.string(),
          nonce: z.number().int().nonnegative(),
          label: z.string().optional(),
        }),
        signingMessage: z.string(),
      }),
    },
    async ({
      groupId,
      threshold,
      msgCheck,
      keyType,
      signerIndex,
    }: {
      groupId: GroupId
      threshold: number
      msgCheck: MsgCheck
      keyType: Key
      signerIndex: number
    }): Promise<CallToolResult> => {
      const keyOptions = await fetchManagementKeyOptions()
      const selectedSigningKey = await getManagementKeyOptionByIndex(keyOptions, signerIndex)
      const unsignedBody = {
        nonce: selectedSigningKey.nonce,
        sig: "",
        clientPk: selectedSigningKey.value,
        threshold,
        groupId,
        msgCheck,
        keyType,
      }
      const signingMessage = buildManagementSigningMessage(unsignedBody)
      const signature = await signManagementMessage(selectedSigningKey, signingMessage)
      const body = { ...unsignedBody, sig: signature }
      const requestId = await mgtPOST<KeyGenId>("/keyGenRequest", body)
      return {
        content: [{ type: "text", text: JSON.stringify({ requestId, selectedSigningKey, signingMessage }) }],
        structuredContent: { requestId, selectedSigningKey, signingMessage },
      }
    },
  )

  server.registerTool(
    "accept_mpc_keygen_request",
    {
      description: "Accept a request from another member of a common Group ID to generate a new MPC key pair.",
      inputSchema: z.object({
        requestId: KeyGenIdSchema,
        signerIndex: z.number().int().nonnegative(),
      }),
      outputSchema: z.object({
        message: z.string(),
        selectedSigningKey: z.object({
          id: z.string(),
          kind: z.literal("EdDSA"),
          value: z.string(),
          nonce: z.number().int().nonnegative(),
          label: z.string().optional(),
        }),
        signingMessage: z.string(),
      }),
    },
    async ({ requestId, signerIndex }: { requestId: KeyGenId; signerIndex: number }): Promise<CallToolResult> => {
      const request = await mgtGET<unknown>("/getKeyGenRequestById", new URLSearchParams({ id: requestId }))
      const status = extractStatus(request)
      if (status && status !== "pending") {
        throw toMcpApiError("KeyGen request is not pending; only pending requests can be agreed", { requestId, status })
      }

      const keyOptions = await fetchManagementKeyOptions()
      const selectedSigningKey = await getManagementKeyOptionByIndex(keyOptions, signerIndex)
      const unsignedBody = {
        nonce: selectedSigningKey.nonce,
        sig: "",
        requestId,
      }
      const signingMessage = buildManagementSigningMessage(unsignedBody)
      const signature = await signManagementMessage(selectedSigningKey, signingMessage)
      const body = { ...unsignedBody, sig: signature }
      const message = await mgtPOST<string>("/keyGenRequestAgree", body)
      return {
        content: [{ type: "text", text: JSON.stringify({ message, selectedSigningKey, signingMessage }) }],
        structuredContent: { message, selectedSigningKey, signingMessage },
      }
    },
  )

  server.registerTool(
    "list_mpc_keygen_requests",
    {
      description: "List MPC key generation requests with optional filter and pagination.",
      inputSchema: z.object({
        filter: z.enum(["all", "pending", "success", "failed", "agree", "originator"]).optional(),
        pagenum: z.number().int().nonnegative().optional(),
        pagesize: z.number().int().positive().optional(),
      }),
      outputSchema: z.object({ requests: z.array(KeyGenRequestSchema) }),
    },
    async ({
      filter,
      pagenum,
      pagesize,
    }: {
      filter?: "all" | "pending" | "success" | "failed" | "agree" | "originator"
      pagenum?: number
      pagesize?: number
    }): Promise<CallToolResult> => {
      const params = new URLSearchParams()
      if (filter !== undefined) {
        params.append("filter", filter)
      }
      if (pagenum !== undefined) {
        params.append("pagenum", String(pagenum))
      }
      if (pagesize !== undefined) {
        params.append("pagesize", String(pagesize))
      }
      const raw = await mgtGET<unknown[]>("/listKeyGenRequests", params)
      const requests = (Array.isArray(raw) ? raw : []).map((x, i) =>
        normalizeKeyGenRequest(x, `list_keygen_requests[${i}]`, toMcpApiError),
      )
      return {
        content: [{ type: "text", text: JSON.stringify({ requests }) }],
        structuredContent: { requests },
      }
    },
  )

  server.registerTool(
    "get_mpc_keygen_request_by_id",
    {
      description: "Get MPC key generation request by request ID.",
      inputSchema: z.object({ id: KeyGenIdSchema }),
      outputSchema: KeyGenRequestSchema,
    },
    async ({ id }: { id: KeyGenId }): Promise<CallToolResult> => {
      const raw = await mgtGET<unknown>("/getKeyGenRequestById", new URLSearchParams({ id }))
      const output = normalizeKeyGenRequest(raw, "get_keygen_request_by_id", toMcpApiError)
      return {
        content: [{ type: "text", text: JSON.stringify(output) }],
        structuredContent: output,
      }
    },
  )

  server.registerTool(
    "get_mpc_keygen_result_by_id",
    {
      description: "Get MPC key generation result by request ID.",
      inputSchema: z.object({ id: KeyGenIdSchema }),
      outputSchema: KeyGenResultSchema,
    },
    async ({ id }: { id: KeyGenId }): Promise<CallToolResult> => {
      const raw = await mgtGET<unknown>("/getKeyGenResultById", new URLSearchParams({ id }))
      const output = normalizeKeyGenResult(raw, "get_keygen_result_by_id", toMcpApiError)
      return {
        content: [{ type: "text", text: JSON.stringify(output) }],
        structuredContent: output,
      }
    },
  )

  server.registerTool(
    "get_mpc_keygen_parent_group_id",
    {
      description: "Get the parent group ID that a generated MPC key pair belongs to.",
      inputSchema: z.object({ id: KeyGenIdSchema }),
      outputSchema: z.object({
        requestid: z.string(),
        groupId: GroupIdSchema,
      }),
    },
    async ({ id }: { id: KeyGenId }): Promise<CallToolResult> => {
      const raw = await mgtGET<unknown>("/getKeyGenGroupId", new URLSearchParams({ id }))
      if (!raw || typeof raw !== "object") {
        throw toMcpApiError("Invalid getKeyGenGroupId response shape", { id, raw })
      }
      const src = raw as Record<string, unknown>
      const output = {
        requestid: asString(
          pick(src, ["requestid", "RequestId", "id"]),
          "get_mpc_keygen_parent_group_id.requestid",
          toMcpApiError,
        ),
        groupId: asString(
          pick(src, ["groupid", "GroupId", "groupId"]),
          "get_mpc_keygen_parent_group_id.groupId",
          toMcpApiError,
        ) as GroupId,
      }
      return {
        content: [{ type: "text", text: JSON.stringify(output) }],
        structuredContent: output,
      }
    },
  )

  server.registerTool(
    "get_mpc_keygen_nonce",
    {
      description: "Get the global nonce of an existing MPC KeyGen. If the key type is not secp256k1 (i.e. ed25519), then returns 0",
      inputSchema: z.object({ id: KeyGenIdSchema }),
      outputSchema: z.object({ globalNonce: z.number() }),
    },
    async ({ id }: { id: KeyGenId }): Promise<CallToolResult> => {
      const raw = await mgtGET<unknown>("/getGlobalNonceByKeyGenId", new URLSearchParams({ id }))
      let globalNonce: number | undefined
      if (typeof raw === "number") {
        globalNonce = raw
      } else if (raw && typeof raw === "object") {
        const src = raw as Record<string, unknown>
        const candidate = pick(src, ["globalNonce", "GlobalNonce", "nonce"])
        if (typeof candidate === "number") {
          globalNonce = candidate
        }
      }
      if (typeof globalNonce !== "number" || Number.isNaN(globalNonce)) {
        throw toMcpApiError("Invalid getGlobalNonceByKeyGenId response shape", { id, raw })
      }
      const output = { globalNonce }
      return {
        content: [{ type: "text", text: JSON.stringify(output) }],
        structuredContent: output,
      }
    },
  )
}

function extractStatus(payload: unknown): string | undefined {
  if (!payload || typeof payload !== "object") {
    return undefined
  }
  const src = payload as Record<string, unknown>
  const status = src.status
  return typeof status === "string" ? status : undefined
}

function normalizeKeyGenRequest(
  value: unknown,
  context: string,
  toMcpApiError: (message: string, data?: unknown) => Error,
): z.infer<typeof KeyGenRequestSchema> {
  if (!value || typeof value !== "object") {
    throw toMcpApiError("KeyGen request response item is not an object", { context, value })
  }
  const src = value as Record<string, unknown>
  return {
    requestid: asString(pick(src, ["requestid", "RequestId", "id"]), `${context}.requestid`, toMcpApiError) as KeyGenId,
    GroupId: asString(pick(src, ["GroupId", "groupId"]), `${context}.GroupId`, toMcpApiError) as GroupId,
    KeyType: asString(pick(src, ["KeyType", "keyType"]), `${context}.KeyType`, toMcpApiError) as Key,
    MsgCheck: asString(pick(src, ["MsgCheck", "msgCheck"]), `${context}.MsgCheck`, toMcpApiError) as MsgCheck,
    SigList: asRecordOptional(pick(src, ["SigList", "sigList"])) as Record<string, string>,
    Threshold: asNumber(pick(src, ["Threshold", "threshold"]), `${context}.Threshold`, toMcpApiError),
    timepoint: asString(pick(src, ["timepoint", "Timepoint"]), `${context}.timepoint`, toMcpApiError),
    status: asOptionalString(pick(src, ["status"])),
    originator: asOptionalString(pick(src, ["originator", "Originator"])) as z.infer<typeof NodeIdSchema> | undefined,
  }
}

function normalizeKeyGenResult(
  value: unknown,
  context: string,
  toMcpApiError: (message: string, data?: unknown) => Error,
): z.infer<typeof KeyGenResultSchema> {
  if (!value || typeof value !== "object") {
    throw toMcpApiError("KeyGen result response item is not an object", { context, value })
  }
  const src = value as Record<string, unknown>
  return {
    requestid: asString(pick(src, ["requestid", "RequestId", "id"]), `${context}.requestid`, toMcpApiError),
    pubkeyhex: asOptionalString(pick(src, ["pubkeyhex", "PubKeyHex"])) as z.infer<typeof PubKeySchema> | undefined,
    keylist: asOptionalStringArray(pick(src, ["keylist", "KeyList"])) as z.infer<typeof NodeIdSchema>[] | undefined,
    groupid: asOptionalString(pick(src, ["groupid", "GroupId"])) as GroupId | undefined,
    threshold: asOptionalNumber(pick(src, ["threshold", "Threshold"])),
    keytype: asOptionalString(pick(src, ["keytype", "KeyType"])) as Key | undefined,
    msgcheck: asOptionalString(pick(src, ["msgcheck", "MsgCheck"])) as MsgCheck | undefined,
    savedata: asOptionalString(pick(src, ["savedata", "SaveData"])),
    timepoint: asString(pick(src, ["timepoint", "Timepoint"]), `${context}.timepoint`, toMcpApiError),
    status: asOptionalString(pick(src, ["status"])),
  }
}

function pick(obj: Record<string, unknown>, keys: string[]): unknown {
  for (const k of keys) {
    if (Object.prototype.hasOwnProperty.call(obj, k)) {
      return obj[k]
    }
  }
  return undefined
}

function asString(value: unknown, field: string, toMcpApiError: (message: string, data?: unknown) => Error): string {
  if (typeof value !== "string" || value.length === 0) {
    throw toMcpApiError("Expected non-empty string field", { field, value })
  }
  return value
}

function asOptionalString(value: unknown): string | undefined {
  if (value === undefined || value === null || value === "") {
    return undefined
  }
  return typeof value === "string" ? value : undefined
}

function asOptionalStringArray(value: unknown): string[] | undefined {
  if (value === undefined || value === null) {
    return undefined
  }
  if (!Array.isArray(value) || value.some((v) => typeof v !== "string")) {
    return undefined
  }
  return value
}

function asRecordOptional(value: unknown): Record<string, string> {
  if (value === undefined || value === null || typeof value !== "object" || Array.isArray(value)) {
    return {}
  }
  const src = value as Record<string, unknown>
  const out: Record<string, string> = {}
  for (const [k, v] of Object.entries(src)) {
    if (typeof v === "string") {
      out[k] = v
    }
  }
  return out
}

function asNumber(value: unknown, field: string, toMcpApiError: (message: string, data?: unknown) => Error): number {
  if (typeof value !== "number" || Number.isNaN(value)) {
    throw toMcpApiError("Expected numeric field", { field, value })
  }
  return value
}

function asOptionalNumber(value: unknown): number | undefined {
  if (typeof value !== "number" || Number.isNaN(value)) {
    return undefined
  }
  return value
}
