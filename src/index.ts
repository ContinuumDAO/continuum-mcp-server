import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js"
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js"
import { ErrorCode, McpError, CallToolResult } from "@modelcontextprotocol/sdk/types.js"
import { z } from "zod"
import { promises as fs } from "fs"
import {
  normalizeEd25519PublicKeyToHex as normalizeEd25519PublicKeyToHexBase,
  listLocalManagementPublicKeys as listLocalManagementPublicKeysBase,
  getManagementKeyOptionByIndex as getManagementKeyOptionByIndexBase,
  buildManagementSigningMessage as buildManagementSigningMessageBase,
  signManagementMessage as signManagementMessageBase,
  getPrivateKeyStatus as getPrivateKeyStatusBase,
  assertAgentCanSignManagementRequests as assertAgentCanSignManagementRequestsBase,
  type LocalManagementKeyEntry,
} from "./ed25519/management-signing.js"
import {
  KeyTypeSchema,
  MsgCheckSchema,
  FilterSchema,
  StatusSchema,
  ECDSAPubKeySchema,
  ECDSAAddressSchema,
  ECDSASigSchema,
  EdDSAPubKeySchema,
  EdDSASigSchema,
  PubKeySchema,
  NodeIdSchema,
  GroupIdSchema,
  NonceSchema,
  ManagementSigSchema,
  GroupRequestIdSchema,
  KeyGenIdSchema,
  LogsSchema,
  MessageToSignResponseSchema,
  MqttKeySchema,
  ConfigUpdatePlanResponseSchema,
  ConfigUpdateImplementResponseSchema,
  MachineInfoSchema,
  GroupRequestSchema,
  GroupResultSchema,
  GroupSchema,
  SubscriptionSchema,
  NodeConnectivityResultSchema,
  ConfiguredNodeSchema,
  type Key,
  type MsgCheck,
  type Filter,
  type Status,
  type Logs,
  type MachineInfo,
  type GroupRequest,
  type GroupResult,
  type ECDSAPubKey,
  type ECDSAAddress,
  type ECDSASig,
  type EdDSAPubKey,
  type EdDSASig,
  type NodeId,
  type GroupId,
  type Nonce,
  type Sig,
  type GroupRequestId,
  type KeyGenId,
  type Subscription,
  type NodeConnectivityResult,
  type ConfiguredNode,
  type MessageToSignResponse,
  type MqttKey,
  type ConfigUpdatePlanResponse,
  type ConfigUpdateImplementResponse,
} from "./types.js"
import { registerGroupTools } from "./group.js"
import { registerSigningTools } from "./signing.js"
import { registerNodeTools } from "./node.js"
import { registerKeyTools } from "./management_keys.js"
import { registerKeyGenTools } from "./keygen.js"
import path from "path"
import os from "os"

// Create server instance
const server = new McpServer({
  name: "continuum-mcp",
  version: "1.0.0",
}, {
  capabilities: {
    tools: {
      listChanged: true,
    },
  },
})

const MPC_AUTH_URL = "http://localhost"
const MPC_AUTH_PORT = "8080"
const KEY_ROOT = process.env.KEY_ROOT ?? path.join(os.homedir(), ".mpa")
const DOCS_ROOT = path.join(process.cwd(), "resources")

type ManagementKeyOption = {
  id: string
  kind: "EdDSA"
  value: string
  nonce: Nonce
  label?: string
}

function registerMarkdownResource(name: string, filename: string, description: string): void {
  const uri = `docs://${filename}`
  server.registerResource(
    name,
    uri,
    { description, mimeType: "text/markdown" },
    async () => {
      const filePath = path.join(DOCS_ROOT, filename)
      const text = await fs.readFile(filePath, "utf8")
      return {
        contents: [
          {
            uri,
            mimeType: "text/markdown",
            text,
          },
        ],
      }
    },
  )
}

registerMarkdownResource("overview_docs", "overview.md", "High-level MCP host overview for this server.")
registerMarkdownResource("group_docs", "group.md", "Group creation flow and validation rules.")
registerMarkdownResource("sign_docs", "sign.md", "Modular signing flow and reusable signing tools.")
registerMarkdownResource("management_keys_docs", "management_keys.md", "How to create and add EdDSA management keys.")
registerMarkdownResource("keygen_docs", "keygen.md", "Key generation request, acceptance, and result flow.")

function normalizeEd25519PublicKeyToHex(value: string): string {
  return normalizeEd25519PublicKeyToHexBase(value, toMcpApiError)
}

async function listLocalManagementPublicKeys(): Promise<LocalManagementKeyEntry[]> {
  return listLocalManagementPublicKeysBase(KEY_ROOT, toMcpApiError)
}

async function getManagementKeyOptionByIndex(keyOptions: ManagementKeyOption[], signerIndex: number): Promise<ManagementKeyOption> {
  return getManagementKeyOptionByIndexBase(
    keyOptions,
    signerIndex,
    { keyRoot: KEY_ROOT, toMcpApiError },
  ) as Promise<ManagementKeyOption>
}

function buildManagementSigningMessage(bodyWithEmptySig: Record<string, unknown>): string {
  return buildManagementSigningMessageBase(bodyWithEmptySig)
}

async function signManagementMessage(option: ManagementKeyOption, message: string): Promise<Sig> {
  return signManagementMessageBase(
    option,
    message,
    {
      keyRoot: KEY_ROOT,
      toMcpApiError,
      assertAgentCanSignManagementRequests,
    },
  ) as Promise<Sig>
}

async function getPrivateKeyStatus(option: ManagementKeyOption): Promise<{ available: boolean; reason?: string }> {
  return getPrivateKeyStatusBase(option, { keyRoot: KEY_ROOT, toMcpApiError })
}

async function assertAgentCanSignManagementRequests(): Promise<void> {
  await assertAgentCanSignManagementRequestsBase({
    keyRoot: KEY_ROOT,
    mgtGET,
    toMcpApiError,
  })
}

async function fetchManagementKeyOptions(): Promise<ManagementKeyOption[]> {
  const eddsaKeys = await mgtGET<Array<{ publicKey: EdDSAPubKey; label: string }>>("/getAllowedEd25519MgtKeys")
  const eddsaWithNonces = await Promise.all(
    eddsaKeys.map(async (item) => {
      const nonceInfo = await mgtGET<{ key: EdDSAPubKey; nonce: Nonce }>("/getPublicMgtKeyNonce", {
        publicKey: item.publicKey,
      })
      return {
        ...item,
        nonce: nonceInfo.nonce,
      }
    }),
  )

  return eddsaWithNonces.map((item) => ({
      id: `eddsa:${item.publicKey}`,
      kind: "EdDSA",
      value: item.publicKey,
      nonce: item.nonce,
      label: item.label,
    }))
}


// ISSUE: This will be revisited when pre-signing is incorporated fully
// // 0.15 /getPreSigningVerificationStatus
// server.registerTool(
//   "get_presigning_verification_status",
//   {
//     description: "Get pre-signing verification status and mode",
//     outputSchema: z.object({
//       enabled: z.boolean(),
//       relayerAPIURL: z.string(),
//       verificationMode: z.string(),
//     }),
//   },
//   async (): Promise<CallToolResult> => {
//     const output = await mgtGET<{
//       enabled: boolean
//       relayerAPIURL: string
//       verificationMode: string
//     }>("/getPreSigningVerificationStatus")
//     return {
//       content: [{ type: "text", text: JSON.stringify(output) }],
//       structuredContent: output,
//     }
//   },
// )

// WARN: this should always be false in production !!
// // 0.16 /getClientSigStatus
// server.registerTool(
//   "get_client_sig_status",
//   {
//     description: "Get whether client signature verification is ignored",
//     outputSchema: z.object({ ignoreClientSigCheck: z.boolean() }),
//   },
//   async (): Promise<CallToolResult> => {
//     const output = await mgtGET<{ ignoreClientSigCheck: boolean }>("/getClientSigStatus")
//     return {
//       content: [{ type: "text", text: JSON.stringify(output) }],
//       structuredContent: output,
//     }
//   },
// )


// // 0.18 /getMSQTTKey
// server.registerTool(
//   "get_mqtt_key",
//   {
//     description: "Get MQTT broker CA certificate PEM and resolved path",
//     outputSchema: MqttKeySchema,
//   },
//   async (): Promise<CallToolResult> => {
//     const output = await mgtGET<MqttKey>("/getMSQTTKey")
//     return {
//       content: [{ type: "text", text: JSON.stringify(output) }],
//       structuredContent: output,
//     }
//   },
// )

// // 0.19 /postMSQTTKey
// server.registerTool(
//   "post_mqtt_key",
//   {
//     description: "Write MQTT broker CA certificate PEM using management-key signature",
//     inputSchema: z.object({
//       nonce: NonceSchema,
//       caCertPem: z.string(),
//       signedMessage: z.string(),
//       clientSig: ManagementSigSchema,
//     }),
//     outputSchema: z.object({
//       path: z.string(),
//       message: z.string(),
//     }),
//   },
//   async ({
//     nonce,
//     caCertPem,
//     signedMessage,
//     clientSig,
//   }: {
//     nonce: Nonce
//     caCertPem: string
//     signedMessage: string
//     clientSig: Sig
//   }): Promise<CallToolResult> => {
//     const body = { nonce, caCertPem, signedMessage, clientSig }
//     const output = await mgtPOST<{ path: string; message: string }>("/postMSQTTKey", body)
//     return {
//       content: [{ type: "text", text: JSON.stringify(output) }],
//       structuredContent: output,
//     }
//   },
// )

// // 0.20 /configUpdatePlan
// server.registerTool(
//   "config_update_plan",
//   {
//     description: "Plan staged configs.yaml update and return planned YAML plus verification digest",
//     inputSchema: z.object({
//       nonce: NonceSchema,
//       sig: ManagementSigSchema,
//       nodeMgtKey: ECDSAAddressSchema.optional(),
//       publicMgtKey: z.union([
//         EdDSAPubKeySchema,
//         z.string().regex(/^ssh-ed25519\s+\S+.*$/, "ssh-ed25519 public key line expected"),
//       ]).optional(),
//       MSQTTRelayIP: z.string().optional(),
//       nodeAddresses: z.array(z.string()).optional(),
//       managementHttpPort: z.number().int().positive().optional(),
//     }),
//     outputSchema: ConfigUpdatePlanResponseSchema,
//   },
//   async ({
//     nonce,
//     sig,
//     nodeMgtKey,
//     publicMgtKey,
//     MSQTTRelayIP,
//     nodeAddresses,
//     managementHttpPort,
//   }: {
//     nonce: Nonce
//     sig: Sig
//     nodeMgtKey?: ECDSAAddress
//     publicMgtKey?: string
//     MSQTTRelayIP?: string
//     nodeAddresses?: string[]
//     managementHttpPort?: number
//   }): Promise<CallToolResult> => {
//     const body = {
//       nonce,
//       sig,
//       nodeMgtKey,
//       publicMgtKey,
//       MSQTTRelayIP,
//       nodeAddresses,
//       managementHttpPort,
//     }
//     const output = await mgtPOST<ConfigUpdatePlanResponse>("/configUpdatePlan", body)
//     return {
//       content: [{ type: "text", text: JSON.stringify(output) }],
//       structuredContent: output,
//     }
//   },
// )
// 
// // 0.21 /configUpdateImplement
// server.registerTool(
//   "config_update_implement",
//   {
//     description: "Apply a planned configs.yaml update using plannedShaMessage-bound signatures",
//     inputSchema: z.object({
//       plannedYaml: z.string(),
//       nonce: NonceSchema,
//       clientSig: ManagementSigSchema,
//       signedMessage: z.string(),
//       rotationNodeMgtKeyClientSig: ECDSASigSchema.optional(),
//       rotationPublicMgtKeyClientSig: EdDSASigSchema.optional(),
//     }),
//     outputSchema: ConfigUpdateImplementResponseSchema,
//   },
//   async ({
//     plannedYaml,
//     nonce,
//     clientSig,
//     signedMessage,
//     rotationNodeMgtKeyClientSig,
//     rotationPublicMgtKeyClientSig,
//   }: {
//     plannedYaml: string
//     nonce: Nonce
//     clientSig: Sig
//     signedMessage: string
//     rotationNodeMgtKeyClientSig?: ECDSASig
//     rotationPublicMgtKeyClientSig?: EdDSASig
//   }): Promise<CallToolResult> => {
//     const body = {
//       plannedYaml,
//       nonce,
//       clientSig,
//       signedMessage,
//       rotationNodeMgtKeyClientSig,
//       rotationPublicMgtKeyClientSig,
//     }
//     const output = await mgtPOST<ConfigUpdateImplementResponse>("/configUpdateImplement", body)
//     return {
//       content: [{ type: "text", text: JSON.stringify(output) }],
//       structuredContent: output,
//     }
//   },
// )
// 

// Category 1: Group Management
registerNodeTools({
  server,
  mgtGET,
})
registerKeyTools({
  server,
  keyRoot: KEY_ROOT,
  mgtGET,
  mgtPOST,
  toMcpApiError,
  assertAgentCanSignManagementRequests,
  normalizeEd25519PublicKeyToHex,
  fetchManagementKeyOptions,
  getManagementKeyOptionByIndex,
  buildManagementSigningMessage,
  signManagementMessage,
  listLocalManagementPublicKeys,
  getPrivateKeyStatus,
})
registerGroupTools({
  server,
  mgtGET,
  mgtPOST,
  toMcpApiError,
  fetchManagementKeyOptions,
  getManagementKeyOptionByIndex,
  buildManagementSigningMessage,
  signManagementMessage,
})
registerSigningTools({
  server,
  fetchManagementKeyOptions,
  getManagementKeyOptionByIndex,
  buildManagementSigningMessage,
  signManagementMessage,
})
registerKeyGenTools({
  server,
  mgtGET,
  mgtPOST,
  toMcpApiError,
  fetchManagementKeyOptions,
  getManagementKeyOptionByIndex,
  buildManagementSigningMessage,
  signManagementMessage,
})

// 1.1 /newGroupRequest

// // 1.2 /newGroupRequestAgree
// 
// server.registerTool(
//   "accept_group_request",
//   {
//     description: "Accept an incoming Group request",
//     inputSchema: z.object({
//       requestId: GroupRequestIdSchema,
//       nonce: NonceSchema,
//       sig: ManagementSigSchema
//     }),
//     outputSchema: z.object({ message: z.string() })
//   },
//   async ({ requestId, nonce, sig }: { requestId: GroupRequestId, nonce: Nonce, sig: Sig }): Promise<CallToolResult> => {
//     const body = { requestId, nonce, sig }
//     const output = await mgtPOST<string>("newGroupRequestAgree", body)
//     return {
//       content: [{ type: "text", text: JSON.stringify({ message: output }) }],
//       structuredContent: { message: output }
//     }
//   }
// )
// 
// // 1.3 /getAllGroupIds
// 
// server.registerTool(
//   "list_all_groups",
//   {
//     description: "List all formed Groups that the MPC node client is a part of",
//     outputSchema: z.object({
//       groupResults: z.array(GroupResultSchema)
//     })
//   },
//   async (): Promise<CallToolResult> => {
//     const output = await mgtGET<GroupResult[]>("/getAllGroupIds")
//     return {
//       content: [{ type: "text", text: JSON.stringify({ groupResults: output }) }]
//     }
//   }
// )
// 
// // 1.3 /listNewGroupRequests
// 
// server.registerTool(
//   "list_group_requests",
//   {
//     description: "List incoming Group requests",
//     inputSchema: z.object({
//       filter: FilterSchema.optional(),
//       pagenum: z.number().optional(),
//       pagesize: z.number().optional()
//     }),
//     outputSchema: z.object({ requests: z.array(GroupRequestSchema) })
//   },
//   async ({ filter, pagenum, pagesize }: { filter?: Filter, pagenum?: number, pagesize?: number }): Promise<CallToolResult> => {
//     let params = new URLSearchParams()
//     if (filter !== undefined) {
//       params.append("filter", filter)
//     }
//     if (pagenum !== undefined) {
//       params.append("pagenum", pagenum.toString())
//     }
//     if (pagesize !== undefined) {
//       params.append("pagesize", pagesize.toString())
//     }
// 
//     const output = await mgtGET<GroupRequest[]>("/listNewGroupRequests", params)
//     return {
//       content: [{ type: "text", text: JSON.stringify({ requests: output }) }],
//       structuredContent: { requests: output }
//     }
//   }
// )
// 
// // 1.4 /getNewGroupRequestById
// 
// server.registerTool(
//   "get_group_request_by_id",
//   {
//     description: "Gets a specific group request by its request ID",
//     inputSchema: z.object({
//       id: GroupRequestIdSchema
//     }),
//     outputSchema: GroupRequestSchema
//   },
//   async ({ id }: { id: GroupRequestId }): Promise<CallToolResult> => {
//     let params = new URLSearchParams()
//     params.append("id", id)
// 
//     const output = await mgtGET<GroupRequest>("/getNewGroupRequestById", params)
//     return {
//       content: [{ type: "text", text: JSON.stringify(output) }],
//       structuredContent: output
//     }
//   }
// )
// 
// // 1.5 /listNewGroupResults
// 
// server.registerTool(
//   "list_group_results",
//   {
//     description: "List Group results",
//     inputSchema: z.object({
//       filter: FilterSchema.optional(),
//       pagenum: z.number().optional(),
//       pagesize: z.number().optional()
//     }),
//     outputSchema: z.object({ results: z.array(GroupResultSchema) })
//   },
//   async ({ filter, pagenum, pagesize }: { filter?: Filter, pagenum?: number, pagesize?: number }): Promise<CallToolResult> => {
//     let params = new URLSearchParams()
//     if (filter !== undefined) {
//       params.append("filter", filter)
//     }
//     if (pagenum !== undefined) {
//       params.append("pagenum", pagenum.toString())
//     }
//     if (pagesize !== undefined) {
//       params.append("pagesize", pagesize.toString())
//     }
// 
//     const output = await mgtGET<GroupResult[]>("/listNewGroupResults", params)
//     return {
//       content: [{ type: "text", text: JSON.stringify({ results: output }) }],
//       structuredContent: { results: output }
//     }
//   }
// )
// 
// // 1.6 /getNewGroupResultById
// 
// server.registerTool(
//   "get_group_result_by_id",
//   {
//     description: "Gets a specific Group result by its request ID or by its group ID (if it is already created)",
//     inputSchema: z.object({
//       id: GroupRequestIdSchema.optional(),
//       group_id: GroupIdSchema.optional()
//     }),
//     outputSchema: GroupResultSchema
//   },
//   async ({ id, group_id }: { id?: GroupRequestId, group_id?: GroupId }): Promise<CallToolResult> => {
//     let params = new URLSearchParams()
//     if (id !== undefined) {
//       params.append("id", id)
//     } else if (group_id !== undefined) {
//       params.append("group_id", group_id)
//     }
// 
//     const output = await mgtGET<GroupResult>("/getNewGroupResultById", params)
//     return {
//       content: [{ type: "text", text: JSON.stringify(output) }],
//       structuredContent: output
//     }
//   }
// )
// 
// server.registerTool(
//   "sign_ecdsa",
//   {
//     description: "Use the configured ECDSA keypair (aka NodeMgtKey) to sign arbitrary message data",
//     inputSchema: {
//       msg: z.string().describe("The exact body of the input that is intended to be called on a management API route")
//     },
//     outputSchema: {
//       sig: ECDSASigSchema
//     }
//   },
//   async ({ msg }): Promise<CallToolResult> => {
//     const { nodeMgtKey, nonce } = await mgtGET<{ nodeMgtKey: ECDSAAddress, nonce: Nonce }>("/getNodeMgtKeyNonce")
//     const messageRaw = await mgtGET<MessageToSignResponse>("/getMessageToSign", {...JSON.parse(msg)})
//     const signature = await ethers.signTransaction(messageRaw, nodeMgtKey);
//     return {
//       content: [{ type: "text", text: JSON.stringify({sig, description: `ECDSA signature for ${msg}`}) }],
//       structuredContent: sig
//     }
//   }
// )

// Category 2: KeyGens

// Category 3: Signing

// Category 4: Execution

// Category 5: Configuration

async function main() {
  // Let clients refresh tools list immediately after initialization.
  // MCP notification method: "notifications/tools/list_changed"
  server.server.oninitialized = () => {
    void server.server.sendToolListChanged().catch((error) => {
      console.error("Failed to send tools/list_changed notification:", error)
    })
  }

  const transport = new StdioServerTransport()
  await server.connect(transport)
  console.error("Continuum MCP Server running on stdio")
}

type QueryParamValue = string | number | boolean | null | undefined
type QueryParams = Record<string, QueryParamValue>
interface ManagementAPIResponse<T> {
  Code: number
  Error: string
  Data: T
}
type RequestTarget = { host?: string; port?: string | number }

function toMcpApiError(message: string, data?: unknown): McpError {
  return new McpError(ErrorCode.InternalError, message, data)
}

function buildRequestUrl(
  path: string,
  params?: string | URLSearchParams | QueryParams,
  target?: RequestTarget,
): string {
  const normalizedPath = path.replace(/^\/+/, "")
  const host = target?.host ?? MPC_AUTH_URL
  const port = String(target?.port ?? MPC_AUTH_PORT)
  const baseUrl = `${host}:${port}/${normalizedPath}`

  if (!params) {
    return baseUrl
  }

  if (typeof params === "string") {
    return `${baseUrl}?${params}`
  }

  const searchParams = params instanceof URLSearchParams ? params : new URLSearchParams()

  if (!(params instanceof URLSearchParams)) {
    for (const [key, value] of Object.entries(params)) {
      if (value !== null && value !== undefined) {
        searchParams.append(key, String(value))
      }
    }
  }

  const query = searchParams.toString()
  return query ? `${baseUrl}?${query}` : baseUrl
}

function normalizeBody(body?: BodyInit | object): { body?: BodyInit; headers?: Record<string, string> } {
  if (body === undefined) {
    return {}
  }

  const isPlainObject = Object.prototype.toString.call(body) === "[object Object]"
  if (!isPlainObject) {
    return { body: body as BodyInit }
  }

  return {
    body: JSON.stringify(body),
    headers: { "Content-Type": "application/json" },
  }
}

async function mgtGET<T>(
  path: string,
  params?: string | URLSearchParams | QueryParams,
  target?: RequestTarget,
): Promise<T> {
  const res = await fetch(buildRequestUrl(path, params, target), {
    method: "GET",
  })

  if (!res.ok) {
    const text = await res.text()
    throw toMcpApiError(`HTTP API error ${res.status}: ${text}`, { status: res.status, body: text })
  }

  let payload: ManagementAPIResponse<T>
  try {
    payload = (await res.json()) as ManagementAPIResponse<T>
  } catch (error) {
    throw toMcpApiError("HTTP API returned non-JSON response", {
      path,
      reason: error instanceof Error ? error.message : String(error),
    })
  }

  if (payload.Code !== 0) {
    const message = payload.Error?.trim() ? payload.Error : "HTTP API request failed with unknown error"
    throw toMcpApiError(message, { path, code: payload.Code, error: payload.Error })
  }

  return payload.Data
}

async function mgtPOST<T>(
  path: string,
  body?: BodyInit | object,
  params?: string | URLSearchParams | QueryParams,
): Promise<T> {
  const normalizedBody = normalizeBody(body)

  const res = await fetch(buildRequestUrl(path, params), {
    method: "POST",
    body: normalizedBody.body,
    headers: normalizedBody.headers,
  })

  if (!res.ok) {
    const text = await res.text()
    throw toMcpApiError(`HTTP API error ${res.status}: ${text}`, { status: res.status, body: text })
  }

  let payload: ManagementAPIResponse<T>
  try {
    payload = (await res.json()) as ManagementAPIResponse<T>
  } catch (error) {
    throw toMcpApiError("HTTP API returned non-JSON response", {
      path,
      reason: error instanceof Error ? error.message : String(error),
    })
  }

  if (payload.Code !== 0) {
    const message = payload.Error?.trim() ? payload.Error : "HTTP API request failed with unknown error"
    throw toMcpApiError(message, { path, code: payload.Code, error: payload.Error })
  }

  return payload.Data
}

main().catch((error) => {
  console.error("Fatal error in main():", error)
  process.exit(1)
})
