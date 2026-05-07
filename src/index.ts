import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js"
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js"
import { ErrorCode, McpError, CallToolResult } from "@modelcontextprotocol/sdk/types.js"
import { z } from "zod"
import { promises as fs } from "fs"
import { generateKeyPairSync } from "crypto"
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
  KeySchema,
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

// Category 0: Node Information

// // 0.1 /version
// server.registerTool(
//   "version",
//   {
//     description: "Get the current version of the MPC node client",
//     outputSchema: z.object({
//       version: z.string(),
//       versionDate: z.string()
//     })
//   },
//   async (): Promise<CallToolResult> => {
//     const output = await mgtGET<{ version: string, versionDate: string }>("/version")
//     return {
//       content: [{ type: "text", text: JSON.stringify(output) }],
//       structuredContent: output
//     }
//   }
// )
// 
// // 0.2 /getMachineInfo
// server.registerTool(
//   "get_machine_info",
//   {
//     description: "Get the MPC node client's host machine technical specifications. Optionally refresh the cached data",
//     inputSchema: z.object({ refresh: z.boolean().optional() }),
//     outputSchema: MachineInfoSchema,
//   },
//   async ({ refresh }: { refresh?: boolean }): Promise<CallToolResult> => {
//     let params = new URLSearchParams()
//     if (refresh !== undefined) {
//       params.append("refresh", refresh.toString())
//     }
// 
//     const output = await mgtGET<MachineInfo>("/getMachineInfo", params)
// 
//     return {
//       content: [{ type: "text", text: JSON.stringify(output) }],
//       structuredContent: output,
//     }
//   }
// )
// 
// // 0.3 /getNodeKey
// server.registerTool(
//   "get_node_id",
//   {
//     description: "Get the MPC node client's unique public key (node ID), a 128-character hex string",
//     outputSchema: z.object({ nodeKey: NodeIdSchema }),
//   },
//   async (): Promise<CallToolResult> => {
//     const nodeKey = await mgtGET<NodeId>("/getNodeKey")
//     return {
//       content: [{ type: "text", text: JSON.stringify({ nodeKey }) }],
//       structuredContent: { nodeKey },
//     }
//   },
// )
// 
// // 0.4 /getNodeMgtKey & /getNodeMgtKeyNonce
// server.registerTool(
//   "get_ecdsa_management_key_and_nonce",
//   {
//     description: "Get the EVM address that is configured to manage this MPC node client along with its next nonce",
//     outputSchema: z.object({ nodeMgtKey: ECDSAAddressSchema, nonce: NonceSchema }),
//   },
//   async (): Promise<CallToolResult> => {
//     const { nodeMgtKey, nonce } = await mgtGET<{ nodeMgtKey: ECDSAAddress, nonce: Nonce }>("/getNodeMgtKeyNonce")
//     return {
//       content: [{ type: "text", text: JSON.stringify({ nodeMgtKey, nonce }) }],
//       structuredContent: { nodeMgtKey, nonce },
//     }
//   },
// )

// FIXIT: Redundant - could merge into /getNodeMgtKey path get_ecdsa_management_key
// // 0.5 /getNodeMgtKeyNonce
// server.registerTool(
//   "get_ecdsa_management_key_nonce",
//   {
//     description: "Get the next nonce for the currently configured secp256k1 Key (the Ethereum address that manages this MPC node client)",
//     outputSchema: z.object({ key: ECDSAAddressSchema, nonce: NonceSchema }),
//   },
//   async (): Promise<CallToolResult> => {
//     const output = await mgtGET<{ key: ECDSAAddress, nonce: Nonce }>("/getNodeMgtKeyNonce")
//     return {
//       content: [{ type: "text", text: JSON.stringify(output) }],
//       structuredContent: output,
//     }
//   },
// )

// 0.6 /hasPublicMgtKey
server.registerTool(
  "has_eddsa_management_key",
  {
    description: "Check whether any EdDSA (Ed25519) key is configured to manage this MPC node client",
    outputSchema: z.object({ hasEdDSAKey: z.boolean() }),
  },
  async (): Promise<CallToolResult> => {
    const output = await mgtGET<boolean>("/hasPublicMgtKey")
    return {
      content: [{ type: "text", text: JSON.stringify({ hasEdDSAKey: output }) }],
      structuredContent: { hasEdDSAKey: output },
    }
  },
)

// 0.7 /getAllowedEd25519MgtKeys
server.registerTool(
  "get_eddsa_management_keys",
  {
    description: "List the EdDSA (Ed25519) keys configured to manage this MPC node client and their given labels",
    outputSchema: z.object({ keys: z.array(z.object({ publicKey: EdDSAPubKeySchema, label: z.string() })) }),
  },
  async (): Promise<CallToolResult> => {
    const output = await mgtGET<{ publicKey: EdDSAPubKey; label: string }[]>("/getAllowedEd25519MgtKeys")

    let result = ""
    if (output.length === 0) {
      result = "No keys configured to manage this MPC node client - a keypair should be created."
    } else {
      result = JSON.stringify({ keys: output })
    }

    return {
      content: [{ type: "text", text: result }],
      structuredContent: { keys: output },
    }
  }
)

// FIXIT: Redundant
// // 0.8 /getPublicMgtKey
// server.registerTool(
//   "get_ed25519_management_key",
//   {
//     description: "List allowed Ed25519 management public keys as plain strings",
//     outputSchema: z.object({ publicKeys: z.array(EdDSAPubKeySchema) }),
//   },
//   async (): Promise<CallToolResult> => {
//     const output = await mgtGET<EdDSAPubKey[]>("/getPublicMgtKey")
//     return {
//       content: [{ type: "text", text: JSON.stringify({ publicKeys: output }) }],
//       structuredContent: { publicKeys: output },
//     }
//   }
// )

// FIXIT: Redundant - could merge into /getAllowedEd25519MgtKeys path get_eddsa_management_keys
// // 0.9 /getPublicMgtKeyNonce
// server.registerTool(
//   "get_eddsa_management_key_nonce",
//   {
//     description: "Get current nonce for an Ed25519 management key",
//     inputSchema: z.object({ publicKey: EdDSAPubKeySchema.optional() }),
//     outputSchema: z.object({ key: EdDSAPubKeySchema, nonce: NonceSchema }),
//   },
//   async ({ publicKey }: { publicKey?: EdDSAPubKey }): Promise<CallToolResult> => {
//     let params = new URLSearchParams()
//     if (publicKey !== undefined) {
//       params.append("publicKey", publicKey)
//     }
// 
//     const output = await mgtGET<{ key: EdDSAPubKey, nonce: Nonce }>("/getPublicMgtKeyNonce", params)
// 
//     return {
//       content: [{ type: "text", text: JSON.stringify(output) }],
//       structuredContent: output,
//     }
//   }
// )

// TEST: commented out temporarily
// // 0.10 /verifyMgtKey
// server.registerTool(
//   "verify_eddsa_management_key",
//   {
//     description: "Verify Ed25519 management key ownership using nonce and signature",
//     inputSchema: z.object({ Nonce: NonceSchema, Sig: EdDSASigSchema }),
//     outputSchema: z.object({ success: z.boolean(), message: z.string() })
//   },
//   async ({ Nonce, Sig }: { Nonce: Nonce, Sig: EdDSASig }): Promise<CallToolResult> => {
//     const body = { Nonce, Sig }
//     await mgtPOST<boolean>("/verifyMgtKey", body)
//     return {
//       content: [{ type: "text", text: JSON.stringify({ success: true, message: "Verification successful." }) }],
//       structuredContent: { success: true, message: "Verification successful." }
//     }
//   }
// )

server.registerTool(
  "create_eddsa_management_keypair",
  {
    description: "Generate a new Ed25519 keypair in KEY_ROOT/management_keys with auto-generated file name added_key_{N}. This only writes local files.",
    outputSchema: z.object({
      success: z.boolean(),
      fileName: z.string(),
      publicKey: EdDSAPubKeySchema,
      message: z.string(),
      privateKeyPath: z.string(),
      publicKeyPath: z.string(),
    })
  },
  async (): Promise<CallToolResult> => {
    const currentKeyCount = (await mgtGET<{ publicKey: EdDSAPubKey; label: string }[]>("/getAllowedEd25519MgtKeys")).length
    const fileName = `added_key_${currentKeyCount}`
    const keyDir = path.join(KEY_ROOT, "management_keys")
    await fs.mkdir(keyDir, { recursive: true })

    const privateKeyPath = path.join(keyDir, fileName)
    const publicKeyPath = `${privateKeyPath}.pub`

    const privateExists = await fs.access(privateKeyPath).then(() => true).catch(() => false)
    if (privateExists) {
      throw toMcpApiError("Private key file already exists", { privateKeyPath })
    }
    const publicExists = await fs.access(publicKeyPath).then(() => true).catch(() => false)
    if (publicExists) {
      throw toMcpApiError("Public key file already exists", { publicKeyPath })
    }

    const { privateKey, publicKey } = generateKeyPairSync("ed25519")
    const privatePem = privateKey.export({ format: "pem", type: "pkcs8" }).toString()
    const publicJwk = publicKey.export({ format: "jwk" }) as { x?: string }
    if (!publicJwk.x) {
      throw toMcpApiError("Failed to derive Ed25519 raw public key from generated keypair")
    }
    const newPublicKey = Buffer.from(publicJwk.x, "base64url").toString("hex")

    await fs.writeFile(privateKeyPath, privatePem, { mode: 0o600 })
    await fs.writeFile(publicKeyPath, `${newPublicKey}\n`, { mode: 0o644 })

    const structuredContent = {
      success: true,
      fileName,
      publicKey: newPublicKey,
      message: "Generated Ed25519 management keypair locally.",
      privateKeyPath,
      publicKeyPath
    }

    return {
      content: [{ type: "text", text: JSON.stringify(structuredContent) }],
      structuredContent
    }
  },
)

server.registerTool(
  "add_eddsa_management_key",
  {
    description: "Add a new Ed25519 public key to allowed management keys via /addManagementKey, signed by signer index (0=bootstrap, N=added_key_N).",
    inputSchema: z.object({
      signerIndex: z.number().int().nonnegative(),
      newPublicKey: EdDSAPubKeySchema,
    }),
    outputSchema: z.object({
      success: z.boolean(),
      publicKey: EdDSAPubKeySchema,
      message: z.string(),
    })
  },
  async ({
    signerIndex,
    newPublicKey,
  }: {
    signerIndex: number
    newPublicKey: EdDSAPubKey
  }): Promise<CallToolResult> => {
    await assertAgentCanSignManagementRequests()

    const normalizedNewPublicKey = normalizeEd25519PublicKeyToHex(newPublicKey) as EdDSAPubKey
    const keyOptions = await fetchManagementKeyOptions()
    const selectedSigningKey = await getManagementKeyOptionByIndex(keyOptions, signerIndex)
    if (normalizeEd25519PublicKeyToHex(selectedSigningKey.value) === normalizedNewPublicKey) {
      throw toMcpApiError(
        "Signer key cannot be the newly created key being added. Use an existing already-authorized EdDSA signer key.",
        { signerIndex, signerPublicKey: selectedSigningKey.value, newPublicKey: normalizedNewPublicKey },
      )
    }

    const unsignedBody = { newPublicKey: normalizedNewPublicKey, nonce: selectedSigningKey.nonce, sig: "" }
    const signingMessage = buildManagementSigningMessage(unsignedBody)
    const signature = await signManagementMessage(selectedSigningKey, signingMessage)
    const body = { ...unsignedBody, sig: signature }
    await mgtPOST<null>("/addManagementKey", body)

    const structuredContent = {
      success: true,
      publicKey: normalizedNewPublicKey,
      message: "Added Ed25519 management key successfully.",
    }

    return {
      content: [{ type: "text", text: JSON.stringify(structuredContent) }],
      structuredContent
    }
  },
)

// // 0.11.1 /getMessageToSign
// server.registerTool(
//   "get_message_to_sign",
//   {
//     description: "Return exact canonical message to sign with MetaMask for a management-signed request body",
//     inputSchema: z.record(z.string(), z.unknown()),
//     outputSchema: MessageToSignResponseSchema,
//   },
//   async (body: Record<string, unknown>): Promise<CallToolResult> => {
//     const output = await mgtPOST<MessageToSignResponse>("/getMessageToSign", body)
//     return {
//       content: [{ type: "text", text: JSON.stringify(output) }],
//       structuredContent: output,
//     }
//   },
// )

// // 0.12 /getAllowedKeyTypes
// server.registerTool(
//   "get_allowed_key_types",
//   {
//     description: "Get supported key types; can be ed25519 (eddsa) or secp256k1 (ecdsa)",
//     outputSchema: z.object({ keyTypes: z.array(KeySchema) })
//   },
//   async (): Promise<CallToolResult> => {
//     const output = await mgtGET<Key[]>("/getAllowedKeyTypes")
//     return {
//       content: [{ type: "text", text: JSON.stringify({ keyTypes: output }) }],
//       structuredContent: { keyTypes: output },
//     }
//   },
// )

// // 0.13 /getAllowedMsgCheckTypes
// server.registerTool(
//   "get_allowed_msg_check_types",
//   {
//     description: "Get supported message check types; can be multi-agree (for wallets) or tx-check (for validators)",
//     outputSchema: z.object({ msgCheckTypes: z.array(MsgCheckSchema) }),
//   },
//   async (): Promise<CallToolResult> => {
//     const output = await mgtGET<MsgCheck[]>("/getAllowedMsgCheckTypes")
//     return {
//       content: [{ type: "text", text: JSON.stringify({ msgCheckTypes: output }) }],
//       structuredContent: { msgCheckTypes: output },
//     }
//   },
// )

// // 0.14 /getSuccessRate
// server.registerTool(
//   "get_success_rate",
//   {
//     description: "Get keygen and signing success rate statistics, including an optional field for number of hours to check",
//     inputSchema: z.object({ hours: z.number().int().nonnegative().optional() }),
//     outputSchema: z.object({
//       keygen: z.object({
//         total: z.number(),
//         success: z.number(),
//         failed: z.number(),
//         successRate: z.number(),
//       }),
//       signing: z.object({
//         total: z.number(),
//         success: z.number(),
//         failed: z.number(),
//         successRate: z.number(),
//       }),
//     }),
//   },
//   async ({ hours }: { hours?: number }): Promise<CallToolResult> => {
//     let params = new URLSearchParams()
//     if (hours !== undefined) {
//       params.append("hours", hours.toString())
//     }
// 
//     const output = await mgtGET<{
//       keygen: { total: number; success: number; failed: number; successRate: number }
//       signing: { total: number; success: number; failed: number; successRate: number }
//     }>("/getSuccessRate", params)
//     return {
//       content: [{ type: "text", text: JSON.stringify(output) }],
//       structuredContent: output,
//     }
//   },
// )

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

// // 0.17 /getSubscriptions
// server.registerTool(
//   "get_subscriptions",
//   {
//     description: "Get current MQTT subscription information",
//     outputSchema: z.object({ subscriptions: z.array(SubscriptionSchema) }),
//   },
//   async (): Promise<CallToolResult> => {
//     const output = await mgtGET<Subscription[]>("/getSubscriptions")
//     return {
//       content: [{ type: "text", text: JSON.stringify({ subscriptions: output }) }],
//       structuredContent: { subscriptions: output },
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
// // 0.22 /health
// server.registerTool(
//   "health",
//   {
//     description: "Get comprehensive node health status",
//     outputSchema: z.object({
//       status: z.string(),
//       timestamp: z.number(),
//       mqtt: z.object({
//         connected: z.boolean(),
//         channels: z.number(),
//         errors: z.array(z.string()),
//         warnings: z.array(z.string()),
//       }),
//       mongodb: z.object({
//         connected: z.boolean(),
//         error: z.string(),
//       }),
//       subscriptions: z.array(SubscriptionSchema),
//     }),
//   },
//   async (): Promise<CallToolResult> => {
//     const output = await mgtGET<{
//       status: string
//       timestamp: number
//       mqtt: { connected: boolean; channels: number; errors: string[]; warnings: string[] }
//       mongodb: { connected: boolean; error: string }
//       subscriptions: Subscription[]
//     }>("/health")
//     return {
//       content: [{ type: "text", text: JSON.stringify(output) }],
//       structuredContent: output,
//     }
//   },
// )
// 
// // 0.23 /connectivityHealth
// server.registerTool(
//   "connectivity_health",
//   {
//     description: "Check per-node connectivity and latency by group",
//     inputSchema: z.object({
//       groupId: GroupIdSchema.optional(),
//       timeout: z.number().int().positive().optional(),
//     }),
//     outputSchema: z.object({
//       groups: z.array(
//         z.object({
//           groupId: GroupIdSchema,
//           nodeCount: z.number(),
//           results: z.array(NodeConnectivityResultSchema),
//           summary: z.object({
//             very_good: z.number(),
//             good: z.number(),
//             medium: z.number(),
//             slow: z.number(),
//             very_slow: z.number(),
//             no_response: z.number(),
//           })
//         })
//       )
//     })
//   },
//   async ({ groupId, timeout }: { groupId?: GroupId; timeout?: number }): Promise<CallToolResult> => {
//     let params = new URLSearchParams()
//     if (groupId !== undefined) {
//       params.append("groupId", groupId)
//     }
//     if (timeout !== undefined) {
//       params.append("timeout", timeout.toString())
//     }
// 
//     const output = await mgtGET<{
//       groupId: GroupId
//       nodeCount: number
//       results: NodeConnectivityResult[]
//       summary: { very_good: number; good: number; medium: number; slow: number; very_slow: number; no_response: number }
//     }[]>("/connectivityHealth", params)
//     return {
//       content: [{ type: "text", text: JSON.stringify({ groups: output }) }],
//       structuredContent: { groups: output },
//     }
//   }
// )
// 
// // 0.24 /getLogs
// server.registerTool(
//   "get_logs",
//   {
//     description: "Get recent log entries for a time window",
//     inputSchema: z.object({ hours: z.number().positive().optional() }),
//     outputSchema: LogsSchema
//   },
//   async ({ hours }: { hours?: number }): Promise<CallToolResult> => {
//     let params = new URLSearchParams()
//     if (hours !== undefined) {
//       params.append("hours", hours.toString())
//     }
// 
//     const output = await mgtGET<Logs>("/getLogs", params)
//     return {
//       content: [{ type: "text", text: JSON.stringify(output) }],
//       structuredContent: output,
//     }
//   }
// )

// // 0.25 /getConfiguredNodeKeys
// server.registerTool(
//   "get_configured_node_keys",
//   {
//     description: "Get configured node IP addresses and their node IDs",
//     outputSchema: z.object({
//       nodes: z.array(ConfiguredNodeSchema),
//       nodesMap: z.record(z.string(), ConfiguredNodeSchema),
//       total: z.number(),
//       available: z.number(),
//       unavailable: z.number(),
//     })
//   },
//   async (): Promise<CallToolResult> => {
//     const output = await mgtGET<{
//       nodes: ConfiguredNode[],
//       nodesMap: Record<string, ConfiguredNode>,
//       total: number,
//       available: number,
//       unavailable: number
//     }>("/getConfiguredNodeKeys")
//     return {
//       content: [{ type: "text", text: JSON.stringify(output) }],
//       structuredContent: output,
//     }
//   }
// )

// Category 1: Group Management
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
  listLocalManagementPublicKeys,
  getPrivateKeyStatus,
  normalizeEd25519PublicKeyToHex,
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
