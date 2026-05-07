import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js"
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js"
import { ErrorCode, McpError } from "@modelcontextprotocol/sdk/types.js"
import { promises as fs } from "fs"
import {
  normalizeEd25519PublicKeyToHex as normalizeEd25519PublicKeyToHexBase,
  listLocalManagementPublicKeys as listLocalManagementPublicKeysBase,
  resolvePreferredManagementKeyOption as resolvePreferredManagementKeyOptionBase,
  ensureLocalKeyPairForPublicKey as ensureLocalKeyPairForPublicKeyBase,
  getPreferredSignerPublicKeyHex as getPreferredSignerPublicKeyHexBase,
  buildManagementSigningMessage as buildManagementSigningMessageBase,
  signManagementMessage as signManagementMessageBase,
  getPrivateKeyStatus as getPrivateKeyStatusBase,
  assertAgentCanSignManagementRequests as assertAgentCanSignManagementRequestsBase,
  type LocalManagementKeyEntry,
} from "./ed25519/management-signing.js"
import {
  type EdDSAPubKey,
  type Nonce,
  type Sig
} from "./types.js"
import { registerGroupTools } from "./group.js"
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
    resources: {
      subscribe: true,
      listChanged: true
    }
  },
})

const MPC_AUTH_URL = process.env.MPC_AUTH_URL ?? "http://localhost"
const MPC_AUTH_PORT = process.env.MPC_AUTH_PORT ?? "8080"
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

async function resolveManagementSigningKeyOption(keyOptions: ManagementKeyOption[]): Promise<ManagementKeyOption> {
  return resolvePreferredManagementKeyOptionBase(
    keyOptions,
    { keyRoot: KEY_ROOT, toMcpApiError, mgtGET },
  ) as Promise<ManagementKeyOption>
}

async function ensureLocalKeyPairForPublicKey(publicKey: string): Promise<{ fileName: string; publicKeyPath: string; privateKeyPath: string }> {
  return ensureLocalKeyPairForPublicKeyBase(publicKey, { keyRoot: KEY_ROOT, toMcpApiError })
}

async function getPreferredSignerPublicKeyHex(): Promise<string | undefined> {
  return getPreferredSignerPublicKeyHexBase({ mgtGET, toMcpApiError })
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

async function getNodeKey(): Promise<import("./types.js").NodeId> {
  return mgtGET<import("./types.js").NodeId>("/getNodeKey")
}

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
  resolveManagementSigningKeyOption,
  getNodeKey,
  buildManagementSigningMessage,
  signManagementMessage,
  listLocalManagementPublicKeys,
  getPrivateKeyStatus,
  ensureLocalKeyPairForPublicKey,
  getPreferredSignerPublicKeyHex,
})
registerGroupTools({
  server,
  mgtGET,
  mgtPOST,
  toMcpApiError,
  fetchManagementKeyOptions,
  resolveManagementSigningKeyOption,
  buildManagementSigningMessage,
  signManagementMessage,
})
registerKeyGenTools({
  server,
  mgtGET,
  mgtPOST,
  toMcpApiError,
  fetchManagementKeyOptions,
  resolveManagementSigningKeyOption,
  buildManagementSigningMessage,
  signManagementMessage,
})

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
