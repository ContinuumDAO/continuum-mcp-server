const { spawn } = require("node:child_process")
const path = require("path")
const { Client } = require("@modelcontextprotocol/sdk/client/index.js")
const { StreamableHTTPClientTransport } = require("@modelcontextprotocol/sdk/client/streamableHttp.js")

function resolveMcpServerUrl() {
  const host = process.env.MCP_HTTP_HOST ?? "127.0.0.1"
  const port = process.env.MCP_HTTP_PORT ?? process.env.MCP_PORT ?? "3000"
  const mcpPath = process.env.MCP_HTTP_PATH ?? "/mcp"
  return new URL(`http://${host}:${port}${mcpPath}`)
}

async function waitForServer(url, timeoutMs = 15000) {
  const deadline = Date.now() + timeoutMs

  while (Date.now() < deadline) {
    try {
      const response = await fetch(url, { method: "GET" })
      if (response.status === 400) {
        return
      }
    } catch {
      // server not ready yet
    }

    await new Promise((resolve) => setTimeout(resolve, 100))
  }

  throw new Error(`Timed out waiting for MCP server at ${url.toString()}`)
}

async function startServerProcess() {
  const serverPath = path.join(process.cwd(), "build", "index.js")
  const host = process.env.MCP_HTTP_HOST ?? "127.0.0.1"
  const port = process.env.MCP_HTTP_PORT ?? process.env.MCP_PORT ?? "3000"
  const url = resolveMcpServerUrl()

  const child = spawn("node", [serverPath], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      MCP_HTTP_HOST: host,
      MCP_HTTP_PORT: String(port),
    },
    stdio: ["ignore", "inherit", "inherit"],
  })

  await waitForServer(url)

  async function stop() {
    if (child.exitCode !== null || child.killed) {
      return
    }

    child.kill("SIGTERM")

    await new Promise((resolve) => {
      const timeout = setTimeout(() => {
        if (child.exitCode === null && !child.killed) {
          child.kill("SIGKILL")
        }
        resolve()
      }, 3000)

      child.once("exit", () => {
        clearTimeout(timeout)
        resolve()
      })
    })
  }

  return { child, stop, url }
}

async function createClient() {
  const { stop, url } = await startServerProcess()
  const transport = new StreamableHTTPClientTransport(url)

  const client = new Client(
    { name: "mcp-tool-tester", version: "1.0.0" },
    { capabilities: {} },
  )

  await client.connect(transport)

  async function close() {
    try {
      await client.close()
    } catch {
      // ignore close errors for scripts
    }

    await stop()
  }

  return { client, close }
}

async function runTool(toolName, args = {}) {
  const { client, close } = await createClient()
  try {
    const result = await client.callTool({ name: toolName, arguments: args })
    console.log(JSON.stringify(result, null, 2))
  } finally {
    await close()
  }
}

module.exports = { createClient, runTool, resolveMcpServerUrl }
