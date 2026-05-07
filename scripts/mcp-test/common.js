const path = require("path")
const { Client } = require("@modelcontextprotocol/sdk/client/index.js")
const { StdioClientTransport } = require("@modelcontextprotocol/sdk/client/stdio.js")

async function createClient() {
  const serverPath = path.join(process.cwd(), "build", "index.js")
  const transport = new StdioClientTransport({
    command: "node",
    args: [serverPath],
    cwd: process.cwd(),
    stderr: "inherit",
  })

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

module.exports = { createClient, runTool }
