const { createClient } = require("./common")

async function main() {
  const { client, close } = await createClient()
  try {
    const nodeSetsRes = await client.callTool({ name: "list_valid_group_node_sets", arguments: {} })
    const validPairs = nodeSetsRes?.structuredContent?.validPairs || []
    if (!Array.isArray(validPairs) || validPairs.length === 0) {
      throw new Error("No valid node sets returned by list_valid_group_node_sets")
    }

    const keysRes = await client.callTool({ name: "list_management_keys", arguments: {} })
    const keys = keysRes?.structuredContent?.keys || []
    if (!Array.isArray(keys) || keys.length === 0) {
      throw new Error("No management keys returned by list_management_keys")
    }

    const signerIndex = Number.isInteger(keys[0].signerIndex) ? keys[0].signerIndex : 0
    const nodeIds = validPairs[0]
    const res = await client.callTool({
      name: "create_group_request",
      arguments: { nodeIds, signerIndex },
    })
    console.log(JSON.stringify(res, null, 2))
  } finally {
    await close()
  }
}

main().catch((error) => {
  console.error("Tool test failed:", error)
  process.exit(1)
})
