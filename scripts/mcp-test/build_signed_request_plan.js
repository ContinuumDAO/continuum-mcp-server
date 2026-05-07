const { createClient } = require("./common")

async function main() {
  const { client, close } = await createClient()
  try {
    const keyRes = await client.callTool({ name: "list_management_keys", arguments: {} })
    const keys = keyRes?.structuredContent?.keys || []
    if (!Array.isArray(keys) || keys.length === 0) {
      throw new Error("No management keys returned by list_management_keys")
    }

    const planRes = await client.callTool({
      name: "build_signed_request_plan",
      arguments: {
        action: "newGroupRequest",
        payload: {
          keyList: [],
          BrokerArray: [],
        },
      },
    })
    console.log(JSON.stringify(planRes, null, 2))
  } finally {
    await close()
  }
}

main().catch((error) => {
  console.error("Tool test failed:", error)
  process.exit(1)
})
