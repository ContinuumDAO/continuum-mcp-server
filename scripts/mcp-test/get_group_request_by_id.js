const { createClient } = require("./common")

async function main() {
  const { client, close } = await createClient()
  try {
    let requestId = process.env.REQUEST_ID

    if (!requestId) {
      const listRes = await client.callTool({ name: "list_group_requests", arguments: {} })
      const requests = listRes?.structuredContent?.requests
      if (!Array.isArray(requests) || requests.length === 0) {
        throw new Error("No group requests available. Set REQUEST_ID=<id> to test get_group_request_by_id directly.")
      }

      const first = requests[0]
      requestId = first?.RequestId || first?.requestid || first?.id
      if (!requestId || typeof requestId !== "string") {
        throw new Error(
          `Could not resolve request ID from first list_group_requests item. Keys: ${Object.keys(first || {}).join(", ")}`,
        )
      }
    }

    const res = await client.callTool({
      name: "get_group_request_by_id",
      arguments: { id: requestId },
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
