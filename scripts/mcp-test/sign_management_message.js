const { createClient } = require("./common")

async function main() {
  const { client, close } = await createClient()
  try {
    const keyRes = await client.callTool({ name: "list_management_signing_keys", arguments: {} })
    const keys = keyRes?.structuredContent?.keys || []
    if (!Array.isArray(keys) || keys.length === 0) {
      throw new Error("No management keys returned by list_management_signing_keys")
    }

    const selectedKeyId = keys[0].id
    const message = JSON.stringify({ nonce: keys[0].nonce, sig: "", ping: "test-message" })
    const signRes = await client.callTool({
      name: "sign_management_message",
      arguments: { selectedKeyId, message },
    })
    console.log(JSON.stringify(signRes, null, 2))
  } finally {
    await close()
  }
}

main().catch((error) => {
  console.error("Tool test failed:", error)
  process.exit(1)
})
