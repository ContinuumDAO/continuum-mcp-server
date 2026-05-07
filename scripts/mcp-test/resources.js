const { createClient } = require("./common")

async function main() {
  const { client, close } = await createClient()
  try {
    const resources = await client.listResources()
    console.log("=== Resources ===")
    console.log(JSON.stringify(resources, null, 2))

    const uris = ["docs://overview.md", "docs://group.md", "docs://sign.md"]
    for (const uri of uris) {
      const res = await client.readResource({ uri })
      console.log(`\n=== ${uri} ===`)
      console.log(JSON.stringify(res, null, 2))
    }
  } finally {
    await close()
  }
}

main().catch((error) => {
  console.error("Resource test failed:", error)
  process.exit(1)
})
