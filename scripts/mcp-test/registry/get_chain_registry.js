const { runTool } = require("../common")

const chainId = process.env.REGISTRY_TEST_CHAIN_ID

const args = {}
if (chainId) {
  args.chain_id = chainId
}

runTool("get_chain_registry", args).catch((error) => {
  console.error("Tool test failed:", error)
  process.exit(1)
})
