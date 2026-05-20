const { runTool } = require("../common")

const chainType = process.env.REGISTRY_TEST_CHAIN_TYPE
const chainId = process.env.REGISTRY_TEST_CHAIN_ID

const args = {}
if (chainType) {
  args.chainType = chainType
}
if (chainId) {
  args.chain_id = chainId
}

runTool("get_token_registry", args).catch((error) => {
  console.error("Tool test failed:", error)
  process.exit(1)
})
