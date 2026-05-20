const { runTool } = require("../common")

const chainType = process.env.REGISTRY_TEST_CHAIN_TYPE || "ethereum"
const address = process.env.REGISTRY_TEST_ADDRESS || "0x00000000000000000000000000000000000000DE"
const name = process.env.REGISTRY_TEST_NAME || `mcp-registry-test-${Date.now()}`
const chainIds = process.env.REGISTRY_TEST_CHAIN_IDS
  ? process.env.REGISTRY_TEST_CHAIN_IDS.split(",").map((s) => s.trim()).filter(Boolean)
  : ["1"]
const isContract = process.env.REGISTRY_TEST_IS_CONTRACT === "true"

const args = {
  chainType,
  address,
  name,
  chainIds,
  isContract,
}

runTool("add_to_address_book_registry", args).catch((error) => {
  console.error("Tool test failed:", error)
  process.exit(1)
})
