const { runTool } = require("../common")

const chainType = process.env.REGISTRY_TEST_CHAIN_TYPE
const chainId = process.env.REGISTRY_TEST_CHAIN_ID
const isContract = process.env.REGISTRY_TEST_IS_CONTRACT

const args = {}
if (chainType) {
  args.chain_type = chainType
}
if (chainId) {
  args.chain_id = chainId
}
if (isContract === "0" || isContract === "1") {
  args.is_contract = isContract
}

runTool("get_address_book_registry", args).catch((error) => {
  console.error("Tool test failed:", error)
  process.exit(1)
})
