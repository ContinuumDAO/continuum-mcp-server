const { runTool } = require("../common")

const chainType = process.env.REGISTRY_TEST_CHAIN_TYPE || "ethereum"
const address = process.env.REGISTRY_TEST_ADDRESS || "0x00000000000000000000000000000000000000DE"

runTool("remove_from_address_book_registry", { chainType, address }).catch((error) => {
  console.error("Tool test failed:", error)
  process.exit(1)
})
