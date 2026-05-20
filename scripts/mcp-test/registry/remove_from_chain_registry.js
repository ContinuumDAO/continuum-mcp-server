const { runTool } = require("../common")

const chainId = process.env.REGISTRY_TEST_CHAIN_ID || "31337"

runTool("remove_from_chain_registry", { chainId }).catch((error) => {
  console.error("Tool test failed:", error)
  process.exit(1)
})
