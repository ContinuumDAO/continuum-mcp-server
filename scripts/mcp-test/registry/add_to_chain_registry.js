const { runTool } = require("../common")

const chainId = process.env.REGISTRY_TEST_CHAIN_ID || "31337"
const chainName = process.env.REGISTRY_TEST_CHAIN_NAME || `MCP Test Chain ${Date.now()}`
const rpcGateway = process.env.REGISTRY_TEST_RPC_GATEWAY || "http://127.0.0.1:8545"

runTool("add_to_chain_registry", {
  chainName,
  chainId,
  rpcGateway,
  legacy: false,
  testnet: true,
  gasName: "ETH",
}).catch((error) => {
  console.error("Tool test failed:", error)
  process.exit(1)
})
