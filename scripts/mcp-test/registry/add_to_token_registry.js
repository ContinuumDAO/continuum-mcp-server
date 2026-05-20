const { runTool } = require("../common")

const chainType = process.env.REGISTRY_TEST_CHAIN_TYPE || "ethereum"
const chainId = process.env.REGISTRY_TEST_CHAIN_ID || "1"
const tokenType = process.env.REGISTRY_TEST_TOKEN_TYPE || "ERC20"
const contractAddress =
  process.env.REGISTRY_TEST_CONTRACT_ADDRESS || "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
const name = process.env.REGISTRY_TEST_TOKEN_NAME || `mcp-token-test-${Date.now()}`
const symbol = process.env.REGISTRY_TEST_TOKEN_SYMBOL || "MCP"
const decimals = process.env.REGISTRY_TEST_TOKEN_DECIMALS
  ? Number(process.env.REGISTRY_TEST_TOKEN_DECIMALS)
  : 6

runTool("add_to_token_registry", {
  chainType,
  chainId,
  tokenType,
  contract: {
    contractAddress,
    name,
    symbol,
    symbolURL: "",
    decimals,
  },
}).catch((error) => {
  console.error("Tool test failed:", error)
  process.exit(1)
})
