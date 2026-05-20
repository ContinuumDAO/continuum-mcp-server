const { runTool } = require("../common")

const chainType = process.env.REGISTRY_TEST_CHAIN_TYPE || "ethereum"
const chainId = process.env.REGISTRY_TEST_CHAIN_ID || "1"
const tokenType = process.env.REGISTRY_TEST_TOKEN_TYPE || "ERC20"
const contractAddress =
  process.env.REGISTRY_TEST_CONTRACT_ADDRESS || "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
const tokenId = process.env.REGISTRY_TEST_TOKEN_ID

const args = {
  chainType,
  chainId,
  tokenType,
  contractAddress,
}
if (tokenId !== undefined) {
  args.tokenId = tokenId
}

runTool("remove_from_token_registry", args).catch((error) => {
  console.error("Tool test failed:", error)
  process.exit(1)
})
