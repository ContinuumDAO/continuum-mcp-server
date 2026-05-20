import { createContinuumMcpServer } from "./create-server.js"
import { startHttpTransportServer } from "./http-transport.js"
import { loadAddressBookRegistry } from "./registry/address_book.js"
import { loadContractsRegistry } from "./registry/contracts.js"
import { loadNetworksRegistry } from "./registry/networks.js"
import { loadTokensRegistry } from "./registry/tokens.js"

async function main() {
  await Promise.all([
    loadAddressBookRegistry(),
    loadContractsRegistry(),
    loadTokensRegistry(),
    loadNetworksRegistry(),
  ])

  await startHttpTransportServer(createContinuumMcpServer)
}

main().catch((error) => {
  console.error("Fatal error in main():", error)
  process.exit(1)
})
