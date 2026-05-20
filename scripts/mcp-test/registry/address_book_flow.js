/**
 * End-to-end address book registry test (src/registry/address_book.ts):
 * list keys → get → add → get (verify) → remove → get (verify removed).
 *
 * Requires a running Continuum management API and usable EdDSA keys in KEY_ROOT.
 */
const { createClient } = require("../common")

const TEST_CHAIN_TYPE = process.env.REGISTRY_TEST_CHAIN_TYPE || "ethereum"
const TEST_ADDRESS = process.env.REGISTRY_TEST_ADDRESS || "0x00000000000000000000000000000000000000DE"
const TEST_NAME = process.env.REGISTRY_TEST_NAME || `mcp-registry-flow-${Date.now()}`
const TEST_CHAIN_IDS = process.env.REGISTRY_TEST_CHAIN_IDS
  ? process.env.REGISTRY_TEST_CHAIN_IDS.split(",").map((s) => s.trim()).filter(Boolean)
  : ["1"]

function assertToolOk(result, step) {
  if (result?.isError) {
    const text = result.content?.map((c) => c.text).filter(Boolean).join("\n") || "unknown error"
    throw new Error(`${step} failed: ${text}`)
  }
}

function findEntry(data, chainType, address) {
  if (!data || typeof data !== "object") {
    return undefined
  }
  const list = data[chainType]
  if (!Array.isArray(list)) {
    return undefined
  }
  const normalized = address.toLowerCase()
  return list.find((entry) => typeof entry.address === "string" && entry.address.toLowerCase() === normalized)
}

async function main() {
  const { client, close } = await createClient()
  try {
    console.log("Prerequisite: list_management_keys")
    const keysRes = await client.callTool({ name: "list_management_keys", arguments: {} })
    assertToolOk(keysRes, "list_management_keys")
    const keys = keysRes?.structuredContent?.keys || []
    if (!Array.isArray(keys) || keys.length === 0) {
      throw new Error("No management keys returned; cannot run signed registry tools")
    }
    const usable = keys.filter((k) => k.localPrivateKeyAvailable)
    if (usable.length === 0) {
      throw new Error("No management key with a usable local private key")
    }
    console.log(`Using ${usable.length} locally-signable key(s)\n`)

    console.log("1. get_address_book_registry (before)")
    const beforeRes = await client.callTool({ name: "get_address_book_registry", arguments: {} })
    assertToolOk(beforeRes, "get_address_book_registry (before)")
    console.log(JSON.stringify(beforeRes.structuredContent, null, 2))

    console.log("\n2. add_to_address_book_registry")
    const addRes = await client.callTool({
      name: "add_to_address_book_registry",
      arguments: {
        chainType: TEST_CHAIN_TYPE,
        address: TEST_ADDRESS,
        name: TEST_NAME,
        chainIds: TEST_CHAIN_IDS,
        isContract: false,
      },
    })
    assertToolOk(addRes, "add_to_address_book_registry")
    console.log(JSON.stringify(addRes.structuredContent, null, 2))

    console.log("\n3. get_address_book_registry (after add)")
    const afterAddRes = await client.callTool({
      name: "get_address_book_registry",
      arguments: { chain_type: TEST_CHAIN_TYPE },
    })
    assertToolOk(afterAddRes, "get_address_book_registry (after add)")
    const afterAdd = afterAddRes.structuredContent
    console.log(JSON.stringify(afterAdd, null, 2))

    const added = findEntry(afterAdd, TEST_CHAIN_TYPE, TEST_ADDRESS)
    if (!added) {
      throw new Error(
        `Expected address ${TEST_ADDRESS} under chain type ${TEST_CHAIN_TYPE} after add`,
      )
    }
    if (added.name !== TEST_NAME) {
      throw new Error(`Expected name ${TEST_NAME}, got ${added.name}`)
    }
    console.log("\nVerified entry present after add.")

    console.log("\n4. remove_from_address_book_registry")
    const removeRes = await client.callTool({
      name: "remove_from_address_book_registry",
      arguments: {
        chainType: TEST_CHAIN_TYPE,
        address: TEST_ADDRESS,
      },
    })
    assertToolOk(removeRes, "remove_from_address_book_registry")
    console.log(JSON.stringify(removeRes.structuredContent, null, 2))

    console.log("\n5. get_address_book_registry (after remove)")
    const afterRemoveRes = await client.callTool({
      name: "get_address_book_registry",
      arguments: { chain_type: TEST_CHAIN_TYPE },
    })
    assertToolOk(afterRemoveRes, "get_address_book_registry (after remove)")
    const afterRemove = afterRemoveRes.structuredContent
    console.log(JSON.stringify(afterRemove, null, 2))

    if (findEntry(afterRemove, TEST_CHAIN_TYPE, TEST_ADDRESS)) {
      throw new Error(
        `Expected address ${TEST_ADDRESS} to be absent under ${TEST_CHAIN_TYPE} after remove`,
      )
    }
    console.log("\nVerified entry removed.")
    console.log("\nAddress book registry flow completed successfully.")
  } finally {
    await close()
  }
}

main().catch((error) => {
  console.error("Registry flow test failed:", error)
  process.exit(1)
})
