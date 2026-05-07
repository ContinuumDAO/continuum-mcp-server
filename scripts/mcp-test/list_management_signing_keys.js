const { runTool } = require("./common")

runTool("list_management_signing_keys").catch((error) => {
  console.error("Tool test failed:", error)
  process.exit(1)
})
