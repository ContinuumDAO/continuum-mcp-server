const { runTool } = require("./common")

runTool("has_eddsa_management_key").catch((error) => {
  console.error("Tool test failed:", error)
  process.exit(1)
})
