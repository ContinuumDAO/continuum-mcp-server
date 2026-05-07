const { runTool } = require("./common")

// Uses server-side defaults for selectedIndexes/selectedKeyId.
runTool("create_group_request", {}).catch((error) => {
  console.error("Tool test failed:", error)
  process.exit(1)
})
