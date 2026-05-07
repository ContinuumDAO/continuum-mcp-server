const { runTool } = require("./common")

runTool("list_group_requests", {}).catch((error) => {
  console.error("Tool test failed:", error)
  process.exit(1)
})
