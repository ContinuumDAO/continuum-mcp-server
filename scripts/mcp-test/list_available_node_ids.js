const { runTool } = require("./common")

runTool("list_available_node_ids").catch((error) => {
  console.error("Tool test failed:", error)
  process.exit(1)
})
