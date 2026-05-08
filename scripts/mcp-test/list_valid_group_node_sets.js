const { runTool } = require("./common")

runTool("list_valid_group_node_sets").catch((error) => {
  console.error("Tool test failed:", error)
  process.exit(1)
})
