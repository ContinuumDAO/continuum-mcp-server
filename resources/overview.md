# Continuum MCP Server Overview

This MCP server is a thin orchestration layer over the node management API.

## What the MCP host should know

- The server is tool-first and route-oriented.
- Most business logic is:
  - fetch/validate inputs,
  - build canonical request payloads,
  - sign with configured EdDSA management keys,
  - call management API routes.
- Signing is modular and reusable across routes (not tied to one endpoint).

## Core operational modules

- **Node discovery**: list available nodes and map IP -> node ID.
- **Signing**: key listing, plan generation, canonical message signing.
- **Route execution**: endpoint-specific tools (for example, group creation).

## Recommended client orchestration style

1. Discover options (`list_available_node_ids`, signing keys).
2. Select or provide concrete inputs.
3. Build/sign as needed.
4. Execute target route tool.

Keep prompts short and structured; rely on tool outputs as source of truth.
