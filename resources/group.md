# Group Flow in This MCP Server

This server exposes a practical group-creation toolchain around `/newGroupRequest`.

## Primary tools

- `list_available_node_ids`
  - Returns configured nodes with index, IP, node ID, and a marker for the current node.
- `list_management_signing_keys`
  - Returns available EdDSA signing keys (`selectedKeyId`) with current nonce.
- `create_group_request`
  - Creates a new group request from:
    - selected node indexes (or auto-selection),
    - selected signing key ID (or first available key),
    - optional `BrokerArray`.

## Validation rules enforced before submit

- At least 2 nodes are required.
- The current node must be included.
- The selected node set must not match an existing group exactly.

## How it connects to signing

`create_group_request` uses the signing module internally:
1. resolve key + nonce,
2. build canonical request body (`sig: ""`),
3. sign canonical message with EdDSA,
4. submit signed body to `/newGroupRequest`.

Use this as the reference pattern for future group-related tools.
