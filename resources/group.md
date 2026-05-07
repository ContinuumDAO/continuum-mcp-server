# Group Operations

This document explains how to create and manage MPC groups with this server.

## Purpose

Groups define which node IDs can participate in key generation and signing.
A valid group must include your node and at least one peer.

## Primary tools

- `list_available_node_ids`
  - Lists configured nodes with index, IP, node ID, and self marker.
- `list_valid_group_node_sets`
  - Returns currently valid 2-node sets that include your node and do not already exist.
- `create_group_request`
  - Creates a group request from explicit `nodeIds` using preferred signer (or fallback signer).
- `list_group_requests`
  - Lists incoming and historical group requests with optional filters.
- `get_group_request_by_id`
  - Fetches one group request by request ID.
- `accept_group_request`
  - Accepts a pending group request using preferred signer (or fallback signer).
- `list_group_results`
  - Lists formed groups/results (with endpoint compatibility normalization).
- `get_group_result_by_id`
  - Gets a single group result by request ID or group ID.

## Create group flow

1. Discover node options
   - Call `list_available_node_ids`.
2. Ask user which nodes to include
   - Optionally guide with `list_valid_group_node_sets`.
3. (Optional) set preferred signer
   - Call `set_preferred_management_key`.
4. Submit group request
   - Call `create_group_request` with `nodeIds`.
5. Group peers accept
   - Other members call `accept_group_request`.
6. Verify completion
   - Use `list_group_results` or `get_group_result_by_id`.

## Validation rules enforced

- `nodeIds` must be a subset of configured node IDs.
- At least 2 unique node IDs are required.
- Originator node ID must be included.
- Duplicate node IDs are normalized away before submit.
- Existing identical group set is rejected.

## Signing behavior

`create_group_request` and `accept_group_request` use the same signing model:

- resolve signer from preferred signer (or fallback local allowed signer)
- use signer's current nonce
- build canonical body with `nodeKey`, `Nonce`, `Sig: ""`
- sign message with local EdDSA private key
- submit signed body to management API

## Notes for MCP clients

- Prompt users for concrete node-ID choices, not free text.
- Treat tool responses as source of truth for IDs and status.
- Prefer `get_*_by_id` tools when the user references a specific request.
