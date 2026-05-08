# Continuum MCP Server Overview

This server helps an MCP client operate a Continuum node through safe, structured tools over the management API.

## MCP convention (prompt vs resource)

- MCP servers do not typically force a universal "system prompt" into every client session.
- The standard pattern is to expose guidance as MCP resources and let the client load them at startup.
- For this server, `overview.md` is the high-level onboarding resource, while other resource files contain step-specific detail.

## What this server is for

- Discover node state and health (`version`, `get_machine_info`, `get_node_id`, `health`, `connectivity_health`, `logs`).
- Manage EdDSA management keys and signer selection (`list_management_keys`, `create_eddsa_management_keypair`, `add_eddsa_management_key`, `set_preferred_management_key`, `get_preferred_management_key`).
- Coordinate group lifecycle (`list_available_node_ids`, `list_valid_group_node_sets`, `create_group_request`, `accept_group_request`).
- Coordinate MPC key generation (`create_mpc_keygen_request`, `accept_mpc_keygen_request`, keygen query tools).
- Provide signed management route tools that handle signing internally.

## Common node-operator loop

1. Ensure management signing is available.
   - Use `list_management_keys`.
   - If needed: generate and add a key via `create_eddsa_management_keypair` + `add_eddsa_management_key`.
   - Optionally pin default signer via `set_preferred_management_key`.
   - If EdDSA is not configured yet, configure bootstrap management key material via node setup/browser flow.

2. Form a group with other nodes (unanimous agreement required).
   - Discover candidates with `list_available_node_ids` or `list_valid_group_node_sets`.
   - Submit with `create_group_request`.
   - Other members confirm with `accept_group_request` (originator is auto-agreed).

3. Generate one or more MPC keys in that group (unanimous agreement required).
   - Start with `create_mpc_keygen_request`.
   - Other members confirm with `accept_mpc_keygen_request` (originator is auto-agreed).

4. Use generated MPC key(s) for transaction signing workflows.
   - Members propose sign requests.
   - At least `gate` members must agree/sign for MPC SIGNATURE generation (with API threshold = gate - 1). This gate applies to sign requests only; group creation and keygen creation require all requested members to agree.

5. Repeat for additional groups, keys, and signing operations.

## Client orchestration guidance

- Keep user interaction simple: fetch options first, then ask for concrete selection, then execute.
- Prefer explicit tool inputs for business data (e.g., concrete node IDs), not signer index.
- For signed tools, rely on preferred signer (or automatic local-key fallback) rather than requesting signer selection each time.
- Use one route tool per signed action; do not split into planning/sign helper steps.
- Treat tool output as source of truth; avoid guessing route payload shape.
- Load detailed docs by topic:
  - signing: `sign.md`
  - groups: `group.md`
  - management keys: `management_keys.md`
