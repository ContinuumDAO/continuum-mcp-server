# Key Generation

This document covers MPC key generation request lifecycle in this server.

## Purpose

After a group is formed, keygen creates one MPC keypair shared across group members.
That key can later be used in signing workflows.

## Primary tools

- `create_keygen_request`
  - Starts keygen for a group with threshold/key type/msgCheck and signer index.
- `accept_keygen_request`
  - Accepts a pending keygen request as another group member.
- `list_mpc_keygen_requests`
  - Lists keygen requests with filter/pagination.
- `get_mpc_keygen_request_by_id`
  - Gets a specific keygen request.
- `get_mpc_keygen_result_by_id`
  - Gets the keygen result document by request ID.
- `get_mpc_keygen_parent_group_id`
  - Returns the group ID associated with a keygen ID.

## Create keygen flow

1. Ensure group exists and members agreed
   - Validate via group tools before keygen.
2. Choose signing key
   - Use `list_management_keys` and pick `signerIndex`.
3. Create request
   - Call `create_keygen_request` with:
     - `groupId`
     - `threshold`
     - `msgCheck`
     - `keyType`
     - `signerIndex`
4. Peers accept
   - Each member calls `accept_keygen_request`.
5. Track progress
   - Poll `list_mpc_keygen_requests` / `get_mpc_keygen_request_by_id`.
6. Read result
   - Use `get_mpc_keygen_result_by_id` when available.

## Inputs that matter

- `groupId`: target group to generate key for.
- `threshold`: approvals needed are effectively `threshold + 1` for signing stage.
- `msgCheck`: policy mode for downstream signing behavior.
- `keyType`: key curve/type (from allowed key types).

## Signing behavior

Both create and accept tools use the same management signing pattern:

- resolve signer from `signerIndex`
- use signer nonce
- build canonical body (`sig: ""`)
- sign canonical message
- submit signed request

## Status expectations

Keygen requests can move through states like:

- `pending`
- `agree`
- `success`
- `failed`

Exact transitions depend on group member participation and backend processing.

## Client guidance

- Show users request ID immediately after creation.
- Keep request ID available for follow-up accept/query tools.
- Prefer explicit polling over assumptions about completion timing.
