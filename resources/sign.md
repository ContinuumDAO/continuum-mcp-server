# Signing Model

This server uses an in-route EdDSA management signing flow across signed routes.

## Why this matters

Most management API writes require:

- signer identity
- correct nonce for that signer
- canonical message body
- signature over that exact message

Each route tool performs its own signing internally so clients only call one tool per action.

## Primary signing tools

- `list_management_keys`
  - Returns authorized EdDSA keys, nonce, local file match, private-key availability, and current preferred signer.
- `set_preferred_management_key`
  - Sets the default signer via `/setPreferredSigner` after strict local keypair validation.
- `get_preferred_management_key`
  - Reads current preferred signer from `/getPreferredSigner`.

## Optional low-level helpers (management)

These are registered alongside management key tools for debugging or custom flows:

- `build_signed_request_plan` — canonical unsigned body and `messageToSign` for a payload.
- `sign_management_message` — sign a canonical message with the resolved management signer.

Prefer calling the route-specific tools directly; they perform the same signing internally.

## Canonical flow

1. (Optional) set preferred signer
   - Call `set_preferred_management_key` with `publicKeyHex`.
2. Call the target route tool directly
   - Example: `create_group_request`, `accept_group_request`, `create_mpc_keygen_request`, `add_eddsa_management_key`.
3. Route tool handles signing internally
   - Resolve signer, build canonical payload, sign, and submit.

## Signer selection behavior

- If preferred signer is set:
  - it must be in allowed management keys, and
  - it must have a matching usable local keypair in `KEY_ROOT/management_keys`.
- If preferred signer is not set:
  - server iterates allowed keys and picks first key with usable local private key.
- If no usable local key exists for any allowed key:
  - signed operations fail with explicit error.

## Key format handling

Server supports local private key material in these forms:

- OpenSSH private key block
- PEM PKCS#8 private key
- DER PKCS#8 hex

Public key normalization to 32-byte hex is applied where required by API calls.

## Typical route usage

- Group creation: `create_group_request`
- Group agree: `accept_group_request`
- Key add: `add_eddsa_management_key`
- Keygen request/agree: `create_mpc_keygen_request`, `accept_mpc_keygen_request`

All use the same preferred-signer + canonical message pattern with base fields:

- `nodeKey`
- `Nonce`
- `Sig: ""` (before signing)

## Common failure causes

- preferred signer does not exist locally
- preferred signer has no matching private key
- preferred signer private key exists but is unreadable/unparseable
- no preferred signer and no allowed key has usable local private key
- signature built from non-canonical message body
- stale nonce due to manually edited body

## Client guidance

- Call one route tool per operation; avoid manual multi-tool signing orchestration.
- If signing fails, refresh `list_management_keys` before retry.
