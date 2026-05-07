# Management Keys

This server signs management actions with Ed25519 keys.

## Goal

Maintain usable local signer keys and keep authorized public keys in sync with the node.

## Key tools

- `has_eddsa_management_key`
- `list_management_keys`
- `create_eddsa_management_keypair`
- `add_eddsa_management_key`
- `set_preferred_management_key`
- `get_preferred_management_key`

## Key lifecycle

1. Check whether any EdDSA management key is configured
   - `has_eddsa_management_key`
2. Inspect current signer state
   - `list_management_keys`
3. Generate a new local keypair when needed
   - `create_eddsa_management_keypair`
4. Add new public key to node authorization set
   - `add_eddsa_management_key`
5. Set default signer for all signed tools
   - `set_preferred_management_key`

## `list_management_keys` output use

Each key entry includes:

- `preferredSigner` (top-level in response)
- `localFileName`
- `value` (public key)
- `nonce`
- `localPrivateKeyAvailable`
- `localPrivateKeyError` (if missing/unusable)

Use this as the source of truth before any signed operation.

## Creating a keypair

`create_eddsa_management_keypair`:

- writes files under `KEY_ROOT/management_keys`
- labels file as `added_key_{N}`
- returns generated public key and file paths
- does not automatically authorize the new key

## Authorizing a new key

`add_eddsa_management_key` requires:

- `newPublicKey` to add (hex or OpenSSH public key)

Flow:

1. Resolve signer from preferred signer (`/getPreferredSigner`) or fallback local allowed key
2. Build canonical body with `nodeKey`, `Nonce`, `Sig: ""`, and route fields
3. Sign canonical message
4. POST `/addManagementKey`

## Preferred signer rules

`set_preferred_management_key` enforces:

1. Requested public key is already in allowed management keys.
2. Matching `.pub` exists in `KEY_ROOT/management_keys`.
3. Matching private key file exists and is readable.
4. Private key derives to the same Ed25519 public key.

If any check fails, tool returns a clear error and does not call `/setPreferredSigner`.

## Operational checks

- If only bootstrap key exists, ensure its private key is present locally.
- If preferred signer is set to a key not available locally, signed tools will fail.
- If key files are moved or renamed manually, local key matching can fail.
- If `localPrivateKeyAvailable` is false, signing tools will fail for that key.

## Recommended client behavior

- Refresh `list_management_keys` before each signed workflow.
- Show preferred signer and nonce when asking for approval.
- Prefer explicit error surfacing (missing private key, unauthorized key, nonce mismatch, parse errors).
