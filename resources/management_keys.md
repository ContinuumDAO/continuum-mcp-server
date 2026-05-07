# Management Keys

This server signs management actions with Ed25519 keys.

## Goal

Maintain usable local signer keys and keep authorized public keys in sync with the node.

## Key tools

- `has_eddsa_management_key`
- `list_management_keys`
- `create_eddsa_management_keypair`
- `add_eddsa_management_key`

## Key lifecycle

1. Check whether any EdDSA management key is configured
   - `has_eddsa_management_key`
2. Inspect current signer state
   - `list_management_keys`
3. Generate a new local keypair when needed
   - `create_eddsa_management_keypair`
4. Add new public key to node authorization set
   - `add_eddsa_management_key`

## `list_management_keys` output use

Each key entry includes:

- `signerIndex`
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

- `signerIndex` of an already-authorized signer
- `newPublicKey` to add

Flow:

1. Resolve signer from `signerIndex`
2. Build canonical body with signer nonce
3. Sign canonical message
4. POST `/addManagementKey`

## Operational checks

- If only bootstrap key exists, ensure its private key is present locally.
- If key files are moved or renamed manually, signer resolution can fail.
- If `localPrivateKeyAvailable` is false, signing tools will fail for that key.

## Recommended client behavior

- Refresh `list_management_keys` before each signed workflow.
- Show signer index and nonce to users when asking for approval.
- Prefer explicit error surfacing (missing private key, unauthorized key, nonce mismatch).
