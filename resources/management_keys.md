# Management Keys (EdDSA)

This MCP server uses Ed25519 (EdDSA) keys for agent-side management signing.

## Goal

Create a new local Ed25519 keypair, then add its public key to the node's allowed management keys via `addManagementKey`.

## Required tools

- `create_eddsa_management_keypair`
- `list_management_signing_keys`
- `add_eddsa_management_key`

## Step-by-step

1. **Create local keypair**
   - Call `create_eddsa_management_keypair`.
   - The server auto-generates file name: `added_key_{N}`.
   - Files are written to `KEY_ROOT/management_keys`:
     - private: `added_key_{N}`
     - public: `added_key_{N}.pub`
   - Save returned `fileName` and `publicKey`.

2. **Choose existing signer key**
   - Call `list_management_signing_keys`.
   - Pick one existing signer public key (`selectedSignerPublicKey`) from the response.
   - This key must already be authorized on the node.

3. **Add new key to management API**
   - Call `add_eddsa_management_key` with:
     - `fileName` from step 1
     - `existingAuthorizedSignerPublicKey` from step 2
   - The tool:
     - reads `KEY_ROOT/management_keys/{fileName}.pub`
     - builds canonical signed body
     - signs with selected signer private key
     - posts `/addManagementKey`

## Important checks

- If no management keys exist, agent-side signed requests cannot proceed.
- If exactly one bootstrap key exists, its private key must be present and readable in `KEY_ROOT/management_keys`.
- `existingAuthorizedSignerPublicKey` format is 32-byte hex (64 hex chars).
- This signer key must already be allowed on the node; do not pass the newly created key here.
