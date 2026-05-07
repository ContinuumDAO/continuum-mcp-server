# Signing Model

This server uses a reusable EdDSA management signing flow across signed routes.

## Why this matters

Most management API writes require:

- signer identity
- correct nonce for that signer
- canonical message body
- signature over that exact message

The tools below standardize this process for clients.

## Primary signing tools

- `list_management_keys`
  - Returns authorized EdDSA keys, nonce, local signer mapping, and private-key availability status.
- `build_signed_request_plan`
  - Route-agnostic helper that builds `unsignedBody` and `messageToSign` for a signer index.
- `sign_management_message`
  - Route-agnostic helper that returns EdDSA signature for a message.

## Canonical flow

1. Choose signer index
   - Call `list_management_keys`.
2. Build canonical payload
   - Call `build_signed_request_plan` with `action`, `signerIndex`, and route payload.
3. Sign canonical message
   - Call `sign_management_message` with same `signerIndex` and `messageToSign`.
4. Submit route call
   - Use returned signature in target route body (`sig = signature`).

## Signer index convention

- `0` = bootstrap signer (non-`added_key_N` local key)
- `N >= 1` = `added_key_N`

This lets clients avoid direct file/path details.

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
- Keygen request/agree tools

All use the same signer-index + nonce + canonical message pattern.

## Common failure causes

- signer index does not map to local key file
- key exists on node but private key is missing locally
- signature built from non-canonical message body
- stale nonce due to manually edited body

## Client guidance

- Never mutate `messageToSign` before signing.
- Keep signing and submit steps tightly coupled.
- If signing fails, refresh `list_management_keys` before retry.
