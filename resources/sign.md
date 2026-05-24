# Signing Model

This server uses **in-route EdDSA management signing**. Clients call one route tool per action; the MCP server resolves the signer, builds the canonical body, signs, and POSTs internally.

## Do not orchestrate signing manually

The following tools are **not** exposed to MCP clients:

- `build_signed_request_plan` (removed)
- `sign_management_message` (removed)

If a client or model attempts to use them, restart the MCP server after upgrading. Use the route-specific tools listed below instead.

## Management key tools (signer setup only)

- `list_management_keys` — authorized EdDSA keys, nonce, local file match, private-key availability, preferred signer
- `set_preferred_management_key` — set default signer (signs internally)
- `get_preferred_management_key` — read current preferred signer
- `create_eddsa_management_keypair` — local key files only (no node authorization)
- `add_eddsa_management_key` — authorize a new server-generated Ed25519 key on the node (signs internally)

## Signed route tools (one call each)

| Action | Tool |
|--------|------|
| Create group | `create_group_request` |
| Agree to group | `accept_group_request` |
| Start keygen | `create_mpc_keygen_request` |
| Agree to keygen | `accept_mpc_keygen_request` |
| Add address book entry | `add_to_address_book_registry` |
| Remove address book entry | `remove_from_address_book_registry` |
| Add saved token | `add_to_token_registry` |
| Remove saved token | `remove_from_token_registry` |
| Add saved chain config | `add_to_chain_registry` |
| Remove saved chain config | `remove_from_chain_registry` |

Read-only registry: `get_address_book_registry`, `get_token_registry`, `get_chain_registry` (no signing).

## Signer selection (server-side)

1. If a preferred signer is set: it must be in allowed management keys and have a usable local keypair under `KEY_ROOT/management_keys`.
2. Otherwise: the server uses the first allowed key with a usable local private key.
3. If none qualify: the tool fails with an explicit error.

## Internal signing sequence

Every signed route tool uses the same server implementation:

1. `fetchManagementKeyOptions`
2. `resolveManagementSigningKeyOption`
3. Build unsigned body with `{ nonce, clientSig: "", nodeKey }` plus route fields (`buildManagementPostBody`)
4. `messageToSignManagementBody` — canonical JSON with `clientSig` cleared
5. `signManagementMessage`
6. POST with `clientSig` set on the same JSON body

**Exceptions (not the standard JSON management envelope):**

- `/multiSignRequest` — client signing: `{ ...bodyForSign, clientSig, signedMessage }`
- `/configUpdateImplement` — `nodeKey` + opaque `signedMessage` hash line + `clientSig`
- `/postMSQTTKey` — sign PEM bytes directly; body has `nodeKey`, `caCertPem`, `clientSig`
- `/addManagementKey`, `/removeManagementKey` — Ethereum NodeMgtKey may use `signedMessage` + EIP-191 `clientSig` instead of pure Ed25519 JSON signing

Clients must not replicate or split this flow.

## Typical workflow

1. (Optional) `set_preferred_management_key`
2. Call the target route tool with business arguments only (e.g. `nodeIds`, `groupId`, `chainType` + `address`)
3. Use list/get tools to verify results

## Common failure causes

- Preferred signer not present locally
- No allowed key has a usable private key
- Stale nonce from manually edited bodies (should not happen when using route tools only)
- Unparseable private key material

## Client guidance

- One route tool per signed operation.
- Refresh `list_management_keys` if signing fails before retrying.
- Load `overview.md` for the full operator loop.
