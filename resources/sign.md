# Signing in This MCP Server

This server uses a modular signing flow so signature logic can be reused across routes (not just group creation).

## Available signing tools

- `list_management_signing_keys`
  - Returns all usable **EdDSA (Ed25519)** management keys with stable `id` and current `nonce`.
- `build_signed_request_plan`
  - Route-agnostic planner. Given an `action`, `selectedKeyId`, and unsigned `payload`, it returns:
    - `unsignedBody` (with `nonce` filled and `sig: ""`)
    - `messageToSign` (canonical JSON string)
    - selected key metadata
- `sign_management_message`
  - Route-agnostic signer. Given `selectedKeyId` + `message`, returns an EdDSA signature.

## Practical flow for any signed route

1. Choose a signing key via `list_management_signing_keys`.
2. Build canonical body/message via `build_signed_request_plan`.
3. Sign the message via `sign_management_message`.
4. Submit the target route with the same body plus `sig = signature`.

## Example: `create_group_request`

`create_group_request` applies the same pattern internally:
- validates/selects node set,
- builds canonical request body with nonce,
- signs with selected EdDSA management key,
- posts `/newGroupRequest`.

Use this same 4-step pattern when adding future tools that require management signatures.
