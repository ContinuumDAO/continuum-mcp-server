import type { Nonce, Sig } from "./types.js"
import { messageToSignManagementBody, withManagementClientSig } from "./management-post-sig.js"

export type ManagementKeyOption = {
  id: string
  kind: "EdDSA"
  value: string
  nonce: Nonce
  label?: string
}

export type ManagementSigningFlowDeps = {
  fetchManagementKeyOptions: () => Promise<ManagementKeyOption[]>
  resolveManagementSigningKeyOption: (keyOptions: ManagementKeyOption[]) => Promise<ManagementKeyOption>
  buildManagementSigningMessage: (bodyWithEmptySig: Record<string, unknown>) => string
  signManagementMessage: (option: ManagementKeyOption, message: string) => Promise<Sig>
}

export type SignedManagementRequest = {
  selectedSigningKey: ManagementKeyOption
  unsignedBody: Record<string, unknown>
  signingMessage: string
  signature: Sig
  body: Record<string, unknown>
}

/**
 * Appended to signed route tool descriptions so MCP clients invoke one tool only.
 * Manual signing / request-plan tools are not exposed.
 */
export const SIGNED_ROUTE_TOOL_NOTE =
  " Signs and submits internally using the preferred management signer, or the first allowed key with a usable local private key if none is set. Do not orchestrate signing manually."

/**
 * Canonical management signing sequence for route tools:
 * fetchManagementKeyOptions → resolveManagementSigningKeyOption →
 * buildManagementSigningMessage → signManagementMessage → withManagementClientSig.
 *
 * `buildUnsignedBody` should return a full POST body including `{ nonce, clientSig: "", nodeKey }`
 * (use `buildManagementPostBody` from management-post-sig.ts).
 */
export async function prepareSignedManagementRequest(
  deps: ManagementSigningFlowDeps,
  buildUnsignedBody: (ctx: { selectedSigningKey: ManagementKeyOption }) =>
    | Record<string, unknown>
    | Promise<Record<string, unknown>>,
): Promise<SignedManagementRequest> {
  const keyOptions = await deps.fetchManagementKeyOptions()
  const selectedSigningKey = await deps.resolveManagementSigningKeyOption(keyOptions)
  const unsignedBody = await buildUnsignedBody({ selectedSigningKey })
  const signingMessage = deps.buildManagementSigningMessage(unsignedBody)
  const signature = await deps.signManagementMessage(selectedSigningKey, signingMessage)
  return {
    selectedSigningKey,
    unsignedBody,
    signingMessage,
    signature,
    body: withManagementClientSig(unsignedBody, signature),
  }
}
