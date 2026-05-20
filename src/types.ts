import { z } from "zod"

export const HEX_128_REGEX = /^[a-fA-F0-9]{128}$/
export const HEX_64_REGEX = /^[a-fA-F0-9]{64}$/

export const keyTypes = ["ed25519", "secp256k1"] as const
export type Key = typeof keyTypes[number]
export const KeyTypeSchema = z.enum(keyTypes)

export const msgCheckTypes = ["multi-agree", "tx-check"] as const
export type MsgCheck = typeof msgCheckTypes[number]
export const MsgCheckSchema = z.enum(msgCheckTypes)

export const filterTypes = ["all", "pending", "success", "failed"] as const
export type Filter = typeof filterTypes[number]
export const FilterSchema = z.enum(filterTypes)

export const statusTypes = ["pending", "agree", "failed"] as const
export type Status = typeof statusTypes[number]
export const StatusSchema = z.enum(statusTypes)

export const ECDSAPubKeySchema = z.string().regex(HEX_128_REGEX, "ECDSA public key must be a 128-character hex string")
export const ECDSAAddressSchema = z.string().regex(/^0x[a-fA-F0-9]{40}$/, "EVM address must be 40-character hex string")
export const ECDSASigSchema = z
  .string()
  .regex(/^0x[a-fA-F0-9]{130}$/, "Ethereum signature must be 130 hex characters with 0x prefix")

export const EdDSAPubKeySchema = z.string().regex(HEX_64_REGEX, "Ed25519 public key must be a 64-character hex string")
export const EdDSASigSchema = z
  .string()
  .regex(/^(?:0x)?[a-fA-F0-9]{128}$/, "Ed25519 signature must be a 128-character hex string")

export const PubKeySchema = z.union([ECDSAPubKeySchema, EdDSAPubKeySchema])

export const NodeIdSchema = z.string().regex(HEX_128_REGEX, "Node ID must be a 128-character hex string")
export const GroupIdSchema = z.string().regex(HEX_64_REGEX, "Group ID must be a 64-character hex string")

export const NonceSchema = z.number().int().nonnegative()
export const ManagementSigSchema = EdDSASigSchema

/** Resolved EdDSA management key included in signed-tool outputs. */
export const SelectedSigningKeySchema = z.object({
  id: z.string(),
  kind: z.literal("EdDSA"),
  value: z.string(),
  nonce: NonceSchema,
  label: z.string().optional(),
})

export const GroupRequestIdSchema = z.string().regex(/^NewGroup[a-f0-9]{25}$/, "Group ID must be in the form: NewGroup202603271129339998910db0b")
export const KeyGenIdSchema = z.string().regex(/^KeyGen[a-f0-9]{25}$/, "KeyGen ID must be in the form KeyGen20260111003720999cf104d0f")

export const LogsSchema = z.object({
  count: z.number(),
  cutoffTime: z.string(),
  hours: z.number(),
  logs: z.array(
    z.object({
      level: z.string(),
      msg: z.string(),
      time: z.string(),
    }),
  ),
})

export const MessageToSignResponseSchema = z.object({
  messageToSign: z.string(),
  nodeMgtKey: ECDSAAddressSchema,
  currentNonce: NonceSchema,
  signingInstructions: z.string(),
  example: z.object({
    javascript: z.string(),
    web3js: z.string(),
  }),
})

export const MqttKeySchema = z.object({
  path: z.string(),
  caCertPem: z.string(),
})

export const ConfigUpdatePlanResponseSchema = z.object({
  configsPath: z.string(),
  planTempPath: z.string(),
  plannedYaml: z.string(),
  plannedShaMessage: z.string(),
  preview: z.record(z.string(), z.unknown()),
})

export const ConfigUpdateImplementResponseSchema = z.object({
  message: z.string().optional(),
  composeWarning: z.string().optional(),
}).passthrough()

export const MachineInfoSchema = z.object({
  cpu: z.object({ cores: z.number(), usagePercent: z.number() }),
  memory: z.object({ totalGB: z.string(), usedGB: z.string(), availableGB: z.string() }),
  disk: z.object({ totalGB: z.string(), usedGB: z.string(), availableGB: z.string() }),
  os: z.object({ version: z.string().describe("Operating System version") }),
  cpuInfo: z.object({
    version: z.string().describe("CPU make and model"),
    physicalCores: z.number(),
    logicalCores: z.number(),
  }),
  vps: z.object({ isVPS: z.boolean(), provider: z.string().describe("VPS provider") }),
  countryCode: z.string().regex(/^([A-Za-z]{2})?$/, "Country code must be empty or 2 letters").describe("Two-letter country code, or empty string"),
})

export const GroupRequestSchema = z.object({
  RequestId: GroupRequestIdSchema,
  NewGroupDataPb: z.object({
    GroupId: GroupIdSchema,
    KeyList: z.array(NodeIdSchema),
    Addresses: z.array(z.string()),
    SigList: z.record(NodeIdSchema, ManagementSigSchema),
    BrokerArray: z.array(z.string()),
  }),
  Timepoint: z.string(),
  status: StatusSchema,
  originator: NodeIdSchema,
})

export const GroupResultSchema = z.object({
  requestid: z.string(),
  GroupId: GroupIdSchema,
  KeyList: z.array(NodeIdSchema),
  Addresses: z.array(z.string()),
  SigList: z.record(NodeIdSchema, ManagementSigSchema),
  BrokerArray: z.array(z.string()),
  timepoint: z.string(),
  originator: NodeIdSchema.optional(),
})

export const GroupSchema = {
  groupId: GroupIdSchema,
  keyGens: [
    {
      requestid: KeyGenIdSchema,
      pubkeyhex: PubKeySchema,
      keylist: z.array(NodeIdSchema),
      timepoint: z.string(),
      ethereumaddress: ECDSAAddressSchema,
      groupid: GroupIdSchema,
      threshold: z.number().nonnegative().describe("Threshold for this KeyGen; threshold + 1 nodes required to generate signature"),
      keytype: KeyTypeSchema,
    },
  ],
}

export const SubscriptionSchema = z.object({
  groupId: z.union([GroupIdSchema, z.string()]),
  brokers: z.array(z.string()),
  topics: z.array(z.string()),
  clientId: NodeIdSchema,
  isConnected: z.boolean(),
})

export const NodeConnectivityResultSchema = z.object({
  nodeKey: NodeIdSchema,
  responded: z.boolean(),
  latencyMs: z.number().optional(),
  speed: z.string().optional(),
  error: z.string().optional(),
})

export const ConfiguredNodeSchema = z.object({
  address: z.string(),
  available: z.boolean(),
  publicKey: NodeIdSchema,
})

/** Management HTTP paths for known-address (address book) registry operations. */
export const ADDRESS_BOOK_REGISTRY_API_PATHS = {
  add_to_address_book_registry: "/addKnownAddress",
  remove_from_address_book_registry: "/removeKnownAddress",
  get_address_book_registry: "/getKnownAddresses",
} as const

export type AddressBookRegistryOperationId = keyof typeof ADDRESS_BOOK_REGISTRY_API_PATHS

/** `GET /getKnownAddresses` query parameters. */
export const GetKnownAddressesQuerySchema = z.object({
  chain_type: z.string().min(1).optional(),
  chain_id: z.string().min(1).optional(),
  is_contract: z.enum(["0", "1"]).optional(),
})

/** One known address entry as returned under each chain type key in `GET /getKnownAddresses` `data`. */
export const KnownAddressEntrySchema = z.object({
  address: z.string(),
  name: z.string().optional(),
  chainIds: z.array(z.string()),
  isContract: z.boolean(),
  updatedAt: z.string(),
})

/**
 * `GET /getKnownAddresses` success `data`: chain type → list of entries.
 * Uses catchall object (not z.record) so MCP SDK output validation accepts it as an object schema.
 */
export const GetKnownAddressesDataSchema = z.object({}).catchall(z.array(KnownAddressEntrySchema))

/** Supported token standards for local token registry (per API). */
export const tokenTypeValues = ["ERC20", "ERC721", "CTMERC20", "CTMRWA1"] as const
export type TokenType = (typeof tokenTypeValues)[number]
export const TokenTypeSchema = z.enum(tokenTypeValues)

/** Management HTTP paths for local token registry operations. */
export const TOKEN_REGISTRY_API_PATHS = {
  add_to_token_registry: "/addToken",
  remove_from_token_registry: "/removeToken",
  get_token_registry: "/getTokens",
} as const

export type TokenRegistryOperationId = keyof typeof TOKEN_REGISTRY_API_PATHS

/** `GET /getTokens` query parameters. */
export const GetTokenRegistryQuerySchema = z.object({
  chainType: z.string().min(1).optional(),
  chain_id: z.string().min(1).optional(),
})

/** Contract object for `POST /addToken` (fields vary by tokenType). */
export const TokenContractInputSchema = z
  .object({
    contractAddress: z.string().min(1),
    name: z.string().optional(),
    symbol: z.string().optional(),
    symbolURL: z.string().optional(),
    decimals: z.number().int().nonnegative().optional(),
    tokenURI: z.string().optional(),
    tokenId: z.string().optional(),
  })
  .passthrough()

const TokenRegistryContractSchema = z.object({
  contractAddress: z.string(),
}).passthrough()

const TokenRegistryTypeBucketSchema = z
  .object({
    contracts: z.array(TokenRegistryContractSchema).optional(),
  })
  .passthrough()

/** One chain's token config: `chainId` plus dynamic token-type keys (ERC20, ERC721, …). */
export const TokenRegistryChainConfigSchema = z
  .object({
    chainId: z.string(),
  })
  .catchall(z.union([TokenRegistryTypeBucketSchema, z.string()]))

/**
 * `GET /getTokens` success `data`: chain type → list of per-chainId configs.
 * Uses catchall so MCP SDK output validation accepts the object schema.
 */
export const GetTokenRegistryDataSchema = z.object({}).catchall(z.array(TokenRegistryChainConfigSchema))

/** Default Get Sig fee tier for stored chain configs. */
export const defaultGetSigFeeSpeedValues = ["slow", "normal", "fast"] as const
export type DefaultGetSigFeeSpeed = (typeof defaultGetSigFeeSpeedValues)[number]
export const DefaultGetSigFeeSpeedSchema = z.enum(defaultGetSigFeeSpeedValues)

/** Management HTTP paths for local chain (network) registry operations. */
export const CHAIN_REGISTRY_API_PATHS = {
  add_to_chain_registry: "/postChainDetails",
  remove_from_chain_registry: "/removeChainDetails",
  get_chain_registry: "/getChainDetails",
} as const

export type ChainRegistryOperationId = keyof typeof CHAIN_REGISTRY_API_PATHS

/** `GET /getChainDetails` query parameters. */
export const GetChainRegistryQuerySchema = z.object({
  chain_id: z.string().min(1).optional(),
})

/** One stored chain config (`GET /getChainDetails` item). */
export const ChainRegistryEntrySchema = z.object({
  chainId: z.string(),
  chainName: z.string(),
  rpcGateway: z.string(),
  explorer: z.string().optional(),
  legacy: z.boolean(),
  testnet: z.boolean(),
  gasName: z.string().optional(),
  gasLimit: z.number().optional(),
  baseFee: z.number().nullable().optional(),
  priorityFee: z.number().nullable().optional(),
  baseFeeMultiplier: z.number().optional(),
  gasMultiplier: z.number().optional(),
  gasPrice: z.number().optional(),
  defaultGetSigFeeSpeed: DefaultGetSigFeeSpeedSchema.optional(),
  updatedAt: z.string().optional(),
})

/**
 * Normalized `GET /getChainDetails` tool output (API returns one object or an array).
 * Wrapped as `{ chains }` so MCP SDK output validation accepts an object schema.
 */
export const GetChainRegistryDataSchema = z.object({
  chains: z.array(ChainRegistryEntrySchema),
})

export type Logs = z.infer<typeof LogsSchema>
export type MachineInfo = z.infer<typeof MachineInfoSchema>

export type GroupRequest = z.infer<typeof GroupRequestSchema>
export type GroupResult = z.infer<typeof GroupResultSchema>

export type ECDSAPubKey = z.infer<typeof ECDSAPubKeySchema>
export type ECDSAAddress = z.infer<typeof ECDSAAddressSchema>
export type ECDSASig = z.infer<typeof ECDSASigSchema>

export type EdDSAPubKey = z.infer<typeof EdDSAPubKeySchema>
export type EdDSASig = z.infer<typeof EdDSASigSchema>

export type NodeId = z.infer<typeof NodeIdSchema>
export type GroupId = z.infer<typeof GroupIdSchema>
export type Nonce = z.infer<typeof NonceSchema>
export type Sig = z.infer<typeof ManagementSigSchema>
export type SelectedSigningKey = z.infer<typeof SelectedSigningKeySchema>

export type GroupRequestId = z.infer<typeof GroupRequestIdSchema>
export type KeyGenId = z.infer<typeof KeyGenIdSchema>

export type Subscription = z.infer<typeof SubscriptionSchema>
export type NodeConnectivityResult = z.infer<typeof NodeConnectivityResultSchema>
export type ConfiguredNode = z.infer<typeof ConfiguredNodeSchema>
export type KnownAddressEntry = z.infer<typeof KnownAddressEntrySchema>
export type GetKnownAddressesData = z.infer<typeof GetKnownAddressesDataSchema>
export type GetKnownAddressesQuery = z.infer<typeof GetKnownAddressesQuerySchema>
export type TokenContractInput = z.infer<typeof TokenContractInputSchema>
export type GetTokenRegistryData = z.infer<typeof GetTokenRegistryDataSchema>
export type GetTokenRegistryQuery = z.infer<typeof GetTokenRegistryQuerySchema>
export type ChainRegistryEntry = z.infer<typeof ChainRegistryEntrySchema>
export type GetChainRegistryData = z.infer<typeof GetChainRegistryDataSchema>
export type GetChainRegistryQuery = z.infer<typeof GetChainRegistryQuerySchema>
export type MessageToSignResponse = z.infer<typeof MessageToSignResponseSchema>
export type MqttKey = z.infer<typeof MqttKeySchema>
export type ConfigUpdatePlanResponse = z.infer<typeof ConfigUpdatePlanResponseSchema>
export type ConfigUpdateImplementResponse = z.infer<typeof ConfigUpdateImplementResponseSchema>
