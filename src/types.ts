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

export type GroupRequestId = z.infer<typeof GroupRequestIdSchema>
export type KeyGenId = z.infer<typeof KeyGenIdSchema>

export type Subscription = z.infer<typeof SubscriptionSchema>
export type NodeConnectivityResult = z.infer<typeof NodeConnectivityResultSchema>
export type ConfiguredNode = z.infer<typeof ConfiguredNodeSchema>
export type MessageToSignResponse = z.infer<typeof MessageToSignResponseSchema>
export type MqttKey = z.infer<typeof MqttKeySchema>
export type ConfigUpdatePlanResponse = z.infer<typeof ConfigUpdatePlanResponseSchema>
export type ConfigUpdateImplementResponse = z.infer<typeof ConfigUpdateImplementResponseSchema>
