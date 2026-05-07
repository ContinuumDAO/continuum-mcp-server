import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js"
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js"
import { z } from "zod"
import {
  GroupIdSchema,
  LogsSchema,
  MachineInfoSchema,
  NodeConnectivityResultSchema,
  NodeIdSchema,
  SubscriptionSchema,
  type GroupId,
  type Logs,
  type NodeConnectivityResult,
  type Subscription,
} from "./types.js"

type QueryParamValue = string | number | boolean | null | undefined
type QueryParams = Record<string, QueryParamValue>
type RequestTarget = { host?: string; port?: string | number }

type NodeToolsDeps = {
  server: McpServer
  mgtGET: <T>(path: string, params?: string | URLSearchParams | QueryParams, target?: RequestTarget) => Promise<T>
}

export function registerNodeTools({ server, mgtGET }: NodeToolsDeps): void {
  server.registerTool(
    "version",
    {
      description: "Get current node version and version date",
      outputSchema: z.object({
        version: z.string(),
        versionDate: z.string(),
      }),
    },
    async (): Promise<CallToolResult> => {
      const output = await mgtGET<{ version: string; versionDate: string }>("/version")
      return {
        content: [{ type: "text", text: JSON.stringify(output) }],
        structuredContent: output,
      }
    },
  )

  server.registerTool(
    "get_machine_info",
    {
      description: "Get machine information (CPU, memory, disk, OS, VPS detection)",
      inputSchema: z.object({
        refresh: z.boolean().optional(),
      }),
      outputSchema: MachineInfoSchema,
    },
    async ({ refresh }: { refresh?: boolean }): Promise<CallToolResult> => {
      const params = new URLSearchParams()
      if (refresh !== undefined) {
        params.append("refresh", String(refresh))
      }
      const output = await mgtGET<z.infer<typeof MachineInfoSchema>>("/getMachineInfo", params)
      return {
        content: [{ type: "text", text: JSON.stringify(output) }],
        structuredContent: output,
      }
    },
  )

  server.registerTool(
    "get_node_id",
    {
      description: "Get this node's public key (node ID)",
      outputSchema: z.object({ nodeId: NodeIdSchema }),
    },
    async (): Promise<CallToolResult> => {
      const nodeId = await mgtGET<string>("/getNodeKey")
      return {
        content: [{ type: "text", text: JSON.stringify({ nodeId }) }],
        structuredContent: { nodeId },
      }
    },
  )

  server.registerTool(
    "get_success_rate",
    {
      description: "Get keygen/sign success-rate statistics (optional hours window)",
      inputSchema: z.object({ hours: z.number().int().nonnegative().optional() }),
      outputSchema: z.object({
        keygen: z.object({
          total: z.number(),
          success: z.number(),
          failed: z.number(),
          successRate: z.number(),
        }),
        signing: z.object({
          total: z.number(),
          success: z.number(),
          failed: z.number(),
          successRate: z.number(),
        }),
      }),
    },
    async ({ hours }: { hours?: number }): Promise<CallToolResult> => {
      const params = new URLSearchParams()
      if (hours !== undefined) {
        params.append("hours", hours.toString())
      }
      const output = await mgtGET<{
        keygen: { total: number; success: number; failed: number; successRate: number }
        signing: { total: number; success: number; failed: number; successRate: number }
      }>("/getSuccessRate", params)
      return {
        content: [{ type: "text", text: JSON.stringify(output) }],
        structuredContent: output,
      }
    },
  )

  server.registerTool(
    "get_subscriptions",
    {
      description: "Get current MQTT subscription information",
      outputSchema: z.object({ subscriptions: z.array(SubscriptionSchema) }),
    },
    async (): Promise<CallToolResult> => {
      const subscriptions = await mgtGET<Subscription[]>("/getSubscriptions")
      return {
        content: [{ type: "text", text: JSON.stringify({ subscriptions }) }],
        structuredContent: { subscriptions },
      }
    },
  )

  server.registerTool(
    "health",
    {
      description: "Get comprehensive node health status",
      outputSchema: z.object({
        status: z.string(),
        timestamp: z.number(),
        mqtt: z.object({
          connected: z.boolean(),
          channels: z.number(),
          errors: z.array(z.string()),
          warnings: z.array(z.string()),
        }),
        mongodb: z.object({
          connected: z.boolean(),
          error: z.string(),
        }),
        subscriptions: z.array(SubscriptionSchema),
      }),
    },
    async (): Promise<CallToolResult> => {
      const output = await mgtGET<{
        status: string
        timestamp: number
        mqtt: { connected: boolean; channels: number; errors: string[]; warnings: string[] }
        mongodb: { connected: boolean; error: string }
        subscriptions: Subscription[]
      }>("/health")
      return {
        content: [{ type: "text", text: JSON.stringify(output) }],
        structuredContent: output,
      }
    },
  )

  server.registerTool(
    "connectivity_health",
    {
      description: "Check per-node connectivity and latency by group",
      inputSchema: z.object({
        groupId: GroupIdSchema.optional(),
        timeout: z.number().int().positive().optional(),
      }),
      outputSchema: z.object({
        groups: z.array(
          z.object({
            groupId: GroupIdSchema,
            nodeCount: z.number(),
            results: z.array(NodeConnectivityResultSchema),
            summary: z.object({
              very_good: z.number(),
              good: z.number(),
              medium: z.number(),
              slow: z.number(),
              very_slow: z.number(),
              no_response: z.number(),
            }),
          }),
        ),
      }),
    },
    async ({ groupId, timeout }: { groupId?: GroupId; timeout?: number }): Promise<CallToolResult> => {
      const params = new URLSearchParams()
      if (groupId !== undefined) {
        params.append("groupId", groupId)
      }
      if (timeout !== undefined) {
        params.append("timeout", timeout.toString())
      }

      const groups = await mgtGET<{
        groupId: GroupId
        nodeCount: number
        results: NodeConnectivityResult[]
        summary: { very_good: number; good: number; medium: number; slow: number; very_slow: number; no_response: number }
      }[]>("/connectivityHealth", params)
      return {
        content: [{ type: "text", text: JSON.stringify({ groups }) }],
        structuredContent: { groups },
      }
    },
  )

  server.registerTool(
    "logs",
    {
      description: "Get recent log entries for a time window in hours",
      inputSchema: z.object({ hours: z.number().positive().optional() }),
      outputSchema: LogsSchema,
    },
    async ({ hours }: { hours?: number }): Promise<CallToolResult> => {
      const params = new URLSearchParams()
      if (hours !== undefined) {
        params.append("hours", hours.toString())
      }
      const output = await mgtGET<Logs>("/getLogs", params)
      return {
        content: [{ type: "text", text: JSON.stringify(output) }],
        structuredContent: output,
      }
    },
  )
}
