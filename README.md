# Continuum Model Context Protocol

## Requirements

1. **Resources:** Can access the Management API via GET operations that expose
node details, for example node key, pending group/keygen/sign requests, etc.
Can also access messages via the node messaging API, and context from previous
threads and conversations.
2. **Tools:** Can make requests to the Management API via POST operations,
allowing the agent to create group/keygen/sign requests and create/respond to
message threads.
3. **Prompts:**: A system prompt telling the agent its purpose, what it can do,
how the basic operational loop operates.

## Lifecycle

### **Phase 1:** Initialization

#### Initialization Lifecycle

- Client sends `initialize` request to the server. Before the server responds,
the client should *ONLY* send pings.
- Server sends `initialize` response. Before the client announces `initialized`,
the server should *ONLY* send pings and logging.
- Client sends `intialized` notification. Proceed to
[Phase 2: Operation](#phase-2-operation).

#### Version

1. Client sends its latest supported version of MCP.
2. If server supports it, respond with same version.
3. If server does not support it, respond with latest version supported.
4. If client does not support it, disconnect.

#### Capabilities

1. Client capabilities are communicated (roots, tasks)
2. Server capabilities are communicated (prompts, resources, tools)

#### Implementation

Both client and server include information such as:

- Name
- Title
- Version
- Description
- Icons
- Website URL

### **Phase 2:** Operation

Client and server communicate according to the agreed MCP version and the
capabilities outlined during initialization.

### **Phase 3:** Shutdown

One side (usually client):

1. Closes the input stream to the server (which is a child process).
2. Waits for the server to exit, or sends a SIGTERM if the server does not
exit within a reasonable time.
3. Sending SIGKILL if the server does not exit within a reasonable time after
SIGTERM.


## Capabilities

### Client

#### Roots

Whether the client supports roots. `listChanged` determines whether the client
will send a notification with the updated list of roots, when it changes.

```json
{
  "roots": {
    "listChanged": true
  }
}
```

The server can send `roots/list` request to get the roots configured in the
client:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "roots": [
      {
        "uri": "file:///home/mpcnode/.mpa",
        "name": "Agent workspace"
      },
      {
        "uri": "file:///home/mpcnode/mpc-config",
        "name": "MPC Config repository"
      }
    ]
  }
}
```

If `listChanged` is set to true, then the client will send an notification
telling the server to request the roots list again:

```json
{
  "jsonrpc": "2.0",
  "method": "notifications/roots/list_changed"
}
```

The client should prompt the user for roots access, and which roots they wish
to configure for the workspace and MPC config repository.

#### Sampling

Means for servers to request that the client executes an LLM request, optionally
with a list of tools that the LLM may request to use.

#### Elicitation

Allows the server to ask the client to ask the user to fill in a form of data
of some kind. This form of data can be standardized according to some standard,
so that the user's response can then be used by the server to execute a tool.

Example KeyGen request in the server:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "elicitation/create",
  "params": {
    "mode": "form",
    "message": "Please enter the KeyGen creation details",
    "requestedSchema": {
      "type": "object",
      "properties": {
        "msgCheck": {
          "type": "string",
          "title": "MsgCheck",
          "description": "Whether the KeyGen is a wallet or validator node",
          "enum": ["multi-agree", "tx-check"]
        },
        "clientAuth": {
          "type": "string",
          "title": "Client Auth",
          "description": "Whether authentication is done using MetaMask or ed25519 key",
          "enum": ["MetaMask", "ed25519"],
          "default": "ed25519"
        },
        "clientKey": {...},
        "groupId": {...},
        "gate": {
          "type": "integer",
          "minimum": 1,
          "maximum": <n>
        },
        "keyType": {
          "type": "string",
          "title": "Key Type",
          "description": "Whether the key type is ed25519 or secp256k1",
          "enum": ["secp256k1", "ed25519"]
        }
      },
      "required": ["msgCheck", "clientKey", "groupId", "keyType"]
    }
  }
}
```

Then the client can responde with:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "action": "accept",
    "content": {
      "msgCheck": "multi-agree",
      "clientAuth": "ed25519",
      "clientKey": "9192836490182734",
      "groupId": "8192384719263904871234",
      "gate": "3",
      "keyType": "secp256k1"
    }
  }
}
```

The client or user may also elect to decline the request:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "action": "decline"
  }
}
```

### Server

#### Prompts

Whether the server supports prompts. `listChanged` determines whether the server
will send a notification with the updated list of prompts, when it changes.

```json
{
  "prompts": {
    "listChanged": true
  }
}
```

The client can send `prompts/list` request to get the prompts configured in the
client:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "prompts": [
      {
        "name": "getKeyGenResultById",
        "title": "Get KeyGen Result by ID",
        "description": "Get information about a given KeyGen.",
        "arguments": [
          {
            "name": "KeyGenID",
            "description": "The KeyGen to get data for.",
            "required": true
          }
        ]
      }
    ]
  }
}
```

Clients can request a specific prompt from the server:

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "prompts/get",
  "params": {
    "name": "validateSignRequest",
    "arguments": {
      "signRequestId": "Sign202604240000000"
    }
  }
}
```

The server would respond with a prompt encoded with something like:

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "result": {
    "description": "Sign request description",
    "messages": [
      {
        "role": "user",
        "content": {
          "type": "text",
          "text": "The user has an incoming sign request for the following data: target address: 0xabc, ETH value: 0.002, calldata: 0x187dace9, etc. Please tell them exactly what would happen if they agreed to this sign request."
        }
      },
      {
        "role": "user",
        "content": {
          "type": "resources",
          "resource": {
            "uri": "resource://sign-request",
            "mimeType": "text/plain",
            "text": "Markdown content including documentation about sign requests and how they are processed, etc."
          }
        }
      }
    ]
  }
}
```

If `listChanged` is set to true, then the server will send an notification
telling the client to request the prompts list again:

```json
{
  "jsonrpc": "2.0",
  "method": "notifications/prompts/list_changed"
}
```

#### Resources

Resources contain information about the application that can be roped into the
context of the conversation or drawn upon individually. The documentation of
Continuum MPA is a good example, including the API reference for interaction
with the node client.

```json
{
  "resources": {
    "subscribe": true,
    "listChanged": true
  }
}
```

Subscribe allows the server to send a notification when a pre-existing resource
changes. List changed allows the server to send a notification when the list
of available resources is added to/removed from.

When the list of resources changes, the server should send a notification:

```json
{
  "jsonrpc": "2.0",
  "method": "notifications/resources/list_changed"
}
```

Clients may subscribe to certain resource changes, which will prompt the server
to notify changes to the file in question:

Client:

```json
{
  "jsonrpc": "2.0",
  "method": "resources/subscribe",
  "params": {
    "uri": "file:///home/mpcnode/.mpa/docs/API.md"
  }
}
```

When that resource changes, the server will notify the cilent with:

```json
{
  "jsonrpc": "2.0",
  "method": "notifications/resources/updated",
  "params": {
    "uri": "file:////home/mpcnode/.mpa/docs/API.md"
  }
}
```

When asking for the list of resources, the client should send the following
request:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "resources/list",
  "params": {}
}
```
To which the response would be:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "resources": [
      {
        "uri": "file:///home/mpcnode/.mpa/docs/API.md",
        "name": "API.md",
        "title": "API reference for MPA wallet",
        "description": "Documentation containing usage of the node API",
        "mimeType": "text/plain"
      },
      {
        "uri": "file:///home/mpcnode/.mpa/docs/KEYGEN.md",
        "name": "KEYGEN.md",
        "title": "KeyGen Information",
        "description": "Basics of KeyGen creation, parameters, usage",
        "mimeType": "text/plain"
      }
    ]
  }
}
```

The client may then request certain resources when it wishes:

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "resources/read",
  "params": {
    "uri": "file:///home/mpcnode/.mpa/docs/API.md"
  }
}
```

To which the server may respond with:

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "result": {
    "contents": [
      {
        "uri": "file:///home/mpcnode/.mpa/docs/API.md",
        "mimeType": "text/plain",
        "text": "# API Reference\n\n## Usage\n\nThe MPA API allows management of the node client..."
      }
    ]
  }
}
```

The client may request parameterized templates that the server exposes, for
general searches in a folder location:

```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "resources/templates/list"
}
```

Response from server:

```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "result": {
    "resourceTemplates": [
      {
        "uriTemplate": "file:///home/mpcnode/.mpa/docs/{path}",
        "name": "Documentation Files",
        "title": "📁 Documentation Files",
        "description": "Access files in the project directory",
        "mimeType": "application/json"
      }
    ]
  }
}
```

The resource object is as such:

```json
{
  "uri": "file:///home/mpcnode/.mpa/docs/API.md",
  "name": "API.md",
  "title": "Main API reference for MPA node",
  "description": "Main API reference for the node client",
  "icons": [],              // options
  "mimeType": "text/plain", // optional
  "size": "234"             // bytes, optional
}
```

Resources can contain text or binary data:

```json
{
  "uri": "...",
  "mimeType": "text/plain",
  "text": "..."
}
```

```json
{
  "uri": "...",
  "mimeType": "image/png",
  "blob": "base64-encoded-data"
}
```

The resource object may also contain annotations, which is useful for hints to
the client about the importance and use of a resource:

```json
{
  "uri": "...",
  "mimeType": "text/plain",
  "text": "...",
  "annotations": {
    "audience": ["assistant"],  // or user, or both
    "priority": 0.8,            // how important is this resource (0-1)
    "lastModified": 2026-04-24T12:12:27Z
  }
}
```

Clients can use annotations to filter for target audience (assitant or user),
prioritize which resource(s) to include in context, sort by recency.

Types of URI schemes for resources are as follows:

1. https:// - client fetches from web, not available on server
2. file:// - local file/directory on server, as specified by mimeType
3. git:// - git version control integration
4. Some custom defined URI scheme conforming to RFC3986.

Servers must validate all resource URIs. Resource permissions should be checked
before operations.

#### Tools

Tools can be used to enable models to invoke interactions with external systems,
such as API call, query database, performing computations. Each tool has a
unique name. The tools are model-invoked, meaning the model can decide to use
a tool as it sees fit based on context and user prompts.

The server should specify whether listChanges to tools will be notified:

```json
{
  "tools": {
    "listChanged": true
  }
}
```

The server should send such a notification:

```json
{
  "jsonrpc": "2.0",
  "method": "notifications/tools/list_changed"
}
```

Which will ensure the server notifies changes to the tool list available to the
client. Client may expose list of tools available via:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/list"
}
```

To which the server would respond with its full list of available tools:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "tools": [
      {
        "name": "list_keygens",
        "title": "List Configured KeyGens",
        "description": "List all KeyGens that the node is configured with",
        "execution": {
          "taskSupport": "optional"
        }
      },
      {
        "name": "get_keygen_data",
        "title": "Get Information for a KeyGen",
        "description": "Get information for a KeyGen such as type, gate, signing algorithm, etc.",
        "inputSchema": [
          {
            "type": "object",
            "properties": {
              "keygenid": {
                "type": "string",
                "description": "KeyGen ID"
              }
            },
            "required": "keygenid"
          }
        ],
        "outputSchema": {
          "type": "object",
          "properties": {
            "msgcheck": {
              "type": "string",
              "description": "multi-agree or tx-check"
            },
            "gate": {
              "type": "number",
              "description": "Number of nodes required to sign an MPC sign request (gate). Internally, API threshold = gate - 1"
            },
            "keytype": {
              "type": "string",
              "description": "secp256k1 or ed25519 key type"
            }
          },
          "required": ["msgcheck", "gate", "keytype"]
        }
      }
    ]
  }
}
```

At this point, the client knows that it may invoke a tool, for example get
KeyGen data:

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "tools/call",
  "params": {
    "name": "get_keygen_data",
    "arguments": {
      "keygenid": "KeyGen20260424000000"
    }
  }
}
```

To which the server would respond with:

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "KeyGen data for KeyGen20260424000000: multi-agree, gate 3, secp256k1, metamask, etc."
      }
    ],
    "isError": false
  }
}
```

Tool schema is as follows:

1. name (required): unique tool identifier
2. title (optional): human readable tool name
3. description (optional): human readable tool description
4. icons (optional): array of icons for the tool
5. inputSchema (required): JSON schema defining expected parameters
  - cannot be null
  - if no parameters for the tool, do: {"type": "object", "additionalProperties": false}.
6. outputSchema (optional): JSON schema defining output of the call.
7. annotations (optional): properties describing tool behaviour
8. execution (optional): object describing execution-related properties:
  - taskSupport: indicates whether this tool supports task-augemented execution.
    can be forbidden, optional or required.

Tool names may contain _, -, or . in the name, but must be unique. No spaces.

##### Unstructured Response

The server may respond with any content type, such as text, resource link, or
embedded resource. Such objects may include an annotations object for further
details about the response.

If the server responds to a tool invocation with text, it should be structured
as follows:

```json
{
  "type": "text",
  "text": "Tool result here..."
}
```

If the tool responds with a link to a resource, it should be structured as
follows: (keep in mind this isn't the same as an embedded resource.)

```json
{
  "type": "resource_link",
  "uri": "file:///home/mpcnode/.mpa/docs/API.md",
  "name": "API.md",
  "description": "Documentation for the API",
  "mimeType": "text/plain"
}
```

Embedded resources may also be returned:

```json
{
  "type": "resource",
  "resource": {
    "uri": "file:///home/mpcnode/docs/API.md",
    "mimeType": "text/plain",
    "text": "Here is the content of the API docs",
    "annotations": {
      "audience": ["assistant"],
      "priority": "0.5",
      "lastModified": "2026-04-24T12:50:34Z"
    }
  }
}
```

##### Structured Response

The server may also respond with structured response. This would be in the
structuredContent field of the reponse. Such a tool should also return the
serialized content as unstructured response in the text content object.

If, in the tool definition (from the tools/list), the server responds with an
outputSchema, then the tool must respond with this field on invocation.

A valid response to the get_keygen_data tool would be:

```json
{
  "jsonrpc": "2.0",
  "id": 5,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "serialized JSON object of structuredContent"
      }
    ],
    "structuredContent": {
      "msgcheck": "multi-agree",
      "gate": 3,
      "keytype": "ed25519"
    }
  }
}
```

NOTE: include error handling for invalid input schema, server error, etc.

If Tool Execution Error:

- Server responds with `isError: true`. This is due to API failures, input
validation errors, business logic errors.
- This can be acionable feedback for the LLM to self-correct and retry.

If Protocol Error:

- In cases such as unknown tools, malformed request, server error; then LLM is
less likely to be able to self-correct.

Example Protocol Error:

```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "error": {
    "code": -32602,
    "message": "Unknown tool: invalid_tool_name"
  }
}
```

Example Tool Request Error:

```json
{
  "jsonrpc": "2.0",
  "id": 4,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "Invalid departure date: must be in the future. Current date is 08/08/2025."
      }
    ],
    "isError": true
  }
}
```

The server must validate all tool inputs, rate limit tool invocations, sanitize
tool outputs.


#### Completions

Used so that the client may request that the server provides some auto-complete
options for the user as they type.

#### Logging

Servers may choose to have logs of varying severity, which the client may filter
by requesting the minimum severity logs to receive. The server can then send
notifications of that severity or higher when it wishes to.

#### Pagination

Servers may support opaque pagination, which means when the client requests
large datasets in the following requests:

- `resources/list`
- `resources/templates/list`
- `prompts/list`
- `tools/list`

The server can respond by including a "nextCursor" on the result object, which
can be included by the client as a cursor param in a subsequent request (new ID)
should be used for new page requests.
