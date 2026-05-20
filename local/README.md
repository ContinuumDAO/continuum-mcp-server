# Local Docker build and registry push

Build and publish **`continuumdao/continuum-mcp-server`** from this repo. Operators run the container via **`mpc-config`** `docker-compose.yml` (service **`continuum-mcp`**), merged from **`configs.yaml`** **`ContinuumMcpServer`** by **`process_config.sh`**.

## Build / push

```bash
chmod +x local/push-image.sh
./local/push-image.sh v1.0.0 --tag-latest
```

- **`Dockerfile`** — `npm run build` → `build/`, copies **`resources/`**, production `npm ci --omit=dev`
- **`push-image.sh`** — `docker build -f local/Dockerfile` and push (default `continuumdao/continuum-mcp-server`)
- **`env.docker-registry.example`** — optional `IMAGE_NAME` for `../mpc-config/.env.docker-registry`

## Runtime (mpc-config)

After push, set **`ContinuumMcpServer.Image`** / **`Tag`** in **`configs.yaml`** (defaults in **`configs-original.yaml`**), run **`process_config.sh`**, then **`docker compose pull`** and **`docker compose up -d`**.

Loopback URL for MCP clients on the host: **`http://127.0.0.1:<HostPort><HttpPath>`** (default **`http://127.0.0.1:8446/mcp`**).

Inside the compose network, mpc-auth and other services reach **`http://continuum-mcp:<Port><HttpPath>`**.

Default container env (override in compose merge):

| Variable | Default |
|----------|---------|
| `MCP_HTTP_HOST` | `0.0.0.0` |
| `MCP_HTTP_PORT` | `8446` |
| `MCP_HTTP_PATH` | `/mcp` |
| `MPC_AUTH_URL` | `http://app` |
| `MPC_AUTH_PORT` | `8080` (management API) |
