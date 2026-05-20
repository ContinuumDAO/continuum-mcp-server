# Build from repository root (npm run build → build/). Runtime via mpc-config docker-compose.yml
# (service "continuum-mcp"). Push with local/push-image.sh — see local/README.md.
FROM node:22-bookworm-slim AS deps

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

FROM deps AS builder

COPY tsconfig.json ./
COPY src ./src
COPY resources ./resources
RUN npm run build

FROM node:22-bookworm-slim AS runner

WORKDIR /app

ENV NODE_ENV=production
ENV MCP_HTTP_HOST=0.0.0.0
ENV MCP_HTTP_PORT=8446
ENV MCP_HTTP_PATH=/mcp
ENV MPC_AUTH_URL=http://app
ENV MPC_AUTH_PORT=8080

COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY --from=builder /app/build ./build
COPY --from=builder /app/resources ./resources

EXPOSE 8446

CMD ["node", "build/index.js"]
