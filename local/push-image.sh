#!/usr/bin/env bash
# Build and push the Continuum MCP server image (same registry style as continuumdao-node-app:
# default IMAGE_NAME=continuumdao/continuum-mcp-server → Docker Hub continuumdao/continuum-mcp-server).
#
# Prerequisite: docker login (e.g. docker login docker.io for the continuumdao org).
#
# Optional overrides:
#   export IMAGE_NAME=continuumdao/continuum-mcp-server
# Or source ../mpc-config/.env.docker-registry (see local/env.docker-registry.example).
#
# Usage:
#   ./local/push-image.sh <version> [--tag-latest]
#
# Examples:
#   ./local/push-image.sh v1.0.0
#   ./local/push-image.sh v1.0.0 --tag-latest

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

OPTIONAL_REGISTRY_ENV="$REPO_ROOT/../mpc-config/.env.docker-registry"
if [[ -f "$OPTIONAL_REGISTRY_ENV" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "$OPTIONAL_REGISTRY_ENV"
  set +a
fi

IMAGE_NAME="${IMAGE_NAME:-${DOCKER_IMAGE:-continuumdao/continuum-mcp-server}}"

VERSION=""
TAG_LATEST=0
for arg in "$@"; do
  if [[ "$arg" == "--tag-latest" ]]; then
    TAG_LATEST=1
  elif [[ "$arg" == -* ]]; then
    echo "Unknown option: $arg" >&2
    exit 1
  elif [[ -z "$VERSION" ]]; then
    VERSION="$arg"
  else
    echo "Unexpected extra argument: $arg" >&2
    exit 1
  fi
done

if [[ -z "$VERSION" ]]; then
  echo "Usage: $0 <version> [--tag-latest]" >&2
  echo "" >&2
  echo "Pushes \${IMAGE_NAME}:\${version} (default IMAGE_NAME=continuumdao/continuum-mcp-server)." >&2
  echo "Override: export IMAGE_NAME=... or set it in ../mpc-config/.env.docker-registry" >&2
  exit 1
fi

FULL_IMAGE="${IMAGE_NAME}:${VERSION}"

cd "$REPO_ROOT"

docker build -f local/Dockerfile -t "${FULL_IMAGE}" "$REPO_ROOT"
docker push "${FULL_IMAGE}"

if [[ "$TAG_LATEST" -eq 1 ]]; then
  docker tag "${FULL_IMAGE}" "${IMAGE_NAME}:latest"
  docker push "${IMAGE_NAME}:latest"
fi

echo "Pushed ${FULL_IMAGE}$([[ $TAG_LATEST -eq 1 ]] && echo " and ${IMAGE_NAME}:latest")"

echo "Cleaning up dangling layers for ${IMAGE_NAME} …"
while IFS= read -r id; do
  [[ -n "$id" ]] && docker rmi -f "$id" 2>/dev/null || true
done < <(docker images "${IMAGE_NAME}" --filter "dangling=true" -q)

echo "Pruning all dangling images …"
docker image prune -f
