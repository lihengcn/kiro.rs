#!/usr/bin/env bash

set -euo pipefail

IMAGE_REPO="${IMAGE_REPO:-lihengcn/kiro-rs}"
IMAGE_TAG="${IMAGE_TAG:-latest}"
PLATFORM="${PLATFORM:-linux/amd64}"
OUTPUT_MODE="${OUTPUT_MODE:-push}"
BUILDER_NAME="${BUILDER_NAME:-kiro-rs-builder}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../../.." && pwd)"

if [[ ! -f "${REPO_ROOT}/Dockerfile" ]]; then
  echo "未找到 Dockerfile: ${REPO_ROOT}/Dockerfile" >&2
  exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "未找到 docker 命令" >&2
  exit 1
fi

if ! docker buildx version >/dev/null 2>&1; then
  echo "当前 Docker 不支持 buildx" >&2
  exit 1
fi

if docker buildx inspect "${BUILDER_NAME}" >/dev/null 2>&1; then
  docker buildx use "${BUILDER_NAME}" >/dev/null
else
  docker buildx create --name "${BUILDER_NAME}" --use >/dev/null
fi

docker buildx inspect --bootstrap >/dev/null

case "${OUTPUT_MODE}" in
  push)
    OUTPUT_FLAG="--push"
    ;;
  load)
    OUTPUT_FLAG="--load"
    ;;
  *)
    echo "不支持的 OUTPUT_MODE: ${OUTPUT_MODE}，可选值为 push 或 load" >&2
    exit 1
    ;;
esac

cd "${REPO_ROOT}"

echo "开始构建镜像 ${IMAGE_REPO}:${IMAGE_TAG}"
echo "目标平台: ${PLATFORM}"
echo "输出模式: ${OUTPUT_MODE}"

docker buildx build \
  --platform "${PLATFORM}" \
  -t "${IMAGE_REPO}:${IMAGE_TAG}" \
  "${OUTPUT_FLAG}" \
  "$@" \
  .
