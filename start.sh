#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

RUSTIO_ADDR="${RUSTIO_ADDR:-0.0.0.0:9000}"
RUSTIO_HOST_PORT="${RUSTIO_HOST_PORT:-9000}"
RUSTIO_CONTAINER_PORT="${RUSTIO_CONTAINER_PORT:-9000}"
RUSTIO_DATA_DIR_HOST="${RUSTIO_DATA_DIR_HOST:-$SCRIPT_DIR/data}"
RUSTIO_DATA_DIR_CONTAINER="${RUSTIO_DATA_DIR_CONTAINER:-/app/data}"
RUSTIO_CONTAINER_NAME="${RUSTIO_CONTAINER_NAME:-rustio}"
RUSTIO_IMAGE_NAME="${RUSTIO_IMAGE_NAME:-rustio-rustio}"
RUSTIO_RESTART_POLICY="${RUSTIO_RESTART_POLICY:-unless-stopped}"
RUSTIO_MEMORY_TRIM_ENABLED="${RUSTIO_MEMORY_TRIM_ENABLED:-true}"
RUSTIO_MEMORY_TRIM_INTERVAL_SECONDS="${RUSTIO_MEMORY_TRIM_INTERVAL_SECONDS:-300}"
RUSTIO_MEMORY_TRIM_IDLE_SECONDS="${RUSTIO_MEMORY_TRIM_IDLE_SECONDS:-43200}"
RUSTIO_MEMORY_TRIM_FORCE_INTERVAL_SECONDS="${RUSTIO_MEMORY_TRIM_FORCE_INTERVAL_SECONDS:-7200}"
RUSTIO_MEMORY_TRIM_RSS_THRESHOLD_MB="${RUSTIO_MEMORY_TRIM_RSS_THRESHOLD_MB:-128}"
RUSTIO_AUDIT_MAX_EVENTS="${RUSTIO_AUDIT_MAX_EVENTS:-2048}"
RUSTIO_STORAGE_SCAN_INTERVAL_MS="${RUSTIO_STORAGE_SCAN_INTERVAL_MS:-300000}"
MALLOC_ARENA_MAX="${MALLOC_ARENA_MAX:-2}"
MALLOC_TRIM_THRESHOLD_="${MALLOC_TRIM_THRESHOLD_:-131072}"

DOCKER_API_COMPATIBILITY_PROBED=0
COMPOSE_BIN=()
RUSTIO_COMPOSE_ACTION="up"
RUSTIO_COMPOSE_BUILD=0
RUSTIO_COMPOSE_DETACH=0
DEFAULT_RUSTIO_ADDR="0.0.0.0:9000"
DEFAULT_RUSTIO_PORT="9000"

log() {
  echo "[RustIO] $*"
}

fail() {
  echo "[RustIO] 错误：$*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
用法: ./start.sh [选项]

选项:
  --build, --rebuild         构建前强制重建镜像
  -d, --detach              后台启动
  --down                    停止并移除当前 compose 资源
  --addr <host:port>        指定容器内监听地址，默认 0.0.0.0:9000
  --port <port>             指定宿主机暴露端口，同时同步容器监听端口
  --data-dir <path>         指定宿主机数据目录
  --container-name <name>   指定容器名称
  --image-name <name>       指定镜像名称
  -h, --help                显示帮助

常用环境变量:
  RUSTIO_ADDR
  RUSTIO_HOST_PORT
  RUSTIO_CONTAINER_PORT
  RUSTIO_DATA_DIR_HOST
  RUSTIO_CONTAINER_NAME
  RUSTIO_IMAGE_NAME
  RUSTIO_MEMORY_TRIM_ENABLED
  RUSTIO_MEMORY_TRIM_INTERVAL_SECONDS
  RUSTIO_MEMORY_TRIM_IDLE_SECONDS
  RUSTIO_MEMORY_TRIM_FORCE_INTERVAL_SECONDS
  RUSTIO_MEMORY_TRIM_RSS_THRESHOLD_MB
  MALLOC_ARENA_MAX
  MALLOC_TRIM_THRESHOLD_
EOF
}

resolve_path() {
  local input_path="$1"

  if [[ "$input_path" = /* ]]; then
    printf '%s\n' "$input_path"
  else
    printf '%s\n' "$SCRIPT_DIR/$input_path"
  fi
}

version_gt() {
  local current="$1"
  local baseline="$2"

  [[ "$current" != "$baseline" ]] && [[ "$(printf '%s\n%s\n' "$baseline" "$current" | sort -V | tail -n1)" == "$current" ]]
}

extract_supported_api_version() {
  printf '%s\n' "$1" \
    | sed -nE 's/.*Maximum supported API version is ([0-9.]+).*/\1/p' \
    | head -n1
}

sync_ports_from_addr() {
  local addr_port=""

  addr_port="${RUSTIO_ADDR##*:}"
  [[ "$addr_port" =~ ^[0-9]+$ ]] || fail "监听地址格式不合法：$RUSTIO_ADDR / Invalid listen address: $RUSTIO_ADDR"
  RUSTIO_HOST_PORT="$addr_port"
  RUSTIO_CONTAINER_PORT="$addr_port"
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --build|--rebuild)
        RUSTIO_COMPOSE_BUILD=1
        shift
        ;;
      -d|--detach)
        RUSTIO_COMPOSE_DETACH=1
        shift
        ;;
      --down)
        RUSTIO_COMPOSE_ACTION="down"
        shift
        ;;
      --addr)
        [[ $# -ge 2 ]] || fail "参数 --addr 缺少值。 / Missing value for --addr."
        RUSTIO_ADDR="$2"
        sync_ports_from_addr
        shift 2
        ;;
      --port)
        [[ $# -ge 2 ]] || fail "参数 --port 缺少值。 / Missing value for --port."
        [[ "$2" =~ ^[0-9]+$ ]] || fail "端口必须是数字：$2 / Port must be numeric: $2"
        RUSTIO_HOST_PORT="$2"
        RUSTIO_CONTAINER_PORT="$2"
        RUSTIO_ADDR="0.0.0.0:$2"
        shift 2
        ;;
      --data-dir)
        [[ $# -ge 2 ]] || fail "参数 --data-dir 缺少值。 / Missing value for --data-dir."
        RUSTIO_DATA_DIR_HOST="$(resolve_path "$2")"
        shift 2
        ;;
      --container-name)
        [[ $# -ge 2 ]] || fail "参数 --container-name 缺少值。 / Missing value for --container-name."
        RUSTIO_CONTAINER_NAME="$2"
        shift 2
        ;;
      --image-name)
        [[ $# -ge 2 ]] || fail "参数 --image-name 缺少值。 / Missing value for --image-name."
        RUSTIO_IMAGE_NAME="$2"
        shift 2
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        fail "不支持的参数：$1 / Unsupported argument: $1"
        ;;
    esac
  done
}

probe_docker_api_compatibility() {
  local probe_output=""
  local probe_status=0
  local supported_api_version=""
  local client_api_version=""
  local server_api_version=""

  set +e
  probe_output="$(docker version --format '{{.Client.APIVersion}} {{.Server.APIVersion}}' 2>&1)"
  probe_status=$?
  set -e

  if [[ $probe_status -eq 0 ]]; then
    read -r client_api_version server_api_version <<<"$probe_output"

    if [[ -n "$client_api_version" ]] && [[ -n "$server_api_version" ]] && version_gt "$client_api_version" "$server_api_version"; then
      export DOCKER_API_VERSION="$server_api_version"
      log "检测到 Docker Client API ${client_api_version} 高于 Daemon API ${server_api_version}，已自动锁定兼容版本。"
      if docker version --format '{{.Server.APIVersion}}' >/dev/null 2>&1; then
        return 0
      fi
      fail "自动锁定 Docker API 兼容版本后仍无法连接 daemon。 / Failed to connect to Docker daemon after locking API compatibility version."
    fi

    return 0
  fi

  supported_api_version="$(extract_supported_api_version "$probe_output")"

  if [[ -n "$supported_api_version" ]]; then
    export DOCKER_API_VERSION="$supported_api_version"
    log "检测到 Docker Daemon 最大 API 版本 ${supported_api_version}，已自动启用兼容模式。"
    if docker version --format '{{.Server.APIVersion}}' >/dev/null 2>&1; then
      return 0
    fi
    fail "自动切换 Docker API 兼容模式后仍无法连接 daemon。 / Failed to connect to Docker daemon after enabling compatibility mode."
  fi

  printf '%s\n' "$probe_output" >&2
  fail "检测 Docker daemon 版本失败，请确认 Docker 已启动。 / Failed to detect Docker daemon API version; please ensure Docker is running."
}

ensure_docker_ready() {
  command -v docker >/dev/null 2>&1 || fail "未找到 docker，请先安装 Docker Desktop 或 Docker Engine。 / Docker is not installed; please install Docker Desktop or Docker Engine."

  if [[ "$DOCKER_API_COMPATIBILITY_PROBED" == "1" ]]; then
    return
  fi

  probe_docker_api_compatibility
  DOCKER_API_COMPATIBILITY_PROBED=1
}

probe_compose_api_compatibility() {
  local probe_output=""
  local probe_status=0
  local supported_api_version=""

  set +e
  probe_output="$("${COMPOSE_BIN[@]}" ps 2>&1)"
  probe_status=$?
  set -e

  if [[ $probe_status -eq 0 ]]; then
    return 0
  fi

  supported_api_version="$(extract_supported_api_version "$probe_output")"
  if [[ -n "$supported_api_version" ]]; then
    export DOCKER_API_VERSION="$supported_api_version"
    log "检测到 Compose 访问 Docker Daemon 时 API 版本不兼容，已自动切换到 ${supported_api_version}。"
    if "${COMPOSE_BIN[@]}" ps >/dev/null 2>&1; then
      return 0
    fi
    fail "Compose 切换 Docker API 兼容版本后仍无法访问 daemon。 / Compose still cannot access Docker daemon after switching API compatibility version."
  fi

  printf '%s\n' "$probe_output" >&2
  fail "探测 Compose 与 Docker Daemon 兼容性失败。 / Failed to verify compose and Docker daemon compatibility."
}

ensure_compose_ready() {
  ensure_docker_ready

  if docker compose version >/dev/null 2>&1; then
    COMPOSE_BIN=(docker compose)
  elif command -v docker-compose >/dev/null 2>&1; then
    COMPOSE_BIN=(docker-compose)
  else
    fail "当前环境未启用 docker compose 插件，也未安装 docker-compose。 / Neither docker compose plugin nor docker-compose is available."
  fi

  probe_compose_api_compatibility
}

prepare_environment() {
  if [[ "$RUSTIO_ADDR" != "$DEFAULT_RUSTIO_ADDR" ]] \
    && [[ "$RUSTIO_HOST_PORT" == "$DEFAULT_RUSTIO_PORT" ]] \
    && [[ "$RUSTIO_CONTAINER_PORT" == "$DEFAULT_RUSTIO_PORT" ]]; then
    sync_ports_from_addr
  fi

  mkdir -p "$RUSTIO_DATA_DIR_HOST"

  export RUSTIO_ADDR
  export RUSTIO_HOST_PORT
  export RUSTIO_CONTAINER_PORT
  export RUSTIO_DATA_DIR_HOST
  export RUSTIO_DATA_DIR_CONTAINER
  export RUSTIO_CONTAINER_NAME
  export RUSTIO_IMAGE_NAME
  export RUSTIO_RESTART_POLICY
  export RUSTIO_MEMORY_TRIM_ENABLED
  export RUSTIO_MEMORY_TRIM_INTERVAL_SECONDS
  export RUSTIO_MEMORY_TRIM_IDLE_SECONDS
  export RUSTIO_MEMORY_TRIM_FORCE_INTERVAL_SECONDS
  export RUSTIO_MEMORY_TRIM_RSS_THRESHOLD_MB
  export RUSTIO_AUDIT_MAX_EVENTS
  export RUSTIO_STORAGE_SCAN_INTERVAL_MS
  export MALLOC_ARENA_MAX
  export MALLOC_TRIM_THRESHOLD_
}

run_compose() {
  local compose_args=("$RUSTIO_COMPOSE_ACTION")

  if [[ "$RUSTIO_COMPOSE_ACTION" == "up" ]]; then
    if [[ "$RUSTIO_COMPOSE_BUILD" == "1" ]]; then
      compose_args+=(--build)
      log "检测到 --build，正在强制重建镜像。"
    fi
    if [[ "$RUSTIO_COMPOSE_DETACH" == "1" ]]; then
      compose_args+=(-d)
      log "检测到 --detach，将后台启动服务。"
    fi
    log "使用 Docker 一键启动 RustIO（单端口模式，${RUSTIO_HOST_PORT} 同时提供 API 与管理端）..."
  else
    log "停止并清理当前 RustIO Docker 资源..."
  fi

  log "Compose 命令：${COMPOSE_BIN[*]}"
  log "监听地址：$RUSTIO_ADDR"
  log "数据目录：$RUSTIO_DATA_DIR_HOST"
  log "容器名称：$RUSTIO_CONTAINER_NAME"
  log "内存回收：enabled=$RUSTIO_MEMORY_TRIM_ENABLED idle=${RUSTIO_MEMORY_TRIM_IDLE_SECONDS}s force=${RUSTIO_MEMORY_TRIM_FORCE_INTERVAL_SECONDS}s rss=${RUSTIO_MEMORY_TRIM_RSS_THRESHOLD_MB}MB"
  log "内存保护：audit_max=${RUSTIO_AUDIT_MAX_EVENTS} storage_scan_interval_ms=${RUSTIO_STORAGE_SCAN_INTERVAL_MS}"

  "${COMPOSE_BIN[@]}" "${compose_args[@]}"
}

main() {
  parse_args "$@"
  ensure_compose_ready
  prepare_environment
  run_compose
}

main "$@"
