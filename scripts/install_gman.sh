#!/usr/bin/env bash
set -euo pipefail

# gman installer (Linux/macOS)
#
# Usage examples:
#   curl -fsSL https://raw.githubusercontent.com/Dark-Alex-17/gman/main/scripts/install_gman.sh | bash
#   curl -fsSL https://raw.githubusercontent.com/Dark-Alex-17/gman/main/scripts/install_gman.sh | bash -s -- --version vX.Y.Z
#   BIN_DIR="$HOME/.local/bin" bash scripts/install_gman.sh
#
# Flags / Env:
#   --version <tag>   Release tag (default: latest). Or set GMAN_VERSION.
#   --bin-dir <dir>   Install directory (default: /usr/local/bin or ~/.local/bin). Or set BIN_DIR.

REPO="Dark-Alex-17/gman"
VERSION="${GMAN_VERSION:-}"
BIN_DIR="${BIN_DIR:-}"

usage() {
  echo "gman installer (Linux/macOS)"
  echo
  echo "Options:"
  echo "  --version <tag>         Release tag (default: latest)"
  echo "  --bin-dir <dir>         Install directory (default: /usr/local/bin or ~/.local/bin)"
  echo "  -h, --help              Show help"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) VERSION="$2"; shift 2;;
    --bin-dir) BIN_DIR="$2"; shift 2;;
    -h|--help) usage; exit 0;;
    *) echo "Unknown argument: $1" >&2; usage; exit 2;;
  esac
done

if [[ -z "${BIN_DIR}" ]]; then
  if [[ -w "/usr/local/bin" ]]; then
    BIN_DIR="/usr/local/bin"
  else
    BIN_DIR="${HOME}/.local/bin"
  fi
fi
mkdir -p "${BIN_DIR}"

log() {
	echo "[gman-install] $*"
}

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
  	echo "Error: required command '$1' not found" >&2
  	exit 1
  fi
}

need_cmd uname
need_cmd mktemp
need_cmd tar

if command -v curl >/dev/null 2>&1; then
  DL=curl
elif command -v wget >/dev/null 2>&1; then
  DL=wget
else
  echo "Error: need curl or wget" >&2
  exit 1
fi

UNAME_OS=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$UNAME_OS" in
  linux)  OS=linux ;;
  darwin) OS=darwin ;;
  *) echo "Error: unsupported OS '$UNAME_OS'" >&2; exit 1;;
esac

UNAME_ARCH=$(uname -m)
case "$UNAME_ARCH" in
  x86_64|amd64) ARCH=x86_64 ;;
  aarch64|arm64) ARCH=aarch64 ;;
  *) echo "Error: unsupported arch '$UNAME_ARCH'" >&2; exit 1;;
esac

log "Target: ${OS}-${ARCH}"

if [[ -z "${VERSION}" ]]; then
  DL_BASE="https://github.com/${REPO}/releases/latest/download"
else
  DL_BASE="https://github.com/${REPO}/releases/download/${VERSION}"
fi

download() {
  if [[ "$DL" == "curl" ]]; then
    curl -fsSL -H 'User-Agent: gman-installer' "$1" -o "$2"
  else
    wget -q --header='User-Agent: gman-installer' "$1" -O "$2"
  fi
}

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

ASSET_CANDIDATES=()
if [[ "$OS" == "darwin" ]]; then
  if [[ "$ARCH" == "x86_64" ]]; then
    ASSET_CANDIDATES+=("gman-x86_64-apple-darwin.tar.gz")
  else
    ASSET_CANDIDATES+=("gman-aarch64-apple-darwin.tar.gz")
  fi
elif [[ "$OS" == "linux" ]]; then
  if [[ "$ARCH" == "x86_64" ]]; then
    ASSET_CANDIDATES+=("gman-x86_64-unknown-linux-musl.tar.gz")
    ASSET_CANDIDATES+=("gman-x86_64-unknown-linux-gnu.tar.gz")
  else
    ASSET_CANDIDATES+=("gman-aarch64-unknown-linux-musl.tar.gz")
  fi
else
  echo "Error: unsupported OS for this installer: $OS" >&2; exit 1
fi

ARCHIVE="$TMPDIR/asset"
ASSET_NAME=""; ASSET_URL=""
for candidate in "${ASSET_CANDIDATES[@]}"; do
  URL="${DL_BASE}/${candidate}"
  log "Trying ${URL}"
  if download "$URL" "$ARCHIVE"; then
    ASSET_NAME="$candidate"
    ASSET_URL="$URL"
    break
  fi
done

if [[ -z "$ASSET_NAME" ]]; then
  echo "Error: no matching asset found for ${OS}-${ARCH} (version: ${VERSION:-latest}). Tried:" >&2
  for c in "${ASSET_CANDIDATES[@]}"; do echo "  - $c" >&2; done
  exit 1
fi

log "Selected asset: $ASSET_NAME"
log "Download URL: $ASSET_URL"

WORK="$TMPDIR/work"; mkdir -p "$WORK"
EXTRACTED_DIR="$WORK/extracted"; mkdir -p "$EXTRACTED_DIR"

if tar -tf "$ARCHIVE" >/dev/null 2>&1; then
  tar -xzf "$ARCHIVE" -C "$EXTRACTED_DIR"
else
  if command -v unzip >/dev/null 2>&1; then
  	unzip -q "$ARCHIVE" -d "$EXTRACTED_DIR"
  else
  	echo "Error: unknown archive format; install 'unzip'" >&2
  	exit 1
  fi
fi

BIN_PATH=""
while IFS= read -r -d '' f; do
  base=$(basename "$f")
  if [[ "$base" == "gman" ]]; then
  	BIN_PATH="$f"
  	break
  fi
done < <(find "$EXTRACTED_DIR" -type f -print0)

if [[ -z "$BIN_PATH" ]]; then
	echo "Error: could not find 'gman' binary in the archive" >&2
	exit 1
fi

chmod +x "$BIN_PATH"
install -m 0755 "$BIN_PATH" "${BIN_DIR}/gman"

log "Installed: ${BIN_DIR}/gman"

case ":$PATH:" in
  *":${BIN_DIR}:"*) ;;
  *)
    log "Note: ${BIN_DIR} is not in PATH. Add it, e.g.:"
    log "  export PATH=\"${BIN_DIR}:\$PATH\""
    ;;
esac

log "Done. Try: gman --help"

