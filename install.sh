#!/usr/bin/env bash
# SecForge installer — Linux, macOS, WSL2, Termux.
#
#   curl -fsSL https://raw.githubusercontent.com/ThanhHai151/Security-Forge-AI/main/install.sh | bash
#
# Clones SecForge, sets up an isolated Python venv, builds the Web UI (if Node is
# available), and puts a `secforge` command on your PATH. Re-running updates in place.
#
# Override anything via env vars, e.g.:
#   SECFORGE_REPO=https://github.com/ThanhHai151/Security-Forge-AI.git SECFORGE_BRANCH=main bash install.sh
set -euo pipefail

# ── Config (override via env) ────────────────────────────────────────────────
REPO_URL="${SECFORGE_REPO:-https://github.com/ThanhHai151/Security-Forge-AI.git}"
BRANCH="${SECFORGE_BRANCH:-main}"
INSTALL_DIR="${SECFORGE_HOME:-$HOME/.secforge}"

# ── Pretty output ────────────────────────────────────────────────────────────
info()  { printf '\033[36m==>\033[0m %s\n' "$*"; }
warn()  { printf '\033[33m[!]\033[0m %s\n' "$*"; }
err()   { printf '\033[31m[x]\033[0m %s\n' "$*" >&2; }
die()   { err "$*"; exit 1; }
have()  { command -v "$1" >/dev/null 2>&1; }

# ── Detect platform ──────────────────────────────────────────────────────────
PLATFORM="linux"; BIN_DIR="$HOME/.local/bin"; PKG=""
detect_pkg_manager() {
  # First match wins. Each `have` guarded so `set -e` never trips on a miss.
  if   have pkg && [ "$PLATFORM" = "termux" ]; then PKG="pkg"
  elif have brew;      then PKG="brew"
  elif have apt-get;   then PKG="apt"
  elif have dnf;       then PKG="dnf"
  elif have pacman;    then PKG="pacman"
  else PKG=""; fi
}
detect_platform() {
  case "${PREFIX:-}" in
    *com.termux*) PLATFORM="termux"; BIN_DIR="$PREFIX/bin" ;;
    *)
      if [ "$(uname -s)" = "Darwin" ]; then
        PLATFORM="macos"
      elif grep -qiE "(microsoft|wsl)" /proc/version 2>/dev/null; then
        PLATFORM="wsl2"
      else
        PLATFORM="linux"
      fi ;;
  esac
  detect_pkg_manager
  info "Platform: $PLATFORM   package manager: ${PKG:-none}   bin dir: $BIN_DIR"
}

# ── Install a system package by best effort ──────────────────────────────────
pkg_install() {
  local pkgs="$*"
  case "$PKG" in
    pkg)    pkg install -y $pkgs ;;
    brew)   brew install $pkgs ;;
    apt)    sudo apt-get update -qq && sudo apt-get install -y $pkgs ;;
    dnf)    sudo dnf install -y $pkgs ;;
    pacman) sudo pacman -Sy --noconfirm $pkgs ;;
    *)      return 1 ;;
  esac
}

# ── Resolve a Python >= 3.11 interpreter ─────────────────────────────────────
PY=""
find_python() {
  for c in python3.13 python3.12 python3.11 python3 python; do
    if have "$c" && "$c" -c 'import sys; raise SystemExit(0 if sys.version_info[:2]>=(3,11) else 1)' 2>/dev/null; then
      PY="$c"; return 0
    fi
  done
  return 1
}

ensure_prereqs() {
  have git || { warn "git missing — installing"; pkg_install git || die "install git manually"; }
  if ! find_python; then
    warn "Python >= 3.11 missing — installing"
    case "$PKG" in
      pkg)  pkg_install python ;;
      brew) pkg_install python@3.12 ;;
      apt)  pkg_install python3 python3-venv python3-pip ;;
      *)    pkg_install python3 || true ;;
    esac
    find_python || die "Python >= 3.11 required. Install it and re-run."
  fi
  info "Python: $($PY --version)"
  # Node is optional — only needed to build the Web UI. TUI works without it.
  if ! have npm; then
    warn "Node/npm not found — will install if possible (needed for the Web UI)."
    case "$PKG" in
      pkg)  pkg_install nodejs || true ;;
      brew) pkg_install node || true ;;
      apt)  pkg_install nodejs npm || true ;;
      dnf)  pkg_install nodejs npm || true ;;
      pacman) pkg_install nodejs npm || true ;;
    esac
  fi
}

# ── Clone or update the repo ─────────────────────────────────────────────────
fetch_repo() {
  if [ -d "$INSTALL_DIR/.git" ]; then
    info "Updating existing checkout in $INSTALL_DIR"
    git -C "$INSTALL_DIR" fetch --depth 1 origin "$BRANCH"
    git -C "$INSTALL_DIR" reset --hard "origin/$BRANCH"
  else
    info "Cloning $REPO_URL -> $INSTALL_DIR"
    git clone --depth 1 --branch "$BRANCH" "$REPO_URL" "$INSTALL_DIR"
  fi
}

# ── Python venv + package install ────────────────────────────────────────────
setup_python() {
  info "Creating virtualenv at $INSTALL_DIR/.venv"
  "$PY" -m venv "$INSTALL_DIR/.venv"
  # shellcheck disable=SC1091
  . "$INSTALL_DIR/.venv/bin/activate"
  python -m pip install --quiet --upgrade pip
  info "Installing SecForge (Python)…"
  python -m pip install --quiet -e "$INSTALL_DIR"
  deactivate
}

# ── Build the Web UI (optional) ──────────────────────────────────────────────
build_frontend() {
  if have npm && [ -f "$INSTALL_DIR/frontend/package.json" ]; then
    info "Building the Web UI (npm)…"
    ( cd "$INSTALL_DIR/frontend" && npm install --no-fund --no-audit && npm run build )
  else
    warn "Skipping Web UI build (npm not available). The Terminal UI will still work."
    warn "Later: cd \"$INSTALL_DIR/frontend\" && npm install && npm run build"
  fi
}

# ── Put `secforge` on PATH ───────────────────────────────────────────────────
install_shim() {
  mkdir -p "$BIN_DIR"
  local shim="$BIN_DIR/secforge"
  cat > "$shim" <<EOF
#!/usr/bin/env bash
# SecForge launcher shim (generated by install.sh)
exec "$INSTALL_DIR/.venv/bin/secforge" "\$@"
EOF
  chmod +x "$shim"
  info "Installed launcher: $shim"

  case ":$PATH:" in
    *":$BIN_DIR:"*) ;;  # already on PATH
    *)
      warn "$BIN_DIR is not on your PATH."
      local rc="$HOME/.bashrc"
      if [ "$(basename "${SHELL:-bash}")" = "zsh" ]; then rc="$HOME/.zshrc"; fi
      printf '\n# Added by SecForge installer\nexport PATH="%s:$PATH"\n' "$BIN_DIR" >> "$rc"
      warn "Added $BIN_DIR to PATH in $rc — open a new shell or: export PATH=\"$BIN_DIR:\$PATH\""
      ;;
  esac
}

main() {
  detect_platform
  ensure_prereqs
  fetch_repo
  setup_python
  build_frontend
  install_shim
  echo
  info "Done. Start SecForge with:"
  printf '\n    \033[1msecforge\033[0m\n\n'
  info "It opens an interactive menu (Web UI / Terminal UI). The Web UI serves at http://localhost:61022"
}

main "$@"
