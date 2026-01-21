#!/usr/bin/env bash

# Stacks Core Setup Script
# This script sets up the development environment for stacks-core

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_info() {
  echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
  echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
  echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
  echo -e "${RED}[ERROR]${NC} $1"
}

command_exists() {
  command -v "$1" >/dev/null 2>&1
}

print_info "Starting stacks-core development environment setup..."

print_info "Checking prerequisites..."

if ! command_exists curl; then
  print_error "curl is required. Please install curl and rerun this script."
  exit 1
fi

if ! command_exists rustc; then
  print_info "Rust not found. Installing Rust via rustup..."
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
  # shellcheck disable=SC1090
  source "$HOME/.cargo/env"
fi

print_info "Updating Rust toolchain and installing components..."
rustup update
rustup component add rustfmt clippy

print_success "Rust toolchain ready."

print_info "Building stacks-core (this may take a while)..."
cargo build

print_success "Build complete."

print_info "Setting up environment file..."
if [[ ! -f ".env" ]]; then
  cat > .env << EOF
# Stacks Core Environment Variables
STACKS_NODE_CONFIG=./stacks-node/conf/dev-xenon-miner.toml
STACKS_NODE_RPC_PORT=20443
STACKS_NODE_P2P_PORT=20444
EOF
  print_success ".env file created."
else
  print_info ".env file already exists."
fi

if command_exists docker; then
  print_info "Docker detected. You can run: docker-compose up -d"
else
  print_warning "Docker not found. Docker workflows will be unavailable."
fi

print_success "Setup complete!"
echo ""
print_info "Next steps:"
echo "  1. Start a dev node: make node-dev"
echo "  2. Run tests: make test"
echo "  3. Build release: make build-release"
echo "  4. Use Docker: docker-compose up -d"