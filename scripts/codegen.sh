#!/usr/bin/env bash
set -euo pipefail

# TypeScript code generator for enclave types
# Usage: ./scripts/codegen.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$ROOT_DIR"

cargo run -p enclave-codegen -- \
    --source ./src \
    --output ./autogen/types \
    --types "AuthUser:repository/user.rs" \
    --types "AuthError:lib.rs" \
    --types "UserResponse:api/types.rs" \
    --types "AuthResponse:api/types.rs" \
    --types "TokenResponse:api/types.rs" \
    --types "MessageResponse:api/types.rs" \
    --types "ErrorResponse:api/types.rs"
