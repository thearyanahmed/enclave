#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$ROOT_DIR"

OUTPUT_BASE="./autogen/types"

rm -rf "$OUTPUT_BASE"

# Core types
cargo run -q -p enclave-codegen -- \
    --source ./src \
    --output "$OUTPUT_BASE/core" \
    --types "AuthError:lib.rs" \
    --types "AuthUser:repository/user.rs" \
    --types "ValidationError:validators/mod.rs"

# Token types
cargo run -q -p enclave-codegen -- \
    --source ./src \
    --output "$OUTPUT_BASE/tokens" \
    --types "AccessToken:repository/token.rs" \
    --types "PasswordResetToken:repository/password_reset.rs" \
    --types "EmailVerificationToken:repository/email_verification.rs" \
    --types "MagicLinkToken:repository/magic_link.rs" \
    --types "LoginAttempt:repository/rate_limiter.rs"

# JWT types
cargo run -q -p enclave-codegen -- \
    --source ./src \
    --output "$OUTPUT_BASE/jwt" \
    --types "TokenPair:jwt/service.rs" \
    --types "TokenType:jwt/claims.rs" \
    --types "JwtClaims:jwt/claims.rs"

# Audit types
cargo run -q -p enclave-codegen -- \
    --source ./src \
    --output "$OUTPUT_BASE/audit" \
    --types "AuditEventType:repository/audit_log.rs" \
    --types "AuditLog:repository/audit_log.rs"

# API Request types
cargo run -q -p enclave-codegen -- \
    --source ./src \
    --output "$OUTPUT_BASE/api/requests" \
    --types "RegisterRequest:api/types.rs" \
    --types "LoginRequest:api/types.rs" \
    --types "ForgotPasswordRequest:api/types.rs" \
    --types "ResetPasswordRequest:api/types.rs" \
    --types "ChangePasswordRequest:api/types.rs" \
    --types "UpdateUserRequest:api/types.rs" \
    --types "RefreshTokenRequest:api/types.rs" \
    --types "VerifyEmailRequest:api/types.rs" \
    --types "MagicLinkRequest:api/types.rs" \
    --types "VerifyMagicLinkRequest:api/types.rs"

# API Response types
cargo run -q -p enclave-codegen -- \
    --source ./src \
    --output "$OUTPUT_BASE/api/responses" \
    --types "UserResponse:api/types.rs" \
    --types "AuthResponse:api/types.rs" \
    --types "TokenResponse:api/types.rs" \
    --types "MessageResponse:api/types.rs" \
    --types "ErrorResponse:api/types.rs"

# Teams types
cargo run -q -p enclave-codegen -- \
    --source ./src \
    --output "$OUTPUT_BASE/teams" \
    --types "Team:teams/types.rs" \
    --types "TeamMembership:teams/types.rs" \
    --types "TeamInvitation:teams/types.rs" \
    --types "UserTeamContext:teams/types.rs"

# Teams API Request types
cargo run -q -p enclave-codegen -- \
    --source ./src \
    --output "$OUTPUT_BASE/teams/api/requests" \
    --types "CreateTeamRequest:api/types.rs" \
    --types "UpdateTeamRequest:api/types.rs" \
    --types "TransferOwnershipRequest:api/types.rs" \
    --types "AddMemberRequest:api/types.rs" \
    --types "InviteMemberRequest:api/types.rs" \
    --types "UpdateMemberRoleRequest:api/types.rs" \
    --types "AcceptInvitationRequest:api/types.rs" \
    --types "SetCurrentTeamRequest:api/types.rs"

# Teams API Response types
cargo run -q -p enclave-codegen -- \
    --source ./src \
    --output "$OUTPUT_BASE/teams/api/responses" \
    --types "TeamResponse:api/types.rs" \
    --types "TeamMembershipResponse:api/types.rs" \
    --types "TeamInvitationResponse:api/types.rs" \
    --types "UserTeamContextResponse:api/types.rs"
