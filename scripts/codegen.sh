#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$ROOT_DIR"

OUTPUT_BASE="./autogen/types"

rm -rf "$OUTPUT_BASE"

# TypeScript types
TS_BASE="$OUTPUT_BASE/typescript"

cargo run -q -p enclave-codegen -- \
    --source ./src \
    --output "$TS_BASE/core" \
    --format typescript \
    --types "AuthError:lib.rs" \
    --types "AuthUser:repository/user.rs" \
    --types "ValidationError:validators/mod.rs"

cargo run -q -p enclave-codegen -- \
    --source ./src \
    --output "$TS_BASE/tokens" \
    --format typescript \
    --types "AccessToken:repository/token.rs" \
    --types "PasswordResetToken:repository/password_reset.rs" \
    --types "EmailVerificationToken:repository/email_verification.rs" \
    --types "MagicLinkToken:repository/magic_link.rs" \
    --types "LoginAttempt:repository/rate_limiter.rs"

cargo run -q -p enclave-codegen -- \
    --source ./src \
    --output "$TS_BASE/jwt" \
    --format typescript \
    --types "TokenPair:jwt/service.rs" \
    --types "TokenType:jwt/claims.rs" \
    --types "JwtClaims:jwt/claims.rs"

cargo run -q -p enclave-codegen -- \
    --source ./src \
    --output "$TS_BASE/audit" \
    --format typescript \
    --types "AuditEventType:repository/audit_log.rs" \
    --types "AuditLog:repository/audit_log.rs"

cargo run -q -p enclave-codegen -- \
    --source ./src \
    --output "$TS_BASE/api/requests" \
    --format typescript \
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

cargo run -q -p enclave-codegen -- \
    --source ./src \
    --output "$TS_BASE/api/responses" \
    --format typescript \
    --types "UserResponse:api/types.rs" \
    --types "AuthResponse:api/types.rs" \
    --types "TokenResponse:api/types.rs" \
    --types "MessageResponse:api/types.rs" \
    --types "ErrorResponse:api/types.rs"

cargo run -q -p enclave-codegen -- \
    --source ./src \
    --output "$TS_BASE/teams" \
    --format typescript \
    --types "Team:teams/types.rs" \
    --types "TeamMembership:teams/types.rs" \
    --types "TeamInvitation:teams/types.rs" \
    --types "UserTeamContext:teams/types.rs"

cargo run -q -p enclave-codegen -- \
    --source ./src \
    --output "$TS_BASE/teams/requests" \
    --format typescript \
    --types "CreateTeamRequest:api/types.rs" \
    --types "UpdateTeamRequest:api/types.rs" \
    --types "TransferOwnershipRequest:api/types.rs" \
    --types "AddMemberRequest:api/types.rs" \
    --types "InviteMemberRequest:api/types.rs" \
    --types "UpdateMemberRoleRequest:api/types.rs" \
    --types "AcceptInvitationRequest:api/types.rs" \
    --types "SetCurrentTeamRequest:api/types.rs"

cargo run -q -p enclave-codegen -- \
    --source ./src \
    --output "$TS_BASE/teams/responses" \
    --format typescript \
    --types "TeamResponse:api/types.rs" \
    --types "TeamMembershipResponse:api/types.rs" \
    --types "TeamInvitationResponse:api/types.rs" \
    --types "UserTeamContextResponse:api/types.rs"

# JavaScript with JSDoc types
JS_BASE="$OUTPUT_BASE/javascript"

cargo run -q -p enclave-codegen -- \
    --source ./src \
    --output "$JS_BASE/core" \
    --format jsdoc \
    --types "AuthError:lib.rs" \
    --types "AuthUser:repository/user.rs" \
    --types "ValidationError:validators/mod.rs"

cargo run -q -p enclave-codegen -- \
    --source ./src \
    --output "$JS_BASE/tokens" \
    --format jsdoc \
    --types "AccessToken:repository/token.rs" \
    --types "PasswordResetToken:repository/password_reset.rs" \
    --types "EmailVerificationToken:repository/email_verification.rs" \
    --types "MagicLinkToken:repository/magic_link.rs" \
    --types "LoginAttempt:repository/rate_limiter.rs"

cargo run -q -p enclave-codegen -- \
    --source ./src \
    --output "$JS_BASE/jwt" \
    --format jsdoc \
    --types "TokenPair:jwt/service.rs" \
    --types "TokenType:jwt/claims.rs" \
    --types "JwtClaims:jwt/claims.rs"

cargo run -q -p enclave-codegen -- \
    --source ./src \
    --output "$JS_BASE/audit" \
    --format jsdoc \
    --types "AuditEventType:repository/audit_log.rs" \
    --types "AuditLog:repository/audit_log.rs"

cargo run -q -p enclave-codegen -- \
    --source ./src \
    --output "$JS_BASE/api/requests" \
    --format jsdoc \
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

cargo run -q -p enclave-codegen -- \
    --source ./src \
    --output "$JS_BASE/api/responses" \
    --format jsdoc \
    --types "UserResponse:api/types.rs" \
    --types "AuthResponse:api/types.rs" \
    --types "TokenResponse:api/types.rs" \
    --types "MessageResponse:api/types.rs" \
    --types "ErrorResponse:api/types.rs"

cargo run -q -p enclave-codegen -- \
    --source ./src \
    --output "$JS_BASE/teams" \
    --format jsdoc \
    --types "Team:teams/types.rs" \
    --types "TeamMembership:teams/types.rs" \
    --types "TeamInvitation:teams/types.rs" \
    --types "UserTeamContext:teams/types.rs"

cargo run -q -p enclave-codegen -- \
    --source ./src \
    --output "$JS_BASE/teams/requests" \
    --format jsdoc \
    --types "CreateTeamRequest:api/types.rs" \
    --types "UpdateTeamRequest:api/types.rs" \
    --types "TransferOwnershipRequest:api/types.rs" \
    --types "AddMemberRequest:api/types.rs" \
    --types "InviteMemberRequest:api/types.rs" \
    --types "UpdateMemberRoleRequest:api/types.rs" \
    --types "AcceptInvitationRequest:api/types.rs" \
    --types "SetCurrentTeamRequest:api/types.rs"

cargo run -q -p enclave-codegen -- \
    --source ./src \
    --output "$JS_BASE/teams/responses" \
    --format jsdoc \
    --types "TeamResponse:api/types.rs" \
    --types "TeamMembershipResponse:api/types.rs" \
    --types "TeamInvitationResponse:api/types.rs" \
    --types "UserTeamContextResponse:api/types.rs"
