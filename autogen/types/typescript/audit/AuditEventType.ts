export type AuditEventType =
  | { type: "Signup" }
  | { type: "LoginSuccess" }
  | { type: "LoginFailed" }
  | { type: "Logout" }
  | { type: "PasswordChanged" }
  | { type: "PasswordResetRequested" }
  | { type: "PasswordReset" }
  | { type: "EmailVerificationSent" }
  | { type: "EmailVerified" }
  | { type: "TokenRefreshed" }
  | { type: "AccountDeleted" };
