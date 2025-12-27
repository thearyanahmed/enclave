import type { ValidationError } from './ValidationError';

export type AuthError =
  | { type: "UserNotFound" }
  | { type: "UserAlreadyExists" }
  | { type: "InvalidCredentials" }
  | { type: "InvalidEmail" }
  | { type: "InvalidPassword" }
  | { type: "PasswordHashError" }
  | { type: "TokenExpired" }
  | { type: "TokenInvalid" }
  | { type: "EmailAlreadyVerified" }
  | { type: "TooManyAttempts" }
  | { type: "NotFound" }
  | { type: "Validation"; value: ValidationError }
  | { type: "ConfigurationError"; value: string }
  | { type: "DatabaseError"; value: string }
  | { type: "Internal"; value: string }
  | { type: "Other"; value: string };
