import type { UserResponse } from './UserResponse';

/** Branded type for sensitive string data. Handle securely - do not log or expose. */
export type SecretString = string & { readonly __brand: 'SecretString' };

export interface AuthResponse {
  user: UserResponse;
  token: SecretString;
  expires_at: string;
}
