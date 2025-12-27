import type { SecretString } from './SecretString';
import type { UserResponse } from './UserResponse';

export interface AuthResponse {
  user: UserResponse;
  token: SecretString;
  expires_at: string;
}
