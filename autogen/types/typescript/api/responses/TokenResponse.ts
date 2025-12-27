import type { SecretString } from './SecretString';

export interface TokenResponse {
  token: SecretString;
  expires_at: string;
}
