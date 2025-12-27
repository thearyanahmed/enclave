import type { SecretString } from './SecretString';

export interface AccessToken {
  token: SecretString;
  user_id: number;
  name?: string | null;
  expires_at: string;
  created_at: string;
}
