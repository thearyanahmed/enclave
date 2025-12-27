import type { SecretString } from './SecretString';

export interface MagicLinkToken {
  token: SecretString;
  user_id: number;
  expires_at: string;
  created_at: string;
}
