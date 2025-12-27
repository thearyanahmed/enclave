/** Branded type for sensitive string data. Handle securely - do not log or expose. */
export type SecretString = string & { readonly __brand: 'SecretString' };

export interface MagicLinkToken {
  token: SecretString;
  user_id: number;
  expires_at: string;
  created_at: string;
}
