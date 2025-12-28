/** Branded type for sensitive string data. Handle securely - do not log or expose. */
export type SecretString = string & { readonly __brand: 'SecretString' };

export interface AccessToken {
  token: SecretString;
  user_id: number;
  name: string | null;
  expires_at: string;
  created_at: string;
}
