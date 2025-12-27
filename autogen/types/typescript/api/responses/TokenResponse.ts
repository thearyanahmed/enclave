/** Branded type for sensitive string data. Handle securely - do not log or expose. */
export type SecretString = string & { readonly __brand: 'SecretString' };

export interface TokenResponse {
  token: SecretString;
  expires_at: string;
}
