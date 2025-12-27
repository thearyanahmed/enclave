export interface EmailVerificationToken {
  token: SecretString;
  user_id: number;
  expires_at: string;
  created_at: string;
}
