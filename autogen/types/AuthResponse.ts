export interface AuthResponse {
  user: UserResponse;
  token: SecretString;
  expires_at: string;
}
