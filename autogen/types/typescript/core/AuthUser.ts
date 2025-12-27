export interface AuthUser {
  id: number;
  email: string;
  name: string;
  hashed_password: string;
  email_verified_at?: string | null;
  created_at: string;
  updated_at: string;
}
