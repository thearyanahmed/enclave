export interface LoginAttempt {
  email: string;
  success: boolean;
  ip_address?: string | null;
  attempted_at: string;
}
