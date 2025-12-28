export interface TeamInvitation {
  id: number;
  team_id: number;
  email: string;
  role: string;
  token_hash: string;
  invited_by: number;
  expires_at: string;
  accepted_at: string | null;
  created_at: string;
}
