export interface TeamInvitationResponse {
  id: number;
  team_id: number;
  email: string;
  role: string;
  invited_by: number;
  expires_at: string;
  accepted_at?: string | null;
  created_at: string;
}
