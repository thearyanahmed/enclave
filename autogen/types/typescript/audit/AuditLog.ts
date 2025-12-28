import type { AuditEventType } from './AuditEventType';

export interface AuditLog {
  id: number;
  user_id: number | null;
  event_type: AuditEventType;
  ip_address: string | null;
  user_agent: string | null;
  metadata: string | null;
  created_at: string;
}
