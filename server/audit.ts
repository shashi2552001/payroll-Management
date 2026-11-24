import type Database from 'better-sqlite3';
import crypto from 'crypto';

export interface AuditEntryInput {
  actorUserId?: string | null;
  actorLabel: string;
  actorRole: string;
  action: string;
  entityType: string;
  entityId?: string | null;
  beforeState?: unknown;
  afterState?: unknown;
  ipAddress?: string | null;
  userAgent?: string | null;
  metadata?: unknown;
}

export function recordAudit(db: Database.Database, entry: AuditEntryInput): void {
  const id = `aud_${crypto.randomUUID()}`;
  const now = new Date().toISOString();
  db.prepare(`
    INSERT INTO audit_logs (
      id, actor_user_id, actor_label, actor_role, action,
      entity_type, entity_id, before_state_json, after_state_json,
      ip_address, user_agent, metadata_json, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    id,
    entry.actorUserId ?? null,
    entry.actorLabel,
    entry.actorRole,
    entry.action,
    entry.entityType,
    entry.entityId ?? null,
    entry.beforeState !== undefined ? JSON.stringify(entry.beforeState) : null,
    entry.afterState !== undefined ? JSON.stringify(entry.afterState) : null,
    entry.ipAddress ?? null,
    entry.userAgent ?? null,
    entry.metadata !== undefined ? JSON.stringify(entry.metadata) : null,
    now,
  );
}

export function createNotification(
  db: Database.Database,
  params: {
    recipientUserId: string;
    title: string;
    message: string;
    category?: 'info' | 'action' | 'success' | 'warning';
    relatedEntityType?: string;
    relatedEntityId?: string;
  },
): string {
  const id = `ntf_${crypto.randomUUID()}`;
  const now = new Date().toISOString();
  db.prepare(`
    INSERT INTO notifications (
      id, recipient_user_id, title, message, category,
      related_entity_type, related_entity_id, is_read, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)
  `).run(
    id,
    params.recipientUserId,
    params.title,
    params.message,
    params.category || 'info',
    params.relatedEntityType ?? null,
    params.relatedEntityId ?? null,
    now,
  );
  return id;
}
