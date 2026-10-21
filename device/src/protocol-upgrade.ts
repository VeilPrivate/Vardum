/**
 * @veil/device — one-time protocol upgrade: the hard cut to the current
 * 1:1 protocol (b54 Batch A: veil-ratchet-5; Batch C: veil-ratchet-6).
 *
 *  - 1:1 sessions whose stored ratchet predates RATCHET_PROTOCOL_LATEST
 *    (ratchet-3/-4: P-256, optional PQ; ratchet-5: no responder-IK term,
 *    shared signing key, dials outside the transcript) are ENDED on the relay, so both sides
 *    see the chat as ended and start a new one. Their local state stays for
 *    history; the engine refuses to use it (LegacySessionError).
 *  - Private-group MEMBER records from before b54 have no creator IK, so no
 *    rekey could ever be verified: they are marked ended. Creator records
 *    backfill the creator IK (their own) and an empty local deny list.
 *    Lounge / forum records are untouched (they follow their descriptor).
 *
 * Group envelopes need no migration here: Batch C (A2) changes only the
 * per-message signature format, and old-format envelopes are refused on receipt.
 *
 * Idempotent; a marker key records completion so it runs once per device
 * PER PROTOCOL BUMP (a new bump = a new marker key, so b54 phones run it again).
 */
import { isLegacySessionState } from '../../crypto-core/src/ratchet';
import type { VeilStorage } from '../../crypto-core/src/storage-adapter';
import type { VeilRelay } from './relay';
import type { SessionStore } from './session-store';
import { GROUP_KEY_PREFIX, GROUP_SEND_SUFFIX, loadGroupRecord, saveGroupRecord } from './groups';

const MIGRATED_KEY = 'veil_c6_protocol_upgrade'; // Batch C (veil-ratchet-6); was veil_b54_protocol_upgrade

export interface ProtocolUpgradeResult { endedChats: number; endedGroups: number; backfilledGroups: number; alreadyDone: boolean }

export async function runProtocolUpgrade(
  deps: { relay: VeilRelay; sessions: SessionStore; storage: VeilStorage },
  clientId: string,
  veilId?: string,
): Promise<ProtocolUpgradeResult> {
  if ((await deps.storage.get(MIGRATED_KEY)) === 'done') {
    return { endedChats: 0, endedGroups: 0, backfilledGroups: 0, alreadyDone: true };
  }
  let endedChats = 0;
  let endedGroups = 0;
  let backfilledGroups = 0;

  // 1:1 chats — participant-scoped relay listing; group rows are skipped
  // (their session ratchet is only a relay credential carrier).
  const r = await deps.relay.sessionList(clientId, veilId);
  const list = (r.data as { data?: unknown[] })?.data
    ?? (r.data as { sessions?: unknown[] })?.sessions
    ?? (r.data as unknown as unknown[]);
  for (const raw of Array.isArray(list) ? list : []) {
    const rec = raw as Record<string, unknown>;
    const token = String(rec.token ?? '');
    if (!token || rec.group_token || String(rec.state ?? '') === 'ended') continue;
    const sealed = await deps.sessions.load(token).catch(() => null);
    if (!sealed || !isLegacySessionState(sealed)) continue;
    try {
      await deps.relay.sessionEnd(token, (sealed as { writeSecret?: string | null }).writeSecret ?? null, clientId);
      endedChats += 1;
    } catch (e) {
      console.warn('[veil-upgrade] could not end a legacy chat on the relay', { token: token.slice(0, 4), msg: String((e as Error)?.message ?? e) });
    }
  }

  // private groups
  for (const key of await deps.storage.keys(GROUP_KEY_PREFIX)) {
    if (key.endsWith(GROUP_SEND_SUFFIX)) continue; // Batch H: the send counter item, not a record
    const rec = await loadGroupRecord(deps.storage, key.slice(GROUP_KEY_PREFIX.length)).catch(() => null);
    if (!rec || rec.creatorIkPubB64) continue;
    if (rec.role === 'creator') {
      await saveGroupRecord(deps.storage, { ...rec, creatorIkPubB64: rec.ikPubB64, evictedIks: rec.evictedIks ?? [] });
      backfilledGroups += 1;
    } else if (rec.role === 'member' && !rec.sessionEnded) {
      await saveGroupRecord(deps.storage, { ...rec, sessionEnded: true });
      endedGroups += 1;
    }
  }

  await deps.storage.set(MIGRATED_KEY, 'done');
  return { endedChats, endedGroups, backfilledGroups, alreadyDone: false };
}
