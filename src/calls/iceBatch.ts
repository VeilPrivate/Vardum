/**
 * Call quality (20 Oct 2026): ICE candidates in batches.
 *
 * Every call signal is its own ratchet message: encrypt, save the ratchet
 * state, upload, and the other phone picks it up on its next poll and
 * decrypts it the same way. One message per candidate made call setup slow
 * (the owner's test: ~5 s from Accept to audio). Candidates that arrive
 * within a short window now go as ONE signal.
 *
 * Compatibility: the batched signal still carries the first candidate in
 * `cand`, which is all a build before this change reads, so a call between
 * an old and a new build still connects (on the first relay candidate).
 */

/** Most candidates one signal will carry (relay-only gathering yields a handful). */
export const MAX_CANDS_PER_SIGNAL = 16;

export interface IceBatcher {
  push(cand: string): void;
  /** send whatever is queued now (end of gathering, or the call is answered) */
  flush(): void;
}

export function createIceBatcher(send: (cands: string[]) => Promise<void>, windowMs = 250): IceBatcher {
  let queue: string[] = [];
  let timer: ReturnType<typeof setTimeout> | null = null;
  const flush = () => {
    if (timer) { clearTimeout(timer); timer = null; }
    while (queue.length) {
      const batch = queue.slice(0, MAX_CANDS_PER_SIGNAL);
      queue = queue.slice(MAX_CANDS_PER_SIGNAL);
      void send(batch).catch(() => undefined);
    }
  };
  return {
    push(cand: string) {
      queue.push(cand);
      if (!timer) timer = setTimeout(flush, windowMs);
    },
    flush,
  };
}

/** The ice signal body for a batch: `cand` (first, for older builds) + `cands` (all). */
export function iceSignalBody(callId: string, cands: string[]): { __veil_call: 1; op: 'ice'; call_id: string; cand: string; cands: string[] } {
  return { __veil_call: 1, op: 'ice', call_id: callId, cand: cands[0], cands: cands.slice(0, MAX_CANDS_PER_SIGNAL) };
}

/** Every candidate a received ice signal carries (old single or new batch). */
export function candsOf(sig: { cand?: unknown; cands?: unknown }): string[] {
  if (Array.isArray(sig.cands)) {
    return sig.cands.filter((c): c is string => typeof c === 'string').slice(0, MAX_CANDS_PER_SIGNAL);
  }
  return typeof sig.cand === 'string' ? [sig.cand] : [];
}

/** True when a candidate (our JSON form) is already an a=candidate line in
 *  the SDP, so it needn't also be sent on its own (21 Oct 2026: candidates
 *  ride inside the offer/answer). */
export function candidateInSdp(sdp: string, candJson: string): boolean {
  try {
    const c = (JSON.parse(candJson) as { candidate?: unknown }).candidate;
    if (typeof c !== 'string' || !c) return false;
    const line = c.startsWith('candidate:') ? c : 'candidate:' + c;
    return sdp.split(/\r?\n/).some((l) => l.trim() === 'a=' + line);
  } catch { return false; }
}
