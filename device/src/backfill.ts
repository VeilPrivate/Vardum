/**
 * @veil/device — deep-backlog pager with a deletion-safe backfill anchor
 * (audit doc 13, R1).
 *
 * The 1:1 sync (chat.ts, b196) and the forum inbox (lounge.ts, b195-r1) page
 * the relay NEWEST-FIRST and stop at the first page whose oldest row is
 * already processed. Their old fixed page cap (3 x 50 / 4 x 50) meant a
 * backlog deeper than one pass was never reached: pass 1 took the newest
 * rows, and every later pass stopped at page 0.
 *
 * Both receive paths are also ORDER-SENSITIVE: the 1:1 ratchet keeps at most
 * 100 skipped message keys per chain and the forum replay guard at most 64
 * skipped counters per sender, so decrypting the newest rows of a deep
 * backlog first permanently loses the oldest ones. The backlog therefore has
 * to be processed from its DEEP end, oldest-first.
 *
 * This pager walks down until it reaches the thread's end (short or empty
 * page) or a page whose oldest row is already processed, within a fetch cap
 * per pass. If the cap is hit first, it returns NO rows (nothing may be
 * processed above unreached older rows) and an anchor: the id and
 * created_date of the deepest row fetched, plus its position as a hint. The
 * next pass resumes the descent at the anchor instead of re-walking from the
 * top. The anchor is a row identity located by created_date, never an
 * offset: the position is only where the search starts, so sweeper
 * deletions and new arrivals can't make it skip rows. The caller clears it
 * whenever a pass reaches the end or a processed row (anchor: null).
 *
 * The caller bounds per-pass work by counting DEFINITIVE outcomes (rows
 * ledgered / marked known), not rows attempted, so rows that stay retryable
 * can't starve newer ones.
 */

export interface BackfillAnchor {
  /** id of the deepest row fetched by the unfinished descent */
  id: string;
  /** that row's created_date (the sort key) */
  at: string;
  /** its newest-first position when fetched — a search hint only */
  pos: number;
}

export interface BacklogPage {
  /** unprocessed rows, OLDEST-FIRST, de-duplicated; empty while descending */
  rows: Record<string, unknown>[];
  /** the anchor to persist (null = clear it) */
  anchor: BackfillAnchor | null;
  /** pages fetched this pass (for the sync log line) */
  pages: number;
}

export function parseAnchor(v: unknown): BackfillAnchor | null {
  if (!v || typeof v !== 'object') return null;
  const a = v as Record<string, unknown>;
  if (typeof a.id !== 'string' || !a.id || typeof a.at !== 'string' || !a.at) return null;
  const pos = Number(a.pos);
  return { id: a.id, at: a.at, pos: Number.isFinite(pos) && pos > 0 ? Math.floor(pos) : 0 };
}

const dateOf = (r: Record<string, unknown>): string => String(r.created_date ?? '');
const idOf = (r: Record<string, unknown>): string => String(r.id ?? '');

export async function pageBacklog(opts: {
  /** one newest-first page: sort '-created_date', skip, limit */
  fetchPage: (skip: number, limit: number) => Promise<Record<string, unknown>[]>;
  /** already definitively processed on this device */
  isKnown: (id: string) => boolean;
  pageSize: number;
  maxPages: number;
  anchor: BackfillAnchor | null;
}): Promise<BacklogPage> {
  const { fetchPage, isKnown, pageSize, maxPages } = opts;
  const anchor = opts.anchor;
  const collected: { row: Record<string, unknown>; pos: number }[] = []; // newest-first
  let pages = 0;
  let skip = 0;
  let done = false; // reached the thread's end or a processed row

  // take one fetched page into the collection; true = the descent is finished
  const take = (rows: Record<string, unknown>[], at: number, floor: string | null): boolean => {
    rows.forEach((row, i) => {
      if (floor === null || dateOf(row) <= floor) collected.push({ row, pos: at + i });
    });
    const oldestId = idOf(rows[rows.length - 1] ?? {});
    return rows.length < pageSize || (!!oldestId && isKnown(oldestId));
  };

  if (anchor) {
    // Locate the anchor by created_date, starting half a page above its last
    // known position. Rows above it are newer than it and are left for a
    // later top-down pass; the anchor row itself and everything at or below
    // its date are taken.
    skip = Math.max(0, anchor.pos - Math.floor(pageSize / 2));
    let restarted = skip === 0;
    let located = false;
    while (!located && pages < maxPages) {
      const rows = await fetchPage(skip, pageSize);
      pages++;
      if (!rows.length || dateOf(rows[0]) < anchor.at) {
        // past the end, or overshot (rows above the anchor were deleted):
        // search again from the top — positions only grow from there
        if (!restarted) { restarted = true; skip = 0; continue; }
        if (!rows.length) { done = true; break; } // thread now empty or nothing below
      }
      const oldest = dateOf(rows[rows.length - 1]);
      if (oldest > anchor.at && rows.length === pageSize) { skip += pageSize; continue; } // anchor deeper
      located = true;
      done = take(rows, skip, anchor.at);
    }
  } else {
    const rows = await fetchPage(0, pageSize);
    pages++;
    if (!rows.length) done = true;
    else done = take(rows, 0, null);
  }

  while (!done && pages < maxPages && collected.length) {
    skip += pageSize;
    const rows = await fetchPage(skip, pageSize);
    pages++;
    if (!rows.length) { done = true; break; }
    done = take(rows, skip, null);
  }

  if (!done) {
    // cap hit mid-descent: process nothing above the unreached rows; resume
    // below the deepest row next pass
    const deepest = collected[collected.length - 1];
    const id = deepest ? idOf(deepest.row) : '';
    // (cap spent while still locating: keep the anchor, start lower next time)
    const next = deepest && id
      ? { id, at: dateOf(deepest.row), pos: deepest.pos }
      : anchor && { ...anchor, pos: skip + Math.floor(pageSize / 2) };
    return { rows: [], anchor: next, pages };
  }

  const seen = new Set<string>();
  const rows: Record<string, unknown>[] = [];
  for (let i = collected.length - 1; i >= 0; i--) {
    const r = collected[i].row;
    const id = idOf(r);
    if (!id || seen.has(id) || isKnown(id)) continue;
    seen.add(id);
    rows.push(r);
  }
  return { rows, anchor: null, pages };
}
