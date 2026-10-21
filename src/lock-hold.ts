/**
 * b199 (owner report, Oct 17): the 1-minute inactivity auto-lock fired in
 * the middle of a vault download (a 24 MB container from the relay can take
 * longer than a minute), killing the transfer — "the first one or two opens
 * never load". A screen running a long, user-started job holds the
 * INACTIVITY lock off until it finishes. Backgrounding / locking the phone
 * still locks instantly (AppState path, untouched); this only pauses the
 * no-touch timer, and the timer restarts from zero when the hold ends.
 */
let holds = 0;
let holdSeq = 0;

/** b199 (ZTE device run): the PHONE's own screen timeout (30 s on a fresh
 *  Android) blanked the screen ~30 s into a ~60 s vault create; Android then
 *  cut the network and the upload failed. A hold now keeps the screen on too. */
function keepAwake(tag: string, on: boolean): void {
  try {
    const ka = require('expo-keep-awake') as typeof import('expo-keep-awake');
    if (on) void ka.activateKeepAwakeAsync(tag).then(() => console.log(`[veil-awake] screen held on (${tag})`)).catch((e) => console.log(`[veil-awake] hold FAILED (${tag}): ${(e as Error)?.message ?? e}`));
    else void ka.deactivateKeepAwake(tag).then(() => console.log(`[veil-awake] released (${tag})`)).catch(() => undefined);
  } catch (e) { console.log(`[veil-awake] module unavailable: ${(e as Error)?.message ?? e}`); }
}

/** Start a hold; call the returned function exactly when the job ends. */
export function holdAutoLock(): () => void {
  holds++;
  const tag = `veil-job-${++holdSeq}`;
  keepAwake(tag, true);
  let released = false;
  return () => {
    if (released) return;
    released = true;
    holds = Math.max(0, holds - 1);
    keepAwake(tag, false);
  };
}

export function autoLockHeld(): boolean {
  return holds > 0;
}

/**
 * b199 (owner, ZTE device run Oct 17): on Android the photo picker, camera,
 * file picker, share sheet and permission prompts are separate activities —
 * opening one sends Vardum to 'background', which engaged the passcode lock
 * mid-send (every photo/voice note from the ZTE locked the app). Call this
 * right before Vardum itself opens such a screen: the NEXT backgrounding
 * within 2 minutes is expected and does not lock. Cleared on return to the
 * foreground, so any other departure still locks instantly.
 */
let systemSheetUntil = 0;
export function expectSystemSheet(ms = 120_000): void { systemSheetUntil = Date.now() + ms; }
export function systemSheetExpected(): boolean { return Date.now() < systemSheetUntil; }
export function systemSheetDone(): void { systemSheetUntil = 0; }

/** Run `open` (a picker / prompt / share sheet) with the departure expected
 *  only while it is open — cleared the moment it returns or throws. */
export async function withSystemSheet<T>(open: () => Promise<T>): Promise<T> {
  expectSystemSheet();
  try { return await open(); } finally { systemSheetDone(); }
}
