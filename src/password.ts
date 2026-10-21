/**
 * b199 (owner, Oct 16): the app-lock code is a PASSWORD — any characters
 * (letters, numbers, symbols, spaces), 4 to 50 long. Numeric passcodes set
 * before this keep working: digits are characters. The same rule covers the
 * optional Decoy and Duress codes. Nothing is trimmed — the exact text is the
 * password (a leading or trailing space counts).
 */
export const PASSWORD_MIN = 4;
export const PASSWORD_MAX = 50;

/** null when acceptable, otherwise a short reason to show the user */
export function passwordProblem(p: string): string | null {
  if (p.length < PASSWORD_MIN) return `Use at least ${PASSWORD_MIN} characters.`;
  if (p.length > PASSWORD_MAX) return `Use at most ${PASSWORD_MAX} characters.`;
  return null;
}
