/**
 * Native Settings — NATIVE-PARITY-HANDOFF §2 exact structure:
 * Device protection / Messages / Private storage / Emergency access /
 * Security details / Support / Device transfer / Identity / Appearance /
 * Own VEIL / Account / About / Delete account. (Founder operations — Mission
 * Control — is admin-only and intentionally absent: for everyone else this
 * route is indistinguishable from a page that does not exist.)
 * One mode. Nothing pre-set — every control explained and yours to set.
 */
import React, { useCallback, useState } from 'react';
import Constants from 'expo-constants';
import { View, Text, TextInput, TouchableOpacity, ScrollView, StyleSheet, Alert, Linking, Share, ActivityIndicator, Image } from 'react-native';
import { useThemedPrompt } from './ThemedPrompt';
import { PASSWORD_MIN, PASSWORD_MAX, passwordProblem } from '../password';
import { useThemedShare } from './ThemedSheets';
import {
  type VeilSettings, BURN_OPTIONS, EXPIRY_OPTIONS, QUIET_OPTIONS,
  SELF_DESTRUCT_HOURS, SELF_DESTRUCT_WARN_HOURS, SELF_DESTRUCT_DAYS, selfDestructLeftLabel,
} from '../../vendor/device/src/settings';
import { isSilentAccountEmail } from '../../vendor/device/src/silent-auth';
import { SECURE_CHIP, BIOMETRIC, BIOMETRIC_SHORT, BETA_SOURCE, IS_ANDROID } from '../platformText';

export interface SettingsScreenProps {
  /** b199: open the full-screen VEIL QR */
  onShowQr?: () => void;
  settings: VeilSettings;
  onChange: (s: VeilSettings) => void;
  veilId: string | null;
  email?: string | null;
  /** open the privacy checkup wizard (web parity: /checkup from Settings) */
  onRunCheckup: () => void;
  /** app lock (passcode + Decoy + Duress) configured on this device */
  appLockEnabled: boolean;
  onSetAppLock: (pass: string, decoy?: string | null, duress?: string | null) => Promise<void>;
  onRemoveAppLock: (pass: string) => Promise<boolean>;
  /** Account category */
  onSignOut: () => void;
  onLockNow: () => void;
  onWipeDevice: () => Promise<void>;
  onDeleteAccount: () => Promise<void>;
  onViewIntro: () => void;
  onOpenTools: () => void;
  /** b141: re-open the Getting Started screen (carry-over after "Don't show
   * again") so the Founding Tester Lounge join is always reachable. */
  onOpenWelcome: () => void;
  /** Settings > Identity "Pinned contacts" cross-link (jumps to the Contacts tab) */
  onOpenContacts?: () => void;
  /** Play UGC: the device-local block list (Vardum IDs) and its unblock action */
  blockedIds?: string[];
  onUnblock?: (veilId: string) => Promise<void>;
  /** web app base for purchase + legal links */
  webBaseUrl: string;
  /** device transfer (web parity): build + upload the encrypted bundle */
  onCreateTransfer: () => Promise<{ link: string; sessionCount: number; groupCount: number; hasIdentity: boolean }>;
  /** device transfer: import sessions/identity from a pasted link */
  onReceiveTransfer: (link: string) => Promise<{ sessionCount: number; importedCount: number; skippedExisting: number; identityImported: boolean; identityKept: boolean }>;
  /** Identity (web parity): local-only 24-word phrase check against the current Veil ID */
  onVerifyPhrase: (phrase: string) => Promise<boolean>;
  /** b199 Account: move a made-up-email account's sign-in to the 24-word phrase */
  onSwitchToPhraseSignIn?: (phrase: string) => Promise<'ok' | 'wrong-phrase'>;
  /** Identity (web parity "Remove from this device"): drop this device's keyvault copy only */
  onRemoveIdentity: () => Promise<void>;
  /** "Generate new Veil ID" (landing headline feature): remove current identity then run the create flow */
  onGenerateNewVeilId: () => Promise<void>;
  /** open the identity create/restore flow (shown when this device has no identity) */
  onCreateIdentity: () => void;
}

// Real facts about THIS build, shown in Settings > About — never copied from
// the web app's own About card (which tracks a separate governance process:
// Security patch / Claims Register). PROTOCOL_VERSION must match VeilRelay's
// wire contract. b103: BUILD_NUMBER now derives from the NATIVE build number
// embedded in the binary (expo-constants) — a hardcoded constant here drifted
// from b99 through b103 and made the owner believe a fresh build was stale.
const APP_VERSION = '1.0.92';
const BUILD_NUMBER = (IS_ANDROID ? Constants.expoConfig?.android?.versionCode : Constants.expoConfig?.ios?.buildNumber) ?? Constants.nativeBuildVersion ?? '?';
const BUILD_DATE = '2026-10-12';
// b122: the native build number is frozen into the EAS binary and never
// changes across staged Metro patches — the owner cannot tell which staged
// source the device is actually running (b109-09-24 read identically for
// b118..b121). SOURCE_TAG is bumped with every staged zip so Settings > About
// always identifies the live JS tree.
const SOURCE_TAG = 'b196-r8';
// b185+: the engine is a SPEC-CONFORMANT Signal Double Ratchet with the single
// custom extension retained — per-step ML-KEM-768 post-quantum re-keying
// (PQ-hybrid). 'veil-ratchet-4' is retired; this string is user-facing and
// must match the audited protocol story, not the legacy engine.
// b188: keep the WIRE TAG first (new sessions still stamp veil-ratchet-4 —
// it is the fail-closed version marker separating the DR engine from legacy
// ratchet-3 sessions) and append the audited engine description.
const PROTOCOL_VERSION = 'Signal DR + ML-KEM-768';
const PROTOCOL_WIRE_TAG = 'wire tag: veil-ratchet-4 · PQ-hybrid';

interface Chip { label: string; value: number }

const BURN_CHIPS: Chip[] = BURN_OPTIONS;
const EXPIRE_CHIPS: Chip[] = EXPIRY_OPTIONS;
const RETENTION_CHIPS: Chip[] = QUIET_OPTIONS;

/**
 * OptionSheet — b199 Settings redesign (owner request, Oct 16 2026).
 *
 * A themed "pick one" overlay for the Settings timers: the row on the main
 * screen shows only the current value; tapping it opens this sheet with the
 * explanation, the "Defends against" line and the options. Same overlay
 * pattern as ThemedPrompt (absolute overlay, NOT RN Modal — the
 * modal/native-picker collision freeze from b25 stays avoided).
 *
 *   const { node, pick } = useOptionSheet();
 *   const v = await pick({ title, message, defends, options, value });  // null = cancelled
 */

export interface OptionSheetSpec<T extends number | string> {
  title: string;
  message?: string;
  defends?: string;
  options: { label: string; value: T }[];
  value: T;
}

interface Active {
  spec: OptionSheetSpec<number | string>;
  resolve: (v: number | string | null) => void;
}

export function useOptionSheet(): {
  node: React.ReactNode;
  pick: <T extends number | string>(spec: OptionSheetSpec<T>) => Promise<T | null>;
} {
  const [active, setActive] = useState<Active | null>(null);

  const pick = useCallback(<T extends number | string>(spec: OptionSheetSpec<T>) => (
    new Promise<T | null>((resolve) => {
      setActive({ spec: spec as OptionSheetSpec<number | string>, resolve: resolve as (v: number | string | null) => void });
    })
  ), []);

  const settle = useCallback((v: number | string | null) => {
    setActive((cur) => { cur?.resolve(v); return null; });
  }, []);

  const node = active ? (
    <View style={sheetStyles.backdrop}>
      <TouchableOpacity style={StyleSheet.absoluteFill} activeOpacity={1} onPress={() => settle(null)} />
      <View style={sheetStyles.card}>
        <Text style={sheetStyles.title}>{active.spec.title}</Text>
        {active.spec.message ? <Text style={sheetStyles.message}>{active.spec.message}</Text> : null}
        {active.spec.defends ? <Text style={sheetStyles.defends}>{active.spec.defends}</Text> : null}
        <ScrollView style={sheetStyles.list} bounces={false}>
          {active.spec.options.map((o) => {
            const on = o.value === active.spec.value;
            return (
              <TouchableOpacity key={String(o.value)} style={[sheetStyles.opt, on && sheetStyles.optOn]} onPress={() => settle(o.value)}>
                <Text style={[sheetStyles.optTxt, on && sheetStyles.optTxtOn]}>{o.label}</Text>
                {on ? <Text style={sheetStyles.tick}>✓</Text> : null}
              </TouchableOpacity>
            );
          })}
        </ScrollView>
        <TouchableOpacity style={sheetStyles.cancel} onPress={() => settle(null)}>
          <Text style={sheetStyles.cancelTxt}>Cancel</Text>
        </TouchableOpacity>
      </View>
    </View>
  ) : null;

  return { node, pick };
}

const sheetStyles = StyleSheet.create({
  backdrop: { ...StyleSheet.absoluteFillObject, backgroundColor: 'rgba(11,11,15,0.86)', justifyContent: 'center', alignItems: 'center', padding: 22, zIndex: 90 },
  card: { width: '100%', maxWidth: 420, maxHeight: '86%', backgroundColor: '#15151B', borderRadius: 14, borderWidth: 1, borderColor: '#24242D', padding: 18 },
  title: { color: '#FFFFFF', fontSize: 16, fontWeight: '800', marginBottom: 6 },
  message: { color: '#d69a5c', fontSize: 12, lineHeight: 17, marginBottom: 6 },
  defends: { color: '#8E9696', fontSize: 11, fontStyle: 'italic', lineHeight: 16, marginBottom: 12 },
  list: { flexGrow: 0 },
  opt: { flexDirection: 'row', alignItems: 'center', borderWidth: 1, borderColor: '#24242D', borderRadius: 10, paddingVertical: 12, paddingHorizontal: 14, marginBottom: 8 },
  optOn: { borderColor: '#FFFFFF', backgroundColor: 'rgba(255,255,255,0.08)' },
  optTxt: { color: '#C9CFCE', fontSize: 14, flex: 1 },
  optTxtOn: { color: '#FFFFFF', fontWeight: '700' },
  tick: { color: '#FFFFFF', fontSize: 14, fontWeight: '800' },
  cancel: { borderWidth: 1, borderColor: '#24242D', borderRadius: 10, paddingVertical: 10, alignItems: 'center', marginTop: 4 },
  cancelTxt: { color: '#8E9696', fontSize: 13, fontWeight: '600' },
});

// b199 Settings redesign (owner request, Oct 16 2026): one line per setting,
// the current value on the right, explanations one tap away (OptionSheet /
// themed info sheets) instead of paragraphs on the main screen.

const EXPIRE_CHIPS_SHORT: Chip[] = [
  { label: '12 hours', value: 43200 }, { label: '24 hours', value: 86400 }, { label: '36 hours', value: 129600 },
  { label: '48 hours', value: 172800 }, { label: '30 days', value: 2592000 },
];

function labelFor(chips: Chip[], value: number): string {
  return chips.find((c) => c.value === value)?.label ?? EXPIRE_CHIPS.find((c) => c.value === value)?.label ?? '—';
}

/** A titled group of rows (iOS-style inset list). */
function Group({ title, children, note }: { title: string; children: React.ReactNode; note?: string }) {
  return (
    <View style={styles.groupWrap}>
      <Text style={styles.groupTitle}>{title}</Text>
      <View style={styles.group}>{children}</View>
      {note ? <Text style={styles.groupNote}>{note}</Text> : null}
    </View>
  );
}

/** A tappable row: label on the left, value / chevron on the right. */
function Row({ label, value, onPress, danger, accent, chevron = true, sub, disabled, last }: {
  label: string; value?: string; onPress?: () => void; danger?: boolean; accent?: boolean;
  chevron?: boolean; sub?: string; disabled?: boolean; last?: boolean;
}) {
  return (
    <TouchableOpacity style={[styles.row, last && styles.rowLast]} onPress={onPress} disabled={disabled || !onPress} activeOpacity={0.7}>
      <View style={styles.rowMid}>
        <Text style={[styles.rowLabel, danger && styles.dangerTxt, accent && styles.accentTxt]}>{label}</Text>
        {sub ? <Text style={styles.rowSub}>{sub}</Text> : null}
      </View>
      {value ? <Text style={styles.rowValue} numberOfLines={1}>{value}</Text> : null}
      {chevron && onPress ? <Text style={styles.rowChevron}>›</Text> : null}
    </TouchableOpacity>
  );
}

/** A row with a real on/off switch. */
function SwitchRow({ label, on, onFlip, danger, sub, disabled, last }: {
  label: string; on: boolean; onFlip: () => void; danger?: boolean; sub?: string; disabled?: boolean; last?: boolean;
}) {
  return (
    <TouchableOpacity style={[styles.row, last && styles.rowLast]} onPress={onFlip} disabled={disabled} activeOpacity={0.7}>
      <View style={styles.rowMid}>
        <Text style={[styles.rowLabel, disabled && styles.rowLabelOff]}>{label}</Text>
        {sub ? <Text style={styles.rowSub}>{sub}</Text> : null}
      </View>
      <View style={[styles.switchTrack, on && (danger ? styles.switchTrackDanger : styles.switchTrackOn), disabled && styles.switchOff]}>
        <View style={[styles.switchKnob, on && styles.switchKnobOn]} />
      </View>
    </TouchableOpacity>
  );
}

/**
 * b199 (owner, Oct 16): the identity card — top of Settings AND top of
 * Conversations (it replaced the thin Veil ID strip that sat on every tab).
 * The nickname gets the same weight as the ID. Never renders the account
 * email (b107/b118); the sign-in type line was dropped too (owner, Oct 16).
 */
export function IdentityCard({ veilId, nickname, onShare, onShowQr, onCreateIdentity }: {
  veilId: string | null;
  nickname: string;
  onShare: () => void;
  /** b199: open the full-screen VEIL QR */
  onShowQr?: () => void;
  onCreateIdentity?: () => void;
}) {
  if (!veilId) {
    return (
      <View style={styles.idCard}>
        <Text style={styles.idCardKicker}>No identity on this phone</Text>
        <Text style={styles.idCardLine}>Create an identity with no phone number or email, or restore one with your 24 words.</Text>
        {onCreateIdentity ? (
          <TouchableOpacity style={styles.primaryBtn} onPress={onCreateIdentity}>
            <Text style={styles.primaryBtnTxt}>Create or restore identity</Text>
          </TouchableOpacity>
        ) : null}
      </View>
    );
  }
  return (
    <View style={styles.idCard}>
      <View style={styles.idCardHead}>
        <Image source={require('../../assets/logo.png')} style={styles.idCardLogo} />
        <View style={{ flex: 1 }}>
          <Text style={styles.idCardKicker}>Your Vardum ID</Text>
          <Text style={styles.idCardId} numberOfLines={1} adjustsFontSizeToFit>{veilId}</Text>
        </View>
        {onShowQr ? (
          <TouchableOpacity onPress={onShowQr} style={styles.idCardQr} accessibilityLabel="Show my Vardum QR">
            <Text style={styles.idCardQrTxt}>QR</Text>
          </TouchableOpacity>
        ) : null}
        <TouchableOpacity onPress={onShare}>
          <Text style={styles.idCardCopy}>Share</Text>
        </TouchableOpacity>
      </View>
      <View style={styles.idCardDivider} />
      <Text style={styles.idCardKicker}>Nickname</Text>
      <Text style={[styles.idCardNick, !nickname && styles.idCardNickOff]} numberOfLines={1}>{nickname || 'Not set'}</Text>
    </View>
  );
}

export function SettingsScreen({
  settings, onChange, veilId, email, onRunCheckup, appLockEnabled, onSetAppLock, onRemoveAppLock,
  onSignOut, onLockNow, onWipeDevice, onDeleteAccount, onViewIntro, onOpenWelcome, onOpenContacts, webBaseUrl,
  onCreateTransfer, onReceiveTransfer, onVerifyPhrase, onSwitchToPhraseSignIn, onRemoveIdentity, onGenerateNewVeilId, onCreateIdentity, onShowQr,
  blockedIds, onUnblock,
}: SettingsScreenProps) {
  const phraseSignIn = isSilentAccountEmail(email);
  const [xferBusy, setXferBusy] = useState(false);
  const [xferLink, setXferLink] = useState<{ link: string; sessionCount: number; hasIdentity: boolean } | null>(null);
  const [recvOpen, setRecvOpen] = useState(false);
  const [recvInput, setRecvInput] = useState('');
  const [recvBusy, setRecvBusy] = useState(false);
  const [recvMsg, setRecvMsg] = useState<string | null>(null);
  const [identityArmed, setIdentityArmed] = useState(false);
  const [phraseBusy, setPhraseBusy] = useState(false);
  // (b57) themed replacement for every system Alert.prompt/confirm — the OS
  // alerts are unthemeable white iPhone boxes (owner request).
  const { node: promptNode, ask } = useThemedPrompt();
  // b105: VEIL-branded Veil ID share card (owner request Sept 22 — was the
  // stock Apple share sheet). Copy is the primary action; the system sheet
  // only opens on explicit "Share…".
  const { node: shareNode, share: openShare } = useThemedShare();
  const shareVeilId = () => { if (veilId) openShare({ value: veilId, kicker: 'People use it to look you up and start verified conversations.' }); };

  /** web parity: "Verify recovery phrase" — local-only check, phrase never leaves the device */
  const doVerifyPhrase = async () => {
    const t = (await ask({
      title: 'Verify recovery phrase',
      message: 'Paste your 24-word recovery phrase. It is checked on this device against your Vardum ID — the phrase itself never leaves this device.',
      input: 'text',
      submitLabel: 'Verify',
    })) as string | null;
    const phrase = (t || '').trim().toLowerCase();
    if (!phrase) return;
    setPhraseBusy(true);
    try {
      const ok = await onVerifyPhrase(phrase);
      await ask({
        title: ok ? 'Phrase verified' : 'Not this identity',
        message: ok
          ? 'Phrase verified — it matches the identity key published to the relay.'
          : 'This recovery phrase belongs to a different Vardum identity.',
        info: true,
      });
    } catch {
      await ask({ title: 'Not this identity', message: 'This recovery phrase belongs to a different Vardum identity.', info: true });
    } finally {
      setPhraseBusy(false);
    }
  };

  /** b199: move a made-up-email account's sign-in to the 24-word phrase */
  const doSwitchToPhraseSignIn = async () => {
    if (!onSwitchToPhraseSignIn) return;
    const go = (await ask({
      title: 'Sign in with your 24 words',
      message: 'Your account will sign in with your 24-word recovery phrase instead of an email and password. Your current email and password stop working, and nothing personal stays on the relay. The phrase is checked on this device; only a one-way code made from it is sent. Keep your 24 words safe — they become the only way back into this account.',
      confirm: true,
    })) as boolean;
    if (!go) return;
    const t = (await ask({
      title: 'Enter your recovery phrase',
      message: 'Type or paste your 24 words, in order, separated by spaces.',
      input: 'text',
      submitLabel: 'Switch',
    })) as string | null;
    const phrase = (t || '').trim().toLowerCase();
    if (!phrase) return;
    setPhraseBusy(true);
    try {
      const r = await onSwitchToPhraseSignIn(phrase);
      await ask({
        title: r === 'ok' ? 'Done — 24-word sign-in is on' : 'Not this identity',
        message: r === 'ok'
          ? 'This account now signs in with your 24 words only. Your old email and password no longer work.'
          : 'This recovery phrase belongs to a different Vardum identity. Nothing was changed.',
        info: true,
      });
    } catch (e) {
      await ask({ title: 'Could not switch sign-in', message: String((e as Error).message || e) + ' Nothing was changed.', info: true });
    } finally {
      setPhraseBusy(false);
    }
  };

  /** landing headline: "Generate new Veil ID" — fresh keys, fresh ID, nothing linking old to new */
  const doGenerateNewVeilId = async () => {
    const ok = (await ask({
      title: 'Generate new Vardum ID',
      message: 'Creates a fresh identity — new keys and a new Vardum ID, with nothing linking it to the old one. Your current identity is removed from this device first; it stays recoverable only with its 24-word recovery phrase. Contacts, pins and existing conversation keys are kept — new threads will use the new identity.',
      confirm: true,
      danger: true,
    })) as boolean;
    if (!ok) return;
    setIdentityArmed(false);
    try {
      await onGenerateNewVeilId();
    } catch (e) {
      await ask({ title: 'Could not generate a new identity', message: String((e as Error).message || e), info: true });
    }
  };

  /** web parity: "Remove from this device" — two-tap armed, drops the keyvault copy only */
  const doRemoveIdentity = () => {
    if (identityArmed) {
      setIdentityArmed(false);
      onRemoveIdentity().catch((e) =>
        ask({ title: 'Could not remove the identity', message: String((e as Error).message || e), info: true }));
    } else {
      setIdentityArmed(true);
    }
  };

  const doCreateTransfer = async () => {
    setXferBusy(true); setXferLink(null);
    try {
      const r = await onCreateTransfer();
      setXferLink({ link: r.link, sessionCount: r.sessionCount, hasIdentity: r.hasIdentity });
    } catch (e) {
      void ask({ title: 'Transfer link could not be created', message: String((e as Error).message || e), info: true });
    } finally { setXferBusy(false); }
  };

  const doReceiveTransfer = async () => {
    setRecvBusy(true); setRecvMsg(null);
    try {
      const r = await onReceiveTransfer(recvInput.trim());
      setRecvMsg(
        `Imported ${r.importedCount} conversation${r.importedCount === 1 ? '' : 's'}`
        + (r.skippedExisting ? ` (${r.skippedExisting} already on this device — not overwritten)` : '')
        + (r.identityImported ? ' and your identity.' : r.identityKept ? '. This device\u2019s existing identity was kept.' : '.'),
      );
      setRecvInput('');
    } catch (e) {
      void ask({ title: 'Transfer failed', message: String((e as Error).message || e), info: true });
    } finally { setRecvBusy(false); }
  };
  const set = (patch: Partial<VeilSettings>) => onChange({ ...settings, ...patch });

  /**
   * b105 two-tap key storage change (owner request Sept 22): tap 1 shows what
   * the switch will actually do; tap 2 (Confirm) executes it. The hardware
   * flip's own Face ID demand then fires as part of the switch, as in b104.
   */
  const confirmKeyMode = async (mode: 'device' | 'hardware' | 'memory') => {
    if (settings.storageMode === mode) return;
    const warnings: Record<'device' | 'hardware' | 'memory', string> = {
      device: 'Your identity keys will move into encrypted on-device storage. They persist across restarts and nothing is demanded at boot. Weaker against a seized device — the stored keys exist in a full device image. Conversations keep working unchanged.',
      hardware: `Your identity keys will be re-sealed inside ${SECURE_CHIP}. The phone itself will demand ${BIOMETRIC_SHORT} at boot and at this switch — if biometry is off, broken or re-enrolled, the keys become unreachable and the app falls back to restoring from your 24-word phrase. Strongest protection against extraction from a seized device.`,
      memory: 'The moment Vardum leaves the foreground or the screen locks, ALL local data is wiped: chats, notes, vaults, saved stego images and your identity keys. Local history is forced off. Wiped chat threads can NEVER be reopened. Your 24-word phrase restores identity and notes; vaults reopen with their passphrases. Account login, contacts and settings survive.',
    };
    const labels: Record<'device' | 'hardware' | 'memory', string> = {
      device: 'Switch to Sealed-at-rest',
      hardware: 'Switch to security chip',
      memory: 'Switch to Nothing-at-Rest',
    };
    const ok = await ask({ title: 'Change key storage?', message: warnings[mode], confirm: true, submitLabel: labels[mode] });
    if (ok !== true) return;
    if (mode === 'memory') set({ storageMode: mode, localHistory: false });
    else set({ storageMode: mode });
  };
  const [wipeArmed, setWipeArmed] = useState(0);

  const armWipe = () => {
    const id = Date.now();
    setWipeArmed(id);
    setTimeout(() => setWipeArmed((a) => (a === id ? 0 : a)), 6000);
  };

  const setLockCodes = async () => {
    // b199 (owner, Oct 16): a password — any characters, 4 to 50
    const pass = (await ask({
      title: 'Set your password',
      message: `${PASSWORD_MIN} to ${PASSWORD_MAX} characters: letters, numbers, symbols or spaces. Use it to unlock Vardum.`,
      input: 'secure',
      maxLength: PASSWORD_MAX,
      submitLabel: 'Next',
    })) as string | null;
    if (!pass) return;
    const problem = passwordProblem(pass);
    if (problem) { await ask({ title: 'Password too short', message: problem, info: true }); return; }
    const again = (await ask({ title: 'Type it again', message: 'To make sure there’s no typo.', input: 'secure', maxLength: PASSWORD_MAX, submitLabel: 'Next' })) as string | null;
    if (again === null) return;
    if (again !== pass) { await ask({ title: 'Those didn’t match', message: 'Nothing was saved. Try again.', info: true }); return; }
    const decoy = (await ask({
      title: 'Decoy code (optional)',
      message: 'Cancel to skip. Opens a harmless empty environment if entered at the lock screen. Any characters, 4 to 50.',
      input: 'secure',
      maxLength: PASSWORD_MAX,
      submitLabel: 'Next',
    })) as string | null;
    const duress = (await ask({
      title: 'Duress code (optional)',
      message: 'Cancel to skip. Best-effort deletion of Vardum data if entered at the lock screen. Any characters, 4 to 50.',
      input: 'secure',
      maxLength: PASSWORD_MAX,
      submitLabel: 'Save',
    })) as string | null;
    for (const [label, code] of [['Decoy code', decoy], ['Duress code', duress]] as const) {
      const p = code ? passwordProblem(code) : null;
      if (p) { await ask({ title: `${label} too short`, message: `${p} Nothing was saved.`, info: true }); return; }
    }
    try {
      await onSetAppLock(pass, decoy || null, duress || null);
    } catch (e) {
      await ask({ title: 'Could not save', message: String((e as Error).message || e), info: true });
    }
  };

  // self-destruct countdown state
  const sdArmedAt = settings.selfDestructArmedAt || 0;
  const sdElapsedH = sdArmedAt ? (Date.now() - sdArmedAt) / 3600000 : 0;
  const sdWarn = settings.selfDestruct && sdElapsedH >= SELF_DESTRUCT_WARN_HOURS;

  const selfDestructRow = settings.selfDestruct ? (
    <View style={styles.sdBox}>
      <Text style={styles.sdTxt}>
        {sdWarn
          ? `Self-destruct in under ${selfDestructLeftLabel(SELF_DESTRUCT_HOURS - sdElapsedH)}. Wiping removes everything Vardum keeps on this device — extend if you are still using it.`
          : `Self-destruct armed — everything wipes in ${selfDestructLeftLabel(SELF_DESTRUCT_HOURS - sdElapsedH)}. Messaging does not reset the clock.`}
      </Text>
      <TouchableOpacity style={styles.sdExtendBtn} onPress={() => set({ selfDestructArmedAt: Date.now() })}>
        <Text style={styles.sdExtendTxt}>Extend by another {SELF_DESTRUCT_DAYS} days</Text>
      </TouchableOpacity>
    </View>
  ) : null;

  // b199 redesign: themed "pick one" sheet for the timers
  const { node: sheetNode, pick } = useOptionSheet();

  const pickBurn = async () => {
    const v = await pick({
      title: 'Burn after opening',
      message: 'Messages delete themselves this long after the other person reads them. Off = messages are not burned after opening; they last their full unopened window.',
      defends: 'Defends against: someone later opening a phone and re-reading conversations.',
      options: BURN_CHIPS, value: settings.burnTtlSeconds,
    });
    if (v !== null) set({ burnTtlSeconds: v });
  };
  const pickExpire = async () => {
    const v = await pick({
      title: 'Unopened messages expire',
      message: 'If nobody opens a message, Vardum’s server deletes it this long after it was sent. Opened messages follow the burn timer instead.',
      defends: 'Defends against: unread messages piling up on the server.',
      options: EXPIRE_CHIPS_SHORT, value: settings.expireAfterSeconds,
    });
    if (v !== null) set({ expireAfterSeconds: v });
  };
  const pickQuiet = async () => {
    const v = await pick({
      title: 'End quiet chats after',
      message: 'A chat with no messages for this long ends and deletes itself from Vardum’s server. Off = never ended automatically.',
      defends: 'Defends against: old conversations lingering on the server.',
      options: RETENTION_CHIPS, value: settings.retentionHours,
    });
    if (v !== null) set({ retentionHours: v });
  };
  const info = (title: string, message: string) => { void ask({ title, message, info: true }); };

  const keyModeShort = settings.storageMode === 'hardware'
    ? `Keys sealed in your phone’s security chip. ${BIOMETRIC} is needed to open them.`
    : settings.storageMode === 'memory'
      ? 'Nothing is kept on this phone. Leaving Vardum wipes chats, notes, vaults and keys; your 24 words bring your identity back.'
      : 'Keys stored encrypted on this phone. Convenient, but the most exposed if the phone is seized.';

  return (
    <View style={styles.fill}>
    <ScrollView style={styles.fill} contentContainerStyle={styles.content}>
      <Text style={styles.headline}>Settings</Text>

      {/* ---- Identity ---- */}
      <IdentityCard veilId={veilId} nickname={settings.nickname} onShare={shareVeilId} onShowQr={onShowQr} onCreateIdentity={onCreateIdentity} />

      {/* ---- Messages ---- */}
      <Group title="Messages" note="New chats use these timers. Turning history off means read in the moment: messages vanish from this phone when you leave the chat, including ones you sent.">
        <Row label="Burn after opening" value={labelFor(BURN_CHIPS, settings.burnTtlSeconds)} onPress={pickBurn} />
        <Row label="Unopened messages expire" value={labelFor(EXPIRE_CHIPS_SHORT, settings.expireAfterSeconds)} onPress={pickExpire} />
        <Row label="End quiet chats after" value={labelFor(RETENTION_CHIPS, settings.retentionHours)} onPress={pickQuiet} />
        <SwitchRow
          label="Keep history on this phone"
          on={settings.localHistory}
          onFlip={() => set({ localHistory: !settings.localHistory })}
          disabled={settings.storageMode === 'memory'}
          sub={settings.storageMode === 'memory' ? 'Off while Nothing at rest is on' : undefined}
        />
        <SwitchRow label="Read receipts" on={settings.readReceipts} onFlip={() => set({ readReceipts: !settings.readReceipts })} last />
      </Group>

      {/* ---- Play UGC (18 Oct 2026): blocked people, kept only on this phone ---- */}
      {onUnblock ? (
        <Group title="Blocked" note="Kept only on this phone. Blocked people's messages and forum posts are hidden and don't notify you; they aren't told.">
          {(blockedIds ?? []).length === 0 ? (
            <Row label="Nobody is blocked" sub="Hold a message to block its sender, or use ⋯ in a chat" last />
          ) : (blockedIds ?? []).map((vid, i, all) => (
            <Row
              key={vid}
              label={vid}
              value="Unblock"
              onPress={async () => {
                const ok = await ask({ title: 'Unblock this Vardum ID?', message: `${vid}\n\nTheir messages and forum posts show again on this phone. Ended chats stay ended.`, confirm: true, submitLabel: 'Unblock' });
                if (ok === true) await onUnblock(vid);
              }}
              last={i === all.length - 1}
            />
          ))}
        </Group>
      ) : null}

      {/* ---- Lock and emergency ---- */}
      <Group title="Lock and emergency" note="A decoy code opens a harmless empty space. A duress code deletes Vardum data (best effort) and opens an empty space.">
        <Row label="App lock" value={appLockEnabled ? 'Password, decoy, duress' : 'Off'} onPress={setLockCodes} />
        <SwitchRow
          label="Hold messages while locked"
          on={settings.holdUntilUnlock}
          onFlip={() => set({ holdUntilUnlock: !settings.holdUntilUnlock })}
          sub="A locked phone receives no message data"
        />
        <SwitchRow
          label="Self-destruct countdown"
          on={settings.selfDestruct}
          onFlip={() => set({ selfDestruct: !settings.selfDestruct, selfDestructArmedAt: !settings.selfDestruct ? Date.now() : 0 })}
          sub={`Wipes Vardum from this phone after ${SELF_DESTRUCT_DAYS} days`}
          danger
        />
        <Row label="Lock now" onPress={onLockNow} accent chevron={false} last={!appLockEnabled} />
        {appLockEnabled ? (
          <Row
            label="Remove app lock"
            danger
            chevron={false}
            last
            onPress={async () => {
              const pass = (await ask({ title: 'Enter your current password', message: 'Required to remove the app lock.', input: 'secure', maxLength: PASSWORD_MAX, submitLabel: 'Remove' })) as string | null;
              if (!pass) return;
              // Batch D (D-11): the shared wrong-attempt lockout applies here too
              let ok = false;
              try { ok = await onRemoveAppLock(pass); } catch (e) {
                await ask({ title: 'Not now', message: String((e as Error)?.message ?? 'Could not check the password.'), info: true });
                return;
              }
              if (!ok) await ask({ title: 'Incorrect password', message: 'The app lock was not changed.', info: true });
            }}
          />
        ) : null}
      </Group>
      {selfDestructRow}

      {/* ---- Key storage (b105 two-tap change kept: confirmKeyMode) ---- */}
      <Group title="Key storage">
        <View style={styles.segWrap}>
          <View style={styles.seg}>
            {([['device', 'Sealed'], ['hardware', 'Security chip'], ['memory', 'Nothing at rest']] as const).map(([mode, label]) => (
              <TouchableOpacity
                key={mode}
                style={[styles.segItem, settings.storageMode === mode && styles.segItemOn]}
                onPress={() => { void confirmKeyMode(mode); }}
              >
                <Text style={[styles.segTxt, settings.storageMode === mode && styles.segTxtOn]} numberOfLines={1} adjustsFontSizeToFit>{label}</Text>
              </TouchableOpacity>
            ))}
          </View>
          <Text style={styles.keyModeDesc}>{keyModeShort}</Text>
        </View>
        <Row
          label="If your phone could be seized"
          last
          onPress={() => info('If your phone could be seized',
            `Phone-extraction tools work best on a phone that has been unlocked since it was switched on. Sealed keys can sometimes be extracted from such a phone; security-chip keys need ${BIOMETRIC}; Nothing at rest keeps no conversation keys on the phone (your login and contact pins remain). Saved history reveals more than keys, so turn it off if this risk applies to you. Switching the phone off before it leaves your hands puts it in its hardest-to-extract state.`)}
        />
      </Group>

      {/* ---- Always on ---- */}
      <Group title="Always on">
        <Row
          label="Screen protection"
          value="Always on"
          onPress={() => info('Block recording & blur app switcher',
            'Screen recordings are blocked while Vardum is open and the app-switcher preview is always blurred. A plain screenshot can’t be blocked by any app (no app on iOS can block or redact one), so if one is taken both of you are told immediately over the encrypted channel. There is no setting: the protection is for the person being captured.')}
        />
        <Row
          label="Notifications"
          value="Contentless"
          onPress={() => info('Notifications', 'Vardum only ever shows one constant alert, "Vardum / Notification": never message content, senders or badges.')}
        />
        <Row
          label="Your IP address"
          value="Never stored"
          onPress={() => info('Your IP address',
            'Like any internet service, Vardum’s server sees the network address your phone connects from, but not your messages, name or contacts. It never stores that address: it’s turned into a one-way code that changes daily and is deleted within 48 hours. If hiding your address matters to you, connect through a trusted VPN or Tor (for example Orbot) before opening Vardum.')}
        />
        <Row label="Auto-lock" value="After 1 minute" last />
      </Group>

      {/* ---- Recovery and devices ---- */}
      <Group title="Recovery and devices" note="Your 24 words restore your identity. Chats only move to another phone with a transfer link.">
        {veilId ? <Row label={phraseBusy ? 'Verifying…' : 'Verify recovery phrase'} onPress={doVerifyPhrase} disabled={phraseBusy} /> : null}
        {!phraseSignIn && veilId && onSwitchToPhraseSignIn ? (
          <Row label={phraseBusy ? 'Working…' : 'Sign in with my 24 words instead'} sub="Drops your email and password" onPress={() => { void doSwitchToPhraseSignIn(); }} disabled={phraseBusy} />
        ) : null}
        <Row label={xferBusy ? 'Creating link…' : 'Move to a new phone'} sub="Single-use link, expires in about 10 minutes" onPress={doCreateTransfer} disabled={xferBusy} />
        <Row label="Receive from another phone" onPress={() => setRecvOpen(!recvOpen)} />
        {veilId ? (
          <Row
            label={settings.nickname ? 'Change nickname' : 'Set a nickname'}
            value={settings.nickname || undefined}
            onPress={async () => {
              const t = (await ask({
                title: 'Nickname',
                message: 'The name the other person sees in chats you start. It’s stored with the chat, so Vardum’s server can see it too. Leave it empty to appear as your Vardum ID.',
                input: 'text', defaultValue: settings.nickname ?? '', submitLabel: 'Save',
              })) as string | null;
              if (t === null) return;
              set({ nickname: t.trim() });
            }}
          />
        ) : null}
        <Row label="Generate new Vardum ID" sub="New keys and new 24 words; the old ID is retired" onPress={doGenerateNewVeilId} last />
      </Group>
      {xferLink ? (
        <View style={styles.xferBox}>
          <Text style={styles.xferCount}>
            Link ready — {xferLink.sessionCount} conversation{xferLink.sessionCount === 1 ? '' : 's'}
            {xferLink.hasIdentity ? ' + identity' : ''}. Share it with your other phone now, and never with anyone else.
          </Text>
          <TouchableOpacity style={styles.primaryBtn} onPress={() => Share.share({ message: xferLink.link }).catch(() => {})}>
            <Text style={styles.primaryBtnTxt}>Share / copy the link</Text>
          </TouchableOpacity>
          <TouchableOpacity onPress={() => setXferLink(null)}>
            <Text style={styles.dismissTxt}>Dismiss</Text>
          </TouchableOpacity>
        </View>
      ) : null}
      {recvOpen ? (
        <View style={styles.xferBox}>
          <TextInput
            style={styles.recvInput}
            autoCapitalize="none"
            autoCorrect={false}
            placeholder="Paste the transfer link…"
            placeholderTextColor="#5E6464"
            value={recvInput}
            editable={!recvBusy}
            onChangeText={(t) => { setRecvInput(t); setRecvMsg(null); }}
          />
          <TouchableOpacity
            style={[styles.primaryBtn, recvInput.length < 10 && styles.btnXferOff]}
            disabled={recvBusy || recvInput.length < 10}
            onPress={doReceiveTransfer}
          >
            {recvBusy ? <ActivityIndicator color="#FFFFFF" size="small" /> : <Text style={styles.primaryBtnTxt}>Import onto this phone</Text>}
          </TouchableOpacity>
          {recvMsg ? <Text style={styles.recvOk}>{recvMsg}</Text> : null}
        </View>
      ) : null}

      {/* ---- Help ---- */}
      <Group title="Help">
        <Row label="Run the privacy checkup" onPress={onRunCheckup} />
        <Row label="View the introduction" onPress={onViewIntro} />
        <Row label="Founding Tester Forum" onPress={onOpenWelcome} />
        <Row label="Security Centre" value="Web" onPress={() => Linking.openURL(webBaseUrl + '/who-can-see-what/')} />
        <Row label="Report a problem" sub="support@tryveil.app — add your Vardum ID only if you want a reply" onPress={() => Linking.openURL('mailto:support@tryveil.app')} last />
      </Group>

      {/* ---- About ---- */}
      <Group title="About" note={`Free during the beta (${BETA_SOURCE}). At launch, Vardum is a one-off payment of A$14.99.`}>
        <View style={styles.infoRow}>
          <Text style={styles.rowLabel}>Version</Text>
          <Text style={styles.infoRowValue}>{APP_VERSION}</Text>
        </View>
        <View style={styles.infoRow}>
          <Text style={styles.rowLabel}>Build</Text>
          <View style={styles.infoRowValueWrap}><Text style={styles.infoRowValue}>{SOURCE_TAG} · native b{BUILD_NUMBER}</Text><Text style={styles.infoRowSub}>{BUILD_DATE}</Text></View>
        </View>
        <View style={styles.infoRow}>
          <Text style={styles.rowLabel}>Protocol</Text>
          <View style={styles.infoRowValueWrap}>
            <Text style={styles.infoRowValue}>{PROTOCOL_VERSION}</Text>
            <Text style={styles.infoRowSub}>{PROTOCOL_WIRE_TAG}</Text>
          </View>
        </View>
        <Row label="Privacy policy" onPress={() => Linking.openURL(webBaseUrl + '/privacy')} />
        <Row label="Terms of use" onPress={() => Linking.openURL(webBaseUrl + '/terms')} last />
      </Group>

      {/* ---- Danger zone ---- */}
      <Group title="Danger zone" note="Each of these asks you to confirm first.">
        <Row label="Sign out" onPress={onSignOut} chevron={false} />
        {veilId ? (
          <Row
            label={identityArmed ? 'Tap again to remove the identity' : 'Remove identity from this phone'}
            sub="Without your 24 words it can't be restored here"
            danger
            chevron={false}
            onPress={doRemoveIdentity}
          />
        ) : null}
        <Row
          label={wipeArmed ? 'Tap again within 6 seconds to wipe' : 'Wipe Vardum from this phone'}
          sub="No recovery from this phone"
          danger
          chevron={false}
          onPress={() => {
            if (!wipeArmed) { armWipe(); return; }
            setWipeArmed(0);
            onWipeDevice();
          }}
        />
        <Row
          label="Delete account"
          danger
          chevron={false}
          last
          onPress={async () => {
            const t = (await ask({
              title: 'Type DELETE to confirm',
              message: 'Permanently deletes everything this account owns on Vardum’s server (chats and their messages, vaults, notes, contacts, transfer links, group memberships and published identities) plus the keys on this phone. Encrypted files you uploaded may remain on the server as unreadable data. This can’t be undone, and nothing is deleted until you confirm.',
              input: 'text',
              submitLabel: 'Delete everything',
            })) as string | null;
            if (t === null) return;
            if (t.trim() !== 'DELETE') { await ask({ title: 'Nothing was deleted', message: 'Type DELETE to confirm.', info: true }); return; }
            onDeleteAccount();
          }}
        />
      </Group>

      <View style={styles.footer}>
        <Text style={styles.footerTitle}>Vardum — private messaging, under your control.</Text>
      </View>
    </ScrollView>
    {sheetNode}
    {promptNode}
    {shareNode}
    </View>
  );
}

const styles = StyleSheet.create({
  fill: { flex: 1, backgroundColor: '#0B0B0F' },
  content: { padding: 16, paddingBottom: 60 },
  headline: { color: '#FFFFFF', fontSize: 22, fontWeight: '700', letterSpacing: 1, marginBottom: 12, marginLeft: 4 },
  // grouped list (b199): one inset card per group, hairline row dividers
  groupWrap: { marginTop: 18 },
  groupTitle: { color: '#FFFFFF', fontSize: 11, fontWeight: '800', letterSpacing: 0.8, textTransform: 'uppercase', marginBottom: 6, marginLeft: 6 },
  group: { backgroundColor: '#15151B', borderWidth: 1, borderColor: '#24242D', borderRadius: 12, overflow: 'hidden' },
  groupNote: { color: '#8E9696', fontSize: 11, lineHeight: 16, marginTop: 6, marginHorizontal: 6 },
  row: { flexDirection: 'row', alignItems: 'center', paddingVertical: 13, paddingHorizontal: 14, borderBottomWidth: 1, borderBottomColor: '#24242D', minHeight: 48 },
  rowLast: { borderBottomWidth: 0 },
  rowMid: { flex: 1, paddingRight: 10 },
  rowLabel: { color: '#FFFFFF', fontSize: 14, fontWeight: '500' },
  rowLabelOff: { color: '#5E6464' },
  rowSub: { color: '#8E9696', fontSize: 11, lineHeight: 15, marginTop: 2 },
  rowValue: { color: '#8E9696', fontSize: 13, maxWidth: '50%', textAlign: 'right' },
  rowChevron: { color: '#4A4A54', fontSize: 20, marginLeft: 8, marginTop: -2 },
  accentTxt: { color: '#FFFFFF' },
  dangerTxt: { color: '#e8836f' },
  switchTrack: { width: 46, height: 28, borderRadius: 14, backgroundColor: '#24242D', padding: 3, justifyContent: 'center' },
  switchTrackOn: { backgroundColor: '#FFFFFF' },
  switchTrackDanger: { backgroundColor: '#e8836f' },
  switchOff: { opacity: 0.4 },
  switchKnob: { width: 22, height: 22, borderRadius: 11, backgroundColor: '#5E6464' },
  switchKnobOn: { backgroundColor: '#0B0B0F', alignSelf: 'flex-end' },
  // key storage segmented control (owner: descriptions in light orange)
  segWrap: { padding: 12, borderBottomWidth: 1, borderBottomColor: '#24242D' },
  seg: { flexDirection: 'row', borderWidth: 1, borderColor: '#3A3A44', borderRadius: 9, overflow: 'hidden' },
  segItem: { flex: 1, paddingVertical: 9, paddingHorizontal: 4, alignItems: 'center' },
  segItemOn: { backgroundColor: 'rgba(255,255,255,0.14)' },
  segTxt: { color: '#8E9696', fontSize: 12, fontWeight: '600' },
  segTxtOn: { color: '#FFFFFF', fontWeight: '800' },
  keyModeDesc: { color: '#d69a5c', fontSize: 12, lineHeight: 17, marginTop: 10 },
  sdBox: { borderWidth: 1, borderColor: '#e8836f', borderRadius: 10, padding: 12, marginTop: 8 },
  sdTxt: { color: '#e8836f', fontSize: 12, lineHeight: 16 },
  sdExtendBtn: { marginTop: 8, alignSelf: 'flex-start' },
  sdExtendTxt: { color: '#FFFFFF', fontSize: 12, fontWeight: '700' },
  primaryBtn: { borderWidth: 1, borderColor: '#FFFFFF', borderRadius: 10, padding: 12, alignItems: 'center', marginTop: 10 },
  primaryBtnTxt: { color: '#FFFFFF', fontSize: 13, fontWeight: '700' },
  dismissTxt: { color: '#FFFFFF', fontSize: 12, textAlign: 'center', paddingTop: 10 },
  xferBox: { borderWidth: 1, borderColor: '#3A3A44', borderRadius: 12, padding: 12, marginTop: 8, backgroundColor: 'rgba(255,255,255,0.05)' },
  xferCount: { color: '#C9CFCE', fontSize: 12, lineHeight: 17 },
  recvInput: { color: '#FFFFFF', backgroundColor: '#0B0B0F', borderWidth: 1, borderColor: '#24242D', borderRadius: 10, paddingHorizontal: 12, paddingVertical: 10, fontSize: 12 },
  recvOk: { color: '#FFFFFF', fontSize: 12, lineHeight: 17, marginTop: 8 },
  btnXferOff: { opacity: 0.35 },
  infoRow: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', paddingVertical: 12, paddingHorizontal: 14, borderBottomWidth: 1, borderBottomColor: '#24242D' },
  infoRowValue: { color: '#8E9696', fontSize: 12, fontFamily: 'monospace', flexShrink: 1, textAlign: 'right' },
  infoRowValueWrap: { flex: 1, alignItems: 'flex-end', marginLeft: 12 },
  infoRowSub: { color: '#5E6464', fontSize: 10, fontFamily: 'monospace', marginTop: 2, textAlign: 'right' },
  footer: { marginTop: 28, alignItems: 'center' },
  footerTitle: { color: '#5E6464', fontSize: 11, textAlign: 'center' },
  idCard: { borderWidth: 1, borderColor: '#3A3A44', borderRadius: 14, padding: 14, backgroundColor: '#15151B' },
  idCardHead: { flexDirection: 'row', alignItems: 'center', gap: 10 },
  idCardLogo: { width: 40, height: 40, borderRadius: 10 },
  idCardKicker: { color: '#5E6464', fontSize: 10, letterSpacing: 1.5, textTransform: 'uppercase', marginBottom: 3 },
  idCardId: { color: '#FFFFFF', fontSize: 17, fontWeight: '800', letterSpacing: 0.5 },
  idCardCopy: { color: '#FFFFFF', fontSize: 13, fontWeight: '800', paddingHorizontal: 8, paddingVertical: 6 },
  idCardLine: { color: '#8E9696', fontSize: 12, marginTop: 10 },
  idCardQr: { borderWidth: 1, borderColor: '#3A3A44', borderRadius: 8, paddingHorizontal: 9, paddingVertical: 5, marginRight: 2 },
  idCardQrTxt: { color: '#FFFFFF', fontSize: 12, fontWeight: '800', letterSpacing: 0.5 },
  idCardDivider: { height: 1, backgroundColor: '#24242D', marginVertical: 12 },
  idCardNick: { color: '#FFFFFF', fontSize: 17, fontWeight: '800', letterSpacing: 0.3 },
  idCardNickOff: { color: '#5E6464', fontWeight: '600' },
});
