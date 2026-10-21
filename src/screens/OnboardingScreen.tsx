import React, { useState } from 'react';
import { View, Text, TouchableOpacity, ScrollView, StyleSheet, TextInput, Image } from 'react-native';
import { useThemedPrompt } from './ThemedPrompt';
import { PASSWORD_MIN, PASSWORD_MAX, passwordProblem } from '../password';
import { SECURE_CHIP, BIOMETRIC } from '../platformText';
import {
  type VeilSettings, BURN_OPTIONS, EXPIRY_OPTIONS, QUIET_OPTIONS,
  SELF_DESTRUCT_HOURS, SELF_DESTRUCT_WARN_HOURS, SELF_DESTRUCT_DAYS,
} from '../../vendor/device/src/settings';

/**
 * Onboarding flow (b199 order, owner-approved Oct 16 2026). A NEW sign-up
 * runs it in full, straight after the 24-word phrase is confirmed, and lands
 * in the app only at the end:
 *   1. Intro slides — all of INTROS, in order; the last one bridges into…
 *   2. Privacy Checkup — one screen per dial, every screen answered; the
 *      answers ARE the configuration (recommendations are labelled, never
 *      applied on the user's behalf)
 *   3. Veil ID + nickname + mandatory passcode, then "Apply these settings"
 * No skip or cancel exists in 'full' mode. A phrase RESTORE never enters it.
 *
 * introOnly: replays the intro slides from Settings ("View the introduction"),
 * without the checkup bridge slide.
 * checkupOnly: opens straight at the Privacy Checkup (Settings → Run the
 * privacy checkup; also the "Secure your VEIL" prompt).
 */

interface IntroSlide { title: string; body: string; /** hands over to the checkup — full mode only */ bridge?: boolean }

const INTROS: IntroSlide[] = [
  {
    title: 'Your 24 words are you.',
    body: 'No email, no phone number, no name. Those words are your identity and your sign-in, and they never leave this phone. Keep them safe: if they’re lost, no one, including us, can get your account back.',
  },
  {
    title: 'Only you and the people you talk to can read your messages.',
    body: 'Every message is locked on your phone before it’s sent. Vardum’s server only passes along sealed envelopes it can’t open.',
  },
  {
    title: 'Check who you’re talking to.',
    body: 'When you connect with someone new, you each see a short code. Compare them in person or on a call. If they match, nobody is listening in between.',
  },
  {
    title: 'Know the limits.',
    body: 'Vardum can’t stop someone photographing your screen, and it can’t protect a phone that is unlocked in someone else’s hands or has spyware on it. The choices you make next decide how much stays on this phone.',
  },
  {
    title: 'Now, set your privacy.',
    body: 'Next you’ll choose, one at a time, how long messages last, what this phone keeps, and how your keys are protected. We’ll mark what we recommend, but every choice is yours, and you can change any of them later in Settings.',
    bridge: true,
  },
];

interface DialStep {
  // b133: keys MUST be REAL VeilSettings field names — answers are spread
  // verbatim into settings at finish ({...settings, ...a}); a key that is
  // not a real field is silently discarded by mergeSettings' clamp and the
  // dial falls back to its default (owner repro Sept 27: chose "5 min" burn
  // in onboarding, settings kept the 7200 fallback, lounge created at 2h).
  key: 'burnTtlSeconds' | 'expireAfterSeconds' | 'retentionHours' | 'localHistory' | 'storageMode' | 'holdUntilUnlock' | 'selfDestruct' | 'readReceipts';
  title: string;
  desc: string;
  defends: string;
  /** b199: optional one-line detail shown under an option (key storage) */
  options: { label: string; value: number | boolean | string; sub?: string }[];
}

const DIALS: DialStep[] = [
  {
    key: 'burnTtlSeconds', title: 'Burn after opening',
    desc: 'Messages delete themselves this long after the recipient reads them. Off = threads never burn after opening; messages last their full unopened-expiry window.',
    defends: 'Defends against: someone later opening the device and re-reading conversations.',
    options: BURN_OPTIONS.map((o) => ({ label: o.label + (o.value === 7200 ? '  (Recommended)' : ''), value: o.value })),
  },
  {
    key: 'expireAfterSeconds', title: 'Unopened messages expire',
    // b199: Off really means the standard 36 h window (chat.ts
    // envelopeTtlSeconds); longer choices are honoured up to 30 days
    desc: 'A message nobody opens is deleted from Vardum\u2019s server this long after it was sent. Off = the standard window of 36 hours.',
    defends: 'Defends against: unopened messages piling up on Vardum\u2019s server.',
    options: EXPIRY_OPTIONS.map((o) => ({ label: o.label + (o.value === 86400 ? '  (Recommended)' : ''), value: o.value })),
  },
  {
    key: 'retentionHours', title: 'End quiet threads after',
    desc: 'A conversation with no messages for this long ends and deletes itself from Vardum’s server. Off = never ended automatically (the server still removes records abandoned for a year).',
    defends: 'Defends against: old conversations lingering on Vardum’s server.',
    options: QUIET_OPTIONS.map((o) => ({ label: o.label + (o.value === 168 ? '  (Recommended)' : ''), value: o.value })),
  },
  {
    key: 'localHistory', title: 'Keep conversation history on this device',
    // b199 (owner, Oct 16): shortened so each question fits on one screen
    desc: 'On = an encrypted copy of your chats stays on this phone. Off = messages are read in the moment and forgotten when you leave the chat. Saved history is the first thing a phone-extraction tool recovers from a seized, unlocked phone.',
    defends: 'Turning it Off defends against: a seized phone revealing who you talked to and what was said. Nothing-at-Rest forces this off.',
    // b199 (owner decision, Oct 16): On is the recommended default
    options: [{ label: 'On  (Recommended)', value: true }, { label: 'Off', value: false }],
  },
  {
    key: 'storageMode', title: 'Key storage',
    // b199 (owner, Oct 16): the per-mode detail moved onto each option so the
    // question fits on one screen
    desc: 'Where your identity keys live on this phone. If you could face device seizure, choose the chip or Nothing-at-Rest.',
    defends: 'Defends against: keys being extracted from a seized device by phone-extraction tools.',
    options: [
      { label: 'Sealed-at-rest  (most convenient)', value: 'device', sub: 'Encrypted on this phone, no prompts. Most exposed if the phone is seized after it was unlocked.' },
      { label: 'Security chip  (Recommended)', value: 'hardware', sub: `Sealed in ${SECURE_CHIP}; opens with ${BIOMETRIC}. Much harder to extract.` },
      { label: 'Nothing-at-Rest  (strongest)', value: 'memory', sub: 'Memory only, wiped whenever Vardum leaves the screen. You restore with your 24 words each time.' },
    ],
  },
  {
    key: 'holdUntilUnlock', title: 'Hold until unlock',
    desc: 'Delivery is held while the phone is locked — a locked phone holds no message data at all.',
    defends: 'Defends against: message data arriving while the device is unattended.',
    options: [{ label: 'On', value: true }, { label: 'Off  (Recommended)', value: false }],
  },
  {
    key: 'selfDestruct', title: 'Self-destruct countdown',
    desc: `Everything Vardum keeps on the device wipes on a fixed ${SELF_DESTRUCT_DAYS}-day clock; messaging does not reset it. A warning appears ${SELF_DESTRUCT_HOURS - SELF_DESTRUCT_WARN_HOURS} hours before, extendable by another ${SELF_DESTRUCT_DAYS} days. Opt-in — never armed silently by setup.`,
    defends: 'Defends against: a device being kept and inspected later.',
    options: [{ label: 'Off  (Recommended)', value: false }, { label: `On — wipe everything after ${SELF_DESTRUCT_DAYS} days`, value: true }],
  },
  {
    key: 'readReceipts', title: 'Read receipts',
    desc: 'Tell the sender when you have read their message. You can change this any time in Settings → Messages.',
    defends: 'Defends against: your reading activity being reported without consent.',
    options: [{ label: 'Off  (Recommended)', value: false }, { label: 'On', value: true }],
  },
];

export interface OnboardingScreenProps {
  settings: VeilSettings;
  onApply: (s: VeilSettings) => void;
  onDone: () => void;
  veilId?: string | null;
  mode?: 'full' | 'introOnly' | 'checkupOnly' | 'idOnly';
  /** (b67) passcode is mandatory at the end of the privacy setup */
  appLockEnabled?: boolean;
  onSetAppLock?: (pass: string, decoy?: string | null, duress?: string | null) => Promise<void>;
  /** exit without applying (only rendered for introOnly / checkupOnly —
   *  the checkup opened from Settings must never trap the user) */
  onCancel?: () => void;
}

export function OnboardingScreen({ settings, onApply, onDone, veilId, mode = 'full', onCancel, appLockEnabled, onSetAppLock }: OnboardingScreenProps) {
  // b199: the slide count is no longer a hard-coded 4 (that constant hid the
  // fifth slide, "Understand the limits", for every user). The replay from
  // Settings drops the checkup bridge slide.
  const intros = mode === 'introOnly' ? INTROS.filter((s) => !s.bridge) : INTROS;
  const NI = intros.length;
  // step: 0..NI-1 intros, NI..NI+DIALS-1 checkup dials, last = Veil ID + nickname + passcode
  const [step, setStep] = useState(mode === 'checkupOnly' ? NI : mode === 'idOnly' ? NI + DIALS.length : 0);
  const [answers, setAnswers] = useState<Partial<VeilSettings>>({});
  const [nickname, setNickname] = useState(settings.nickname ?? '');
  const [selfDestructArmed, setSelfDestructArmed] = useState(0);
  // (b67) mandatory passcode at the end of privacy setup (full + checkupOnly)
  const { node: promptNode, ask } = useThemedPrompt();
  const passRequired = (mode === 'full' || mode === 'checkupOnly') && !appLockEnabled;
  const [passSet, setPassSet] = useState(false);
  const [passBusy, setPassBusy] = useState(false);

  const choosePasscode = async () => {
    if (!onSetAppLock || passBusy) return;
    setPassBusy(true);
    try {
      // b199 (owner, Oct 16): a password — any characters, 4 to 50
      const pass = (await ask({
        title: 'Set your password',
        message: `${PASSWORD_MIN} to ${PASSWORD_MAX} characters: letters, numbers, symbols or spaces. Required to finish privacy setup — it locks Vardum on this device.`,
        input: 'secure', maxLength: PASSWORD_MAX, submitLabel: 'Next',
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
        input: 'secure', maxLength: PASSWORD_MAX, submitLabel: 'Next',
      })) as string | null;
      const duress = (await ask({
        title: 'Duress code (optional)',
        message: 'Cancel to skip. Best-effort deletion of Vardum data if entered at the lock screen. Any characters, 4 to 50.',
        input: 'secure', maxLength: PASSWORD_MAX, submitLabel: 'Save',
      })) as string | null;
      for (const [label, code] of [['Decoy code', decoy], ['Duress code', duress]] as const) {
        const p = code ? passwordProblem(code) : null;
        if (p) { await ask({ title: `${label} too short`, message: `${p} Nothing was saved.`, info: true }); return; }
      }
      await onSetAppLock(pass, decoy || null, duress || null);
      setPassSet(true);
    } catch (e) {
      await ask({ title: 'Could not save the password', message: String((e as Error).message || e), info: true });
    } finally { setPassBusy(false); }
  };
  const last = NI + DIALS.length;
  const introDone = mode === 'introOnly' ? () => onDone() : () => setStep(NI);
  const total = mode === 'introOnly' ? NI : last + 1;
  // idOnly: straight to the Veil ID + nickname step, no checkup required

  const cancelChip = onCancel && (mode === 'introOnly' || mode === 'checkupOnly') ? (
    <TouchableOpacity style={styles.cancelBtn} onPress={onCancel}>
      <Text style={styles.cancelTxt}>Cancel</Text>
    </TouchableOpacity>
  ) : null;

  if (step < NI) {
    const it = intros[step];
    const lastIntro = step === NI - 1;
    // b199 (owner, Oct 16): page layout — dots up top, big mark + words in
    // the middle, the button and Back at the bottom
    return (
      <View style={styles.page}>
        {cancelChip}
        <View style={styles.progress}>
          {intros.map((_, i) => (
            <View key={i} style={[styles.dot, step >= i && styles.dotOn]} />
          ))}
        </View>
        <ScrollView style={styles.scroll} contentContainerStyle={styles.pageScroll}>
          <View style={styles.pageMid}>
            <Image source={require('../../assets/logo.png')} style={styles.pageLogo} />
            <Text style={styles.pageTitle}>{it.title}</Text>
            <Text style={styles.pageBody}>{it.body}</Text>
          </View>
        </ScrollView>
        <TouchableOpacity style={styles.btn} onPress={() => (lastIntro ? introDone() : setStep(step + 1))}>
          <Text style={styles.btnTxt}>{lastIntro ? (mode === 'introOnly' ? 'Done' : 'Start the privacy checkup') : 'Continue'}</Text>
        </TouchableOpacity>
        <TouchableOpacity onPress={() => setStep(step - 1)} disabled={step === 0}>
          <Text style={[styles.back, step === 0 && styles.backHidden]}>Back</Text>
        </TouchableOpacity>
      </View>
    );
  }

  if (step < last) {
    const d = DIALS[step - NI];
    return (
      <View style={styles.page}>
        {cancelChip}
        <View style={styles.progress}>
          {Array.from({ length: total - NI }).map((_, i) => (
            <View key={i} style={[styles.dot, step - NI >= i && styles.dotOn]} />
          ))}
        </View>
        {/* b199 (owner, Oct 16): one screen per question, no scrolling —
            question in the middle, answers below (a 3-column grid when there
            are more than four), Back at the bottom. Text spans the full width. */}
        <ScrollView style={styles.scroll} contentContainerStyle={styles.pageScroll}>
          <View style={[styles.pageMid, styles.checkMid]}>
            <Text style={styles.kicker}>Privacy Checkup</Text>
            <Text style={[styles.pageTitle, styles.fullW]}>{d.title}</Text>
            <Text style={[styles.checkBody, styles.fullW]}>{d.desc}</Text>
            <Text style={[styles.defends, styles.fullW]}>{d.defends}</Text>
          </View>
          <View style={d.options.length > 4 ? styles.optGrid : null}>
            {d.options.map((o) => {
              const on = answers[d.key as keyof VeilSettings] === o.value;
              const [main, note] = o.label.split('  (');
              const grid = d.options.length > 4;
              return (
                <TouchableOpacity
                  key={String(o.value)}
                  style={[styles.opt, grid && styles.optCell, on && styles.optOn]}
                  onPress={() => {
                    setAnswers((a) => {
                      const next = { ...a, [d.key]: o.value } as Partial<VeilSettings>;
                      if (d.key === 'storageMode' && o.value === 'memory') next.localHistory = false;
                      if (d.key === 'selfDestruct') setSelfDestructArmed(o.value === true ? Date.now() : 0);
                      return next;
                    });
                    setStep(step + 1);
                  }}
                >
                  <Text style={[styles.optTxt, grid && styles.optTxtCell, on && styles.optTxtOn]}>
                    {main}{note && !grid ? <Text style={styles.optNote}>{'  (' + note}</Text> : null}
                  </Text>
                  {note && grid ? <Text style={styles.optNoteCell}>{note.replace(/\)$/, '')}</Text> : null}
                  {o.sub ? <Text style={styles.optSub}>{o.sub}</Text> : null}
                </TouchableOpacity>
              );
            })}
          </View>
        </ScrollView>
        <TouchableOpacity onPress={() => setStep(step - 1)} disabled={!(step > NI || (step === NI && mode === 'full'))}>
          <Text style={[styles.back, !(step > NI || (step === NI && mode === 'full')) && styles.backHidden]}>Back</Text>
        </TouchableOpacity>
      </View>
    );
  }

  // Veil ID + nickname step
  const canFinish = !passRequired || passSet;
  return (
    <View style={styles.page}>
      {promptNode}
      {cancelChip}
      <View style={styles.progress}>
        {Array.from({ length: total }).map((_, i) => (
          <View key={i} style={[styles.dot, i <= last && styles.dotOn]} />
        ))}
      </View>
      {/* b199 (owner, Oct 16): page layout — ID in the middle, finish at the bottom */}
      <ScrollView style={styles.scroll} contentContainerStyle={styles.pageScroll} keyboardShouldPersistTaps="handled">
        <View style={styles.pageMid}>
          <Image source={require('../../assets/logo.png')} style={styles.pageLogo} />
          <Text style={styles.pageTitle}>Your Vardum ID</Text>
          <Text style={styles.idText}>{veilId ?? 'Your identity will publish a Vardum ID shortly.'}</Text>
          <Text style={styles.pageBody}>Share your Vardum ID with people you want to speak with. They use it to look you up and verify they are speaking with you.</Text>
        </View>
        <Text style={styles.label}>Nickname for this device (local only)</Text>
        <TextInput
          style={styles.input}
          value={nickname}
          onChangeText={setNickname}
          placeholder="Optional — never leaves this device"
          placeholderTextColor="#5E6464"
        />
        {passRequired ? (
          <View style={styles.passBox}>
            <Text style={styles.passTitle}>{passSet ? 'Password set ✓' : 'Set your password — required to finish'}</Text>
            <Text style={styles.passHint}>
              {passSet
                ? 'Vardum will now lock behind your password whenever it is opened.'
                : 'Privacy setup is not complete until this device is protected by a password. It locks Vardum whenever the app is opened or left.'}
            </Text>
            {!passSet ? (
              <TouchableOpacity style={styles.passBtn} onPress={choosePasscode} disabled={passBusy}>
                <Text style={styles.passBtnTxt}>{passBusy ? '…' : 'Choose a password'}</Text>
              </TouchableOpacity>
            ) : null}
          </View>
        ) : null}
        <TouchableOpacity
          style={[styles.btn, !canFinish && styles.btnOff]}
          disabled={!canFinish}
          onPress={() => {
            const a = answers;
            onApply({
              ...settings,
              ...a,
              nickname,
              selfDestructArmedAt: a.selfDestruct === true ? selfDestructArmed || Date.now() : 0,
              setupDone: true,
              onboardingPending: false,
            } as VeilSettings);
            onDone();
          }}
        >
          <Text style={[styles.btnTxt, !canFinish && styles.btnTxtOff]}>Apply these settings</Text>
        </TouchableOpacity>
        {!canFinish ? <Text style={styles.gateNote}>Choose a password above to finish.</Text> : null}
      </ScrollView>
    </View>
  );
}

const styles = StyleSheet.create({
  fill: { flex: 1, backgroundColor: '#0B0B0F', padding: 26, justifyContent: 'center' },
  // b199 page layout: dots at the top, content centred in the middle, actions at the bottom
  page: { flex: 1, backgroundColor: '#0B0B0F', paddingHorizontal: 22, paddingTop: 60, paddingBottom: 26 },
  pageScroll: { flexGrow: 1, paddingBottom: 12 },
  pageMid: { flexGrow: 1, alignItems: 'center', justifyContent: 'center', paddingVertical: 16 },
  pageLogo: { width: 92, height: 92, marginBottom: 26 },
  pageTitle: { color: '#FFFFFF', fontSize: 25, fontWeight: '800', marginBottom: 14, textAlign: 'center', alignSelf: 'stretch' },
  pageBody: { color: '#8E9696', fontSize: 16, lineHeight: 23, marginBottom: 12, textAlign: 'center', alignSelf: 'stretch' },
  backHidden: { opacity: 0 },
  fullW: { alignSelf: 'stretch' },
  checkMid: { alignItems: 'stretch', paddingVertical: 8 },
  checkBody: { color: '#8E9696', fontSize: 15, lineHeight: 21, marginBottom: 10, textAlign: 'center' },
  optGrid: { flexDirection: 'row', flexWrap: 'wrap', justifyContent: 'space-between' },
  optCell: { width: '31.5%', paddingVertical: 12, paddingHorizontal: 6, alignItems: 'center' },
  optTxtCell: { fontSize: 14, textAlign: 'center' },
  optNote: { color: '#FFFFFF', fontSize: 12 },
  optNoteCell: { color: '#FFFFFF', fontSize: 10, fontWeight: '700', marginTop: 2 },
  optSub: { color: '#8E9696', fontSize: 12, lineHeight: 16, marginTop: 4 },
  scroll: { flex: 1 },
  progress: { flexDirection: 'row', gap: 6, justifyContent: 'center', marginBottom: 26 },
  dot: { width: 8, height: 8, borderRadius: 4, borderWidth: 1, borderColor: '#3A3A44' },
  dotOn: { backgroundColor: '#FFFFFF', borderColor: '#FFFFFF' },
  kicker: { color: '#FFFFFF', fontSize: 11, fontWeight: '800', letterSpacing: 2, textTransform: 'uppercase', marginBottom: 12 },
  title: { color: '#FFFFFF', fontSize: 20, fontWeight: '700', marginBottom: 12, textAlign: 'center' },
  body: { color: '#8E9696', fontSize: 13, lineHeight: 19, marginBottom: 12, textAlign: 'center' },
  defends: { color: '#8E9696', fontSize: 12, lineHeight: 17, marginBottom: 14, textAlign: 'center', fontStyle: 'italic' },
  opt: { borderWidth: 1, borderColor: '#24242D', backgroundColor: '#15151B', borderRadius: 12, paddingVertical: 13, paddingHorizontal: 15, marginBottom: 8 },
  optOn: { borderColor: '#FFFFFF', backgroundColor: 'rgba(255,255,255,0.06)' },
  optTxt: { color: '#C9CFCE', fontSize: 15 },
  optTxtOn: { color: '#FFFFFF', fontWeight: '700' },
  back: { color: '#8E9696', fontSize: 13, fontWeight: '600', textAlign: 'center', marginTop: 16 },
  btn: { backgroundColor: '#FFFFFF', borderRadius: 22, paddingVertical: 14, alignItems: 'center', marginTop: 18 },
  btnTxt: { color: '#0B0B0F', fontWeight: '800', fontSize: 14 },
  idText: { color: '#FFFFFF', fontSize: 20, fontWeight: '800', textAlign: 'center', marginBottom: 14, letterSpacing: 1, alignSelf: 'stretch' },
  label: { color: '#8E9696', fontSize: 12, marginBottom: 6 },
  input: { borderWidth: 1, borderColor: '#24242D', borderRadius: 10, color: '#FFFFFF', padding: 12, fontSize: 14, marginBottom: 6 },
  passBox: { borderWidth: 1, borderColor: '#FFFFFF', borderRadius: 12, padding: 14, marginVertical: 12, backgroundColor: 'rgba(255,255,255,0.05)' },
  passTitle: { color: '#FFFFFF', fontSize: 13, fontWeight: '800', marginBottom: 6 },
  passHint: { color: '#8E9696', fontSize: 12, lineHeight: 17, marginBottom: 10 },
  passBtn: { backgroundColor: '#FFFFFF', borderRadius: 10, paddingVertical: 12, alignItems: 'center' },
  passBtnTxt: { color: '#0B0B0F', fontWeight: '800', fontSize: 13 },
  btnOff: { backgroundColor: '#3A3A44' },
  btnTxtOff: { color: '#8E9696' },
  gateNote: { color: '#8E9696', fontSize: 11, textAlign: 'center', marginTop: 8 },
  cancelBtn: { position: 'absolute', top: 54, right: 24, zIndex: 10, paddingHorizontal: 14, paddingVertical: 8, borderRadius: 16, borderWidth: 1, borderColor: '#3A3A44' },
  cancelTxt: { color: '#5E6464', fontSize: 13, fontWeight: '600' },
});
