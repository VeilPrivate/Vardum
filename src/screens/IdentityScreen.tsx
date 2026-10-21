import React, { useEffect, useMemo, useState } from 'react';
import { View, Text, TextInput, TouchableOpacity, StyleSheet, ScrollView, Platform, ActivityIndicator, Image, Alert} from 'react-native';
import { useKbPadding } from '../hooks/useKbPadding';
import { startScreenWatch } from '../screen-watch';
import { validatePhrase } from '../../vendor/crypto-core/src/index';
import { canonicalPhrase } from '../../vendor/device/src/silent-auth';
import { PERMISSION_DECLINED } from '../platformText';



export interface IdentityScreenProps {
  /** Provision a freshly created identity (create flow). */
  onCreate: () => Promise<{ phrase: string[]; veilId: string }>;
  /** Restore an existing identity from its 24-word phrase. */
  onRestore: (phrase: string) => Promise<void>;
  /** Provision the freshly created identity (called after the user confirms the phrase is written down). */
  onFinishCreate: () => Promise<void>;
  /** Sign out and go back to login. */
  onSignOut: () => void;
  /** b112: classic email sign-in for existing accounts (the account link). */
  onAccountSignIn?: () => void;
  /** Entry point — 'confirm-create' for Settings > "Generate new Veil ID" (skips the chooser). */
  initialMode?: 'choose' | 'confirm-create';
}

/**
 * Shown after login when the device keychain holds no Veil identity.
 * Restore (phrase login) or create a new anonymous identity.
 * The phrase and keys never leave the device in either flow.
 */

/**
 * b111 (owner directive: no raw internal errors on screen, ever): raw
 * exception text goes to the Metro console; the UI gets one human sentence.
 */
function friendlyError(e: unknown, what: string): string {
  const err = e as Error;
  console.log(`[veil-error] ${what}:`, String(err?.message ?? e), err?.stack ?? '');
  const s = String(err?.message ?? e).toLowerCase();
  if (s.includes('network') || s.includes('timeout') || s.includes('fetch') || s.includes('request failed'))
    return 'Connection problem — check your internet and try again.';
  if (s.includes('permission') || s.includes('denied') || s.includes('not authorized'))
    return PERMISSION_DECLINED;
  if (s.includes('rate limit'))
    // b175 (owner Metro repro, Oct 2: burst send surfaced a raw-feeling
    // "Something went wrong" during a transient relay throttle): the relay's
    // anti-abuse limiter is a few-second self-healing cooldown, not a real
    // failure — say so plainly instead of falling through to the scary
    // generic bucket. The composer keeps the drafted text either way.
    return 'The server is briefly busy — wait a few seconds and try again.';
  return 'Something went wrong — please try again.';
}

export function IdentityScreen({ onCreate, onRestore, onFinishCreate, onSignOut, onAccountSignIn, initialMode = 'choose' }: IdentityScreenProps) {
  const kbH = useKbPadding();
  const [mode, setMode] = useState<'choose' | 'restore' | 'confirm-create' | 'reveal' | 'provisioning'>(initialMode);
  const [phraseInput, setPhraseInput] = useState('');
  const [words, setWords] = useState<string[]>([]);
  // b168 (web P3.8 parity): the phrase is hidden until the user deliberately
  // taps "Show my 24 words" — no accidental shoulder-surf reveal the instant
  // keys are generated. Reset for each fresh creation.
  const [revealed, setRevealed] = useState(false);
  const [written, setWritten] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // b199: count what will actually be used (punctuation/numbering ignored)
  const wordCount = useMemo(() => canonicalPhrase(phraseInput).split(' ').filter(Boolean).length, [phraseInput]);

  // b199: iOS cannot block a screenshot (screen RECORDING is already blocked
  // app-wide), but it reports one. While the 24 words are on screen, a
  // screenshot gets an immediate, specific warning — a photo of the phrase in
  // Photos / iCloud is the easiest copy for anyone to find or extract.
  const wordsVisible = mode === 'reveal' && revealed;
  useEffect(() => {
    if (!wordsVisible) return;
    const stop = startScreenWatch((ev) => {
      if (ev.kind !== 'screenshot') return;
      Alert.alert(
        'Delete that screenshot',
        'A screenshot of your 24 words was just taken. Anyone who finds it can become you. Delete it from Photos AND from "Recently Deleted", and check it has not synced to iCloud Photos. Write the words on paper instead.',
      );
    });
    return () => { stop?.(); };
  }, [wordsVisible]);

  const doCreate = async () => {
    setBusy(true); setError(null);
    try {
      const { phrase } = await onCreate();
      setRevealed(false);
      setWords(phrase);
      setMode('reveal');
      setWritten(false);
    } catch (e) {
      const msg = String((e as Error).message || e) + '\n\n' + String((e as Error).stack || '').slice(0, 400);
      setError(msg);
      try { Alert.alert('Vardum error — photograph this screen', msg); } catch { /* Alert optional */ }
    } finally { setBusy(false); }
  };

  const doRestore = async () => {
    setBusy(true); setError(null);
    // b199 (owner hardware repro, Oct 16): canonicalise, then CHECK the words
    // on-device before anything touches the network. A stray character used
    // to derive a different sign-in, fail it, and drop the user on the email
    // screen with no hint that the words were the problem. Diagnostics log
    // counts only — never a word.
    const canonical = canonicalPhrase(phraseInput);
    const stray = (phraseInput.match(/[^a-zA-Z\s]/g) || []).length;
    try {
      await validatePhrase(canonical);
      console.log(`[veil-restore] phrase checked on-device: ${canonical.split(' ').length} words, ${stray} stray character(s) removed, checksum OK`);
    } catch (e) {
      console.log(`[veil-restore] phrase rejected on-device: ${canonical ? canonical.split(' ').length : 0} words, ${stray} stray character(s), ${String((e as Error)?.message ?? e).replace(/".*"/, '"…"')}`);
      const msg = String((e as Error)?.message ?? e);
      setError(/Unknown recovery word/.test(msg)
        ? `${msg} — check its spelling. Only the 24 words count; numbers and punctuation are ignored.`
        : /exactly 24 words/.test(msg)
          ? `${msg} Check that no word is missing or split in two.`
          : 'These 24 words don’t form a valid recovery phrase — check that every word is spelled right and in the right order.');
      setBusy(false);
      return;
    }
    try {
      await onRestore(canonical);
    } catch (e) {
      setError(friendlyError(e, 'identity'));
      setBusy(false);
    }
  };


  if (mode === 'choose') {
    return (
      <View style={styles.fill}>
        {/* b199 (owner, Oct 16): the first screen a new user sees, laid out as a
            page — big mark and welcome up top, the two choices below, Sign out
            at the very bottom. Heading was "One last thing" (email-first era). */}
        <ScrollView contentContainerStyle={[styles.welcomePage, kbH > 0 ? { paddingBottom: kbH + 24 } : null]}>
          <View style={styles.welcomeTop}>
            <Image source={require('../../assets/logo.png')} style={styles.welcomeLogo} />
            <Text style={styles.welcomeWordmark}><Text style={{ color: '#20D9C2' }}>V</Text>ardum</Text>
            <Text style={styles.welcomeH1}>Welcome to Vardum</Text>
            <Text style={styles.welcomeH2}>
              Private messaging with no name, email or phone number. Your identity is a Vardum ID, made on this phone, with nothing personal attached.
            </Text>
          </View>

          <View style={styles.welcomeChoices}>
          <TouchableOpacity style={styles.card} onPress={() => setMode('restore')} disabled={busy}>
            <Text style={styles.cardTitle}>Restore with recovery phrase</Text>
            <Text style={styles.cardBody}>Have your 24 words? Your identity, contacts and pins come back on this device.</Text>
          </TouchableOpacity>

          <TouchableOpacity style={styles.cardTeal} onPress={() => setMode('confirm-create')} disabled={busy}>
            <Text style={styles.cardTealTitle}>Create a new identity</Text>
            <Text style={styles.cardTealBody}>Generates a fresh Vardum ID and a one-time 24-word phrase.</Text>
          </TouchableOpacity>

          {error ? <Text style={styles.error}>{error}</Text> : null}
          {onAccountSignIn ? (
            <TouchableOpacity style={styles.link} onPress={onAccountSignIn} disabled={busy}>
              <Text style={styles.linkText}>Sign in with an existing account</Text>
            </TouchableOpacity>
          ) : null}
          </View>

          <TouchableOpacity style={styles.welcomeSignOut} onPress={onSignOut} disabled={busy}>
            <Text style={styles.welcomeSignOutTxt}>Sign out</Text>
          </TouchableOpacity>
        </ScrollView>
      </View>
    );
  }

  if (mode === 'restore') {
    return (
      <View style={styles.fill}>
        {/* b199 (owner, Oct 16): full-page layout, same as the welcome page */}
        <ScrollView contentContainerStyle={[styles.welcomePage, kbH > 0 ? { paddingBottom: kbH + 24 } : null]} keyboardShouldPersistTaps="handled">
          <View style={styles.welcomeTop}>
            <Image source={require('../../assets/logo.png')} style={styles.pageLogo} />
            <Text style={styles.welcomeH1}>Restore your identity</Text>
            <Text style={styles.welcomeH2}>
              Type or paste your 24 words, in order, with spaces between them. They're checked on this phone first; nothing is sent until they're right.
            </Text>
          </View>

          <View style={styles.welcomeChoices}>
          <TextInput
            style={[styles.input, wordCount === 24 && styles.inputOk]}
            multiline
            autoCapitalize="none"
            autoCorrect={false}
            placeholder="word word word …"
            placeholderTextColor="#5E6464"
            value={phraseInput}
            editable={!busy}
            onChangeText={(t) => { setPhraseInput(t.toLowerCase()); setError(null); }}
          />
          <Text style={[styles.counter, wordCount === 24 && styles.counterOk]}>{wordCount} / 24 words</Text>

          {error ? <Text style={styles.error}>{error}</Text> : null}

          {busy ? (
            <ActivityIndicator color="#FFFFFF" style={styles.busy} />
          ) : (
            <TouchableOpacity
              style={[styles.cta, wordCount !== 24 && styles.ctaDisabled]}
              disabled={wordCount !== 24}
              onPress={doRestore}
            >
              <Text style={styles.ctaText}>Restore identity</Text>
            </TouchableOpacity>
          )}
          </View>

          <TouchableOpacity style={styles.welcomeSignOut} onPress={() => setMode('choose')} disabled={busy}>
            <Text style={styles.welcomeSignOutTxt}>← Back</Text>
          </TouchableOpacity>
        </ScrollView>
      </View>
    );
  }

  if (mode === 'confirm-create') {
    return (
      <View style={styles.fill}>
        {/* b199 (owner, Oct 16): same full-page layout as the welcome page */}
        <ScrollView contentContainerStyle={[styles.welcomePage, kbH > 0 ? { paddingBottom: kbH + 24 } : null]}>
          <View style={styles.welcomeTop}>
            <Image source={require('../../assets/logo.png')} style={styles.welcomeLogo} />
            <Text style={styles.welcomeWordmark}><Text style={{ color: '#20D9C2' }}>V</Text>ardum</Text>
            <Text style={styles.welcomeH1}>Create a new identity?</Text>
            <Text style={styles.welcomeH2}>
              A new Vardum ID is made on this phone. You'll get a 24-word recovery phrase, shown exactly once.
            </Text>
            <Text style={styles.welcomeWarn}>
              Lose the phrase and the identity is gone for good. No one, including us, can recover it for you.
            </Text>
          </View>

          <View style={styles.welcomeChoices}>
            <TouchableOpacity style={styles.cta} onPress={doCreate} disabled={busy}>
              <Text style={styles.ctaText}>{busy ? 'Generating…' : 'Yes — create my identity'}</Text>
            </TouchableOpacity>
            {error ? <Text style={styles.error}>{error}</Text> : null}
          </View>

          <TouchableOpacity style={styles.welcomeSignOut} onPress={() => setMode('choose')} disabled={busy}>
            <Text style={styles.welcomeSignOutTxt}>← Back</Text>
          </TouchableOpacity>
        </ScrollView>
      </View>
    );
  }

  if (mode === 'reveal') {
    return (
      // b199 (owner, Oct 16): full-page layout, same as the welcome page
      <ScrollView style={styles.fill} contentContainerStyle={styles.welcomePage}>
        {!revealed ? (
          <>
            {/* b168 (web P3.8 parity): announce the 24-word requirement and
                prep the user BEFORE the words hit the screen — the phrase only
                appears behind a deliberate "Show my 24 words" tap. */}
            <View style={styles.welcomeTop}>
              <Image source={require('../../assets/logo.png')} style={styles.pageLogo} />
              <Text style={styles.welcomeH1}>Your recovery phrase</Text>
              <Text style={styles.welcomeH2}>
                Your identity comes with a 24-word recovery phrase. It is the only way to restore this identity, and it is shown exactly once — no one, including us, can recover it for you.
              </Text>
            </View>
            <View style={styles.welcomeChoices}>
              <View style={styles.tipCard}>
                <Text style={styles.tipTitle}>Before you reveal them</Text>
                <Text style={styles.tipTxt}>Get paper and a pen ready. Make sure no one can see your screen, then reveal the words.</Text>
                <Text style={styles.tipTxt}>Never screenshot or photograph them, and never type them into Notes, email, a chat, or any cloud service. Digital copies are what phone-extraction tools and account breaches find first. Paper, kept somewhere safe, is the safest copy.</Text>
              </View>
              <TouchableOpacity style={styles.cta} onPress={() => setRevealed(true)}>
                <Text style={styles.ctaText}>Show my 24 words</Text>
              </TouchableOpacity>
              {error ? <Text style={styles.error}>{error}</Text> : null}
            </View>
          </>
        ) : (
          <>
            <Text style={[styles.welcomeH1, { marginTop: 8 }]}>Your recovery phrase</Text>
            <Text style={[styles.welcomeH2, { marginBottom: 18 }]}>
              Write these 24 words down, in order, on paper. They are the only way to restore this identity and to sign in to your account. They are never shown again. Do not screenshot them.
            </Text>

            <View style={styles.wordGrid}>
          {words.map((w, i) => (
            <View key={i} style={styles.wordRow}>
              <Text style={styles.wordNum}>{i + 1}</Text>
              <Text style={styles.word}>{w}</Text>
            </View>
          ))}
        </View>
            <View style={{ flexGrow: 1, minHeight: 18 }} />

            <TouchableOpacity style={styles.check} onPress={() => setWritten(!written)}>
              <View style={[styles.checkbox, written && styles.checkboxOn]} />
              <Text style={styles.checkText}>I have written it down somewhere safe</Text>
            </TouchableOpacity>

            {busy ? (
              <ActivityIndicator color="#FFFFFF" style={styles.busy} />
            ) : (
              <TouchableOpacity
                style={[styles.cta, !written && styles.ctaDisabled]}
                disabled={!written || busy}
                onPress={async () => {
                  setBusy(true); setError(null);
                  try { await onFinishCreate(); } catch (e) { setError(friendlyError(e, 'identity')); setBusy(false); }
                }}
              >
                <Text style={styles.ctaText}>Finish</Text>
              </TouchableOpacity>
            )}
            {error ? <Text style={styles.error}>{error}</Text> : null}
          </>
        )}
      </ScrollView>
    );
  }

  return (
    <View style={[styles.fill, styles.center]}>
      <ActivityIndicator color="#FFFFFF" />
      <Text style={styles.bootText}>Sealing your identity…</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  fill: { flex: 1, backgroundColor: '#0B0B0F' },
  scroll: { padding: 28 },
  // b199 welcome page: top block grows to fill, choices sit below it, Sign out at the very bottom
  welcomePage: { flexGrow: 1, paddingHorizontal: 24, paddingTop: 48, paddingBottom: 28 },
  welcomeTop: { flexGrow: 1, alignItems: 'center', justifyContent: 'center', paddingVertical: 24 },
  welcomeLogo: { width: 112, height: 112, marginBottom: 16 },
  welcomeWordmark: { color: '#FFFFFF', fontSize: 36, fontFamily: 'Menlo', fontWeight: '600', letterSpacing: 0.5, marginBottom: 34 },
  welcomeH1: { color: '#FFFFFF', fontSize: 26, fontWeight: '800', textAlign: 'center' },
  welcomeH2: { color: '#8E9696', fontSize: 15, lineHeight: 22, textAlign: 'center', marginTop: 10, paddingHorizontal: 6 },
  welcomeChoices: { marginTop: 24 },
  pageLogo: { width: 84, height: 84, marginBottom: 22 },
  tipCard: { backgroundColor: '#15151B', borderRadius: 14, borderWidth: 1, borderColor: '#5c4526', padding: 16, marginBottom: 16 },
  tipTitle: { color: '#d69a5c', fontSize: 12, fontWeight: '800', letterSpacing: 0.8, textTransform: 'uppercase', marginBottom: 8 },
  tipTxt: { color: '#C9CFCE', fontSize: 14, lineHeight: 20, marginBottom: 6 },
  welcomeWarn: { color: '#d69a5c', fontSize: 14, lineHeight: 20, textAlign: 'center', marginTop: 14, paddingHorizontal: 6 },
  welcomeSignOut: { alignItems: 'center', paddingTop: 22, paddingBottom: 4 },
  welcomeSignOutTxt: { color: '#8E9696', fontSize: 13, fontWeight: '600' },
  center: { alignItems: 'center', justifyContent: 'center' },
  brand: { alignItems: 'center', marginBottom: 30, marginTop: 10 },
  logoMark: { width: 60, height: 60, marginBottom: 12 },
  logo: { color: '#FFFFFF', fontSize: 28, fontWeight: '700', letterSpacing: 8 },
  h1: { color: '#FFFFFF', fontSize: 22, fontWeight: '600' },
  h2: { color: '#8E9696', fontSize: 13, marginTop: 8, marginBottom: 20, lineHeight: 19 },
  card: { backgroundColor: '#15151B', borderRadius: 14, borderWidth: 1, borderColor: '#24242D', padding: 18, marginBottom: 14 },
  cardTitle: { color: '#FFFFFF', fontSize: 16, fontWeight: '600' },
  cardBody: { color: '#8E9696', fontSize: 12, marginTop: 6, lineHeight: 17 },
  cardTeal: { backgroundColor: '#15151B', borderRadius: 14, borderWidth: 1, borderColor: '#3A3A44', padding: 18, marginBottom: 14 },
  cardTealTitle: { color: '#FFFFFF', fontSize: 16, fontWeight: '600' },
  cardTealBody: { color: '#8E9696', fontSize: 12, marginTop: 6, lineHeight: 17 },
  input: {
    color: '#FFFFFF', backgroundColor: '#0B0B0F', borderWidth: 1, borderColor: '#24242D',
    borderRadius: 10, padding: 14, fontSize: 16, minHeight: 120, textAlignVertical: 'top',
  },
  inputOk: { borderColor: '#3A3A44' },
  counter: { color: '#4A4A54', fontSize: 12, marginTop: 6, marginBottom: 16 },
  counterOk: { color: '#FFFFFF' },
  wordGrid: { backgroundColor: '#15151B', borderRadius: 14, borderWidth: 1, borderColor: '#24242D', padding: 14 },
  wordRow: { flexDirection: 'row', alignItems: 'center', paddingVertical: 4 },
  wordNum: { color: '#4A4A54', fontSize: 11, width: 26 },
  word: { color: '#FFFFFF', fontSize: 14, letterSpacing: 0.5 },
  check: { flexDirection: 'row', alignItems: 'center', marginTop: 18, marginBottom: 22 },
  checkbox: { width: 22, height: 22, borderRadius: 6, borderWidth: 1.5, borderColor: '#3A3A44', marginRight: 10 },
  checkboxOn: { backgroundColor: '#FFFFFF', borderColor: '#FFFFFF' },
  checkText: { color: '#8E9696', fontSize: 13, flexShrink: 1 },
  cta: { backgroundColor: '#FFFFFF', borderRadius: 10, padding: 15, alignItems: 'center' },
  ctaDisabled: { opacity: 0.35 },
  ctaText: { color: '#0B0B0F', fontSize: 16, fontWeight: '700' },
  busy: { marginTop: 14 },
  link: { alignItems: 'center', marginTop: 18 },
  linkText: { color: '#FFFFFF', fontSize: 13 },
  error: { color: '#ff8f8f', fontSize: 13, marginTop: 10, lineHeight: 18 },
  bootText: { color: '#5E6464', marginTop: 14, fontSize: 13, letterSpacing: 1 },
});
