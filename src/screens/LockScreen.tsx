import React, { useEffect, useState } from 'react';
import { View, Text, TextInput, TouchableOpacity, StyleSheet, Image } from 'react-native';
import { useKbPadding } from '../hooks/useKbPadding';
import { PASSWORD_MAX } from '../password';

/**
 * Lock screen. Two web-parity paths:
 *  - app lock configured: password field first (password / Decoy / Duress)
 *  - otherwise: biometric unlock button (native setup flow)
 *
 * b199 (owner, Oct 16): the lock is a PASSWORD — any characters, up to 50 —
 * typed on the iPhone keyboard in dark mode (it replaced the number pad).
 * AutoFill, suggestions and "save password" are off: the phone never stores
 * or offers it. Older numeric passcodes still work (digits are characters).
 */

export function LockScreen({
  hint, onUnlock, onCode, hasAppLock, codeError, verifying, resetKey, lockoutUntil,
}: {
  onUnlock: () => void;
  hint: string | null;
  onCode: (code: string) => void;
  hasAppLock: boolean;
  codeError: string | null;
  /** true while the 210k-iteration PBKDF2 check runs — field disabled, spinner shown */
  verifying?: boolean;
  /** parent bumps this (e.g. Date.now()) to clear the entered password after a wrong one */
  resetKey?: number;
  /** b123: epoch ms until which the field is dead (5 wrong attempts ->
   *  progressive lockout). 0/undefined = no active lockout. */
  lockoutUntil?: number;
}) {
  const kbH = useKbPadding();
  const [code, setCode] = useState('');
  useEffect(() => { setCode(''); }, [resetKey]);
  // b123: live countdown while a lockout is running; the field re-enables
  // itself the moment the window expires.
  const [now, setNow] = useState(Date.now());
  const active = !!lockoutUntil && lockoutUntil > now;
  useEffect(() => {
    if (!lockoutUntil) return;
    setNow(Date.now());
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, [lockoutUntil]);
  const waitMins = active && lockoutUntil
    ? Math.max(1, Math.ceil((lockoutUntil - now) / 60_000))
    : 0;
  const blocked = verifying || active;
  const submit = () => { if (!blocked && code.length > 0) onCode(code); };

  return (
    <View style={[styles.fill, kbH > 0 ? { paddingBottom: kbH } : null]}>
      {/* b109 (owner request Sept 22): the bare ARCS above the wordmark —
          logo-mark.png is the transparent ring/arc mark, no square plate. */}
      {/* b199 (owner, Oct 16): page layout like the setup pages — mark and words
          in the middle, the password field and Unlock at the bottom */}
      <View style={styles.top}>
        <Image source={require('../../assets/logo-mark.png')} style={[styles.logo, kbH > 0 && styles.logoSmall]} resizeMode="contain" />
        <Text style={styles.wordmark}><Text style={{ color: '#20D9C2' }}>V</Text>ardum</Text>
        <Text style={styles.locked}>Vardum is locked</Text>
        <Text style={styles.hint}>{hint ?? (hasAppLock ? 'Enter your password to unlock.' : 'Authenticate to unlock your sessions.')}</Text>
      </View>
      {hasAppLock ? (
        <View style={styles.dock}>
          {active ? (
            <Text style={styles.lockoutTxt}>Too many incorrect attempts — try again in {waitMins} min.</Text>
          ) : (
            <Text style={styles.err}>{verifying ? 'Verifying — this takes a few seconds on this device.' : (codeError ?? '')}</Text>
          )}
          <TextInput
            style={[styles.field, blocked && styles.fieldBusy]}
            value={code}
            onChangeText={(t) => setCode(t.slice(0, PASSWORD_MAX))}
            onSubmitEditing={submit}
            editable={!blocked}
            secureTextEntry
            autoFocus
            maxLength={PASSWORD_MAX}
            placeholder="Password"
            placeholderTextColor="#5E6464"
            keyboardAppearance="dark"
            returnKeyType="go"
            autoCapitalize="none"
            autoCorrect={false}
            spellCheck={false}
            /* iOS still offers "Use Strong Password" on a secure field marked "none";
               oneTimeCode suppresses it (the code is typed, never autofilled or saved) */
            textContentType="oneTimeCode"
            autoComplete="off"
            importantForAutofill="no"
            accessibilityLabel="Password"
          />
          <TouchableOpacity style={[styles.btn, blocked && styles.btnBusy]} disabled={blocked || code.length === 0} onPress={submit}>
            <Text style={[styles.btnTxt, blocked && styles.btnTxtBusy]}>{active ? `Locked · ${waitMins} min` : verifying ? 'Verifying…' : 'Unlock'}</Text>
          </TouchableOpacity>
        </View>
      ) : (
        <View style={styles.dock}>
          <TouchableOpacity style={styles.btn} onPress={onUnlock}>
            <Text style={styles.btnTxt}>Unlock</Text>
          </TouchableOpacity>
        </View>
      )}
    </View>
  );
}

const styles = StyleSheet.create({
  fill: { flex: 1, backgroundColor: '#0B0B0F', paddingHorizontal: 24, paddingTop: 60 },
  // b199 page layout: mark + words centred in the space above the field
  top: { flex: 1, alignItems: 'center', justifyContent: 'center', paddingHorizontal: 8 },
  // owner (Oct 16): no panel or border behind the controls at the bottom
  dock: { alignItems: 'center', paddingTop: 8, paddingBottom: 30 },
  logo: { width: 112, height: 112 },
  logoSmall: { width: 72, height: 72 },
  // letterSpacing adds a trailing gap after the final glyph — nudge the
  // wordmark right by half so "VEIL" sits dead-center optically, not the
  // measured box.
  wordmark: { color: '#FFFFFF', fontSize: 37, fontFamily: 'Menlo', fontWeight: '600', letterSpacing: 0.5, marginTop: 14 },
  locked: { color: '#FFFFFF', fontSize: 24, fontWeight: '800', marginTop: 26 },
  hint: { color: '#8E9696', fontSize: 15, marginTop: 8, textAlign: 'center', alignSelf: 'stretch' },
  err: { color: '#e8836f', fontSize: 13, minHeight: 20, textAlign: 'center', alignSelf: 'stretch', marginBottom: 8 },
  // b123: lockout banner — teal-accent alert, sized to replace the error line
  lockoutTxt: { color: '#FFFFFF', fontSize: 13, minHeight: 20, textAlign: 'center', fontWeight: '700', alignSelf: 'stretch', marginBottom: 8 },
  field: { alignSelf: 'stretch', minHeight: 52, borderRadius: 14, borderWidth: 1, borderColor: '#3A3A44', backgroundColor: '#15151B', color: '#FFFFFF', fontSize: 17, paddingHorizontal: 18, textAlign: 'center' },
  fieldBusy: { opacity: 0.45 },
  btn: { backgroundColor: '#FFFFFF', borderRadius: 12, alignSelf: 'stretch', alignItems: 'center', paddingVertical: 15, marginTop: 12 },
  btnBusy: { backgroundColor: '#3A3A44' },
  btnTxtBusy: { color: '#8E9696' },
  btnTxt: { color: '#0B0B0F', fontWeight: '800', fontSize: 15 },
});
