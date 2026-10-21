import React, { useEffect, useState } from 'react';
import { View, Text, TextInput, TouchableOpacity, StyleSheet, Image, Platform, ActivityIndicator, ScrollView} from 'react-native';
import { useKbPadding } from '../hooks/useKbPadding';
import { SecureInput, SecureKeypadHost } from '../components/SecureKeypad';



export interface LoginScreenProps {
  busy: boolean;
  error: string | null;
  info: string | null;
  onLogin: (email: string, password: string) => void;
  onForgotPassword: (email: string) => void;
  onSignup: (email: string, password: string) => void;
  /** b112: back to the identity flow (create/restore without an account screen). */
  onSwitchToIdentity?: () => void;
}

/** Account sign-in / sign-up (the Base44 app account — the Veil identity is restored/created after). */
export function LoginScreen({ busy, error, info, onLogin, onForgotPassword, onSignup, onSwitchToIdentity }: LoginScreenProps) {
  const kbH = useKbPadding();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [mode, setMode] = useState<'signin' | 'forgot' | 'signup'>('signin');
  const forgot = mode === 'forgot';
  const canSubmit = !busy && (forgot || (!!email && !!password));
  const submit = () => {
    if (!canSubmit) return;
    // Batch G (round-5 review R5-3-12): no email is ever verified, so there is no reset
    // link to send; this screen only explains and goes back
    if (forgot) { setMode('signin'); return; }
    else if (mode === 'signup') onSignup(email.trim(), password);
    else onLogin(email.trim(), password);
  };

  return (
    <SecureKeypadHost style={styles.fill}>
      <ScrollView contentContainerStyle={[styles.scroll, kbH > 0 ? { paddingBottom: kbH + 24 } : null]} keyboardShouldPersistTaps="handled">
        <View style={styles.brand}>
          <Image source={require('../../assets/logo.png')} style={styles.logoMark} />
          <Text style={styles.logo}><Text style={{ color: '#20D9C2' }}>V</Text>ardum</Text>
          <Text style={styles.tagline}>Private by design.</Text>
        </View>

        {/* b198 (founder decision, Oct 15): ANONYMOUS SIGNUP — the Base44-era
            verified-email mandate is retired on our own relay. The email is a
            SELF-DECLARED label: real or invented, never verified, never
            contacted. This disclaimer is the first thing a new user reads. */}
        <View style={styles.disclaimer}>
          <Text style={styles.disclaimerTitle}>YOUR EMAIL IS A LABEL — NOT YOUR IDENTITY</Text>
          <Text style={styles.disclaimerBody}>
            Choose any address — real or completely invented (quiet-fox-42@example.com is fine). It is never verified, never contacted, and never shown to anyone you talk to. It only anchors your login.
          </Text>
          <Text style={styles.disclaimerBold}>Your email is not your identity.</Text>
          <View style={styles.disclaimerRow}><Text style={styles.disclaimerDot}>•</Text><Text style={styles.disclaimerItem}>Your Vardum ID, your identity keys and your 24-word phrase are created on this device. The server links your Vardum ID to this login, but never sees your keys or your phrase.</Text></View>
          <View style={styles.disclaimerRow}><Text style={styles.disclaimerDot}>•</Text><Text style={styles.disclaimerItem}>Your messages, contacts, notes and vaults are end-to-end encrypted. This address is only the login anchor — it is never connected to your message, contact, note or vault contents.</Text></View>
          <View style={styles.disclaimerRow}><Text style={styles.disclaimerDot}>•</Text><Text style={styles.disclaimerItem}>Messages are end-to-end encrypted: the relay passes them on but can't read them.</Text></View>
          <Text style={styles.disclaimerBody}>
            A forgotten password cannot be recovered by email — your 24-word phrase is the ONLY way back into your identity. Keep it safe. Once you are in, the email plays no part in how Vardum identifies you, finds you, or talks to your contacts.
          </Text>
        </View>

        <View style={styles.card}>
          <Text style={styles.h1}>{forgot ? 'Reset password' : mode === 'signup' ? 'Create account' : 'Sign in'}</Text>
          <Text style={styles.h2}>
            {forgot
              ? 'No email is ever verified, so a password cannot be reset or emailed. Sign in with your password, or restore your identity with your 24-word phrase from the welcome screen.'
              : 'Your account keys never leave this device. No email verification — the address is whatever you type.'}
          </Text>

          <Text style={styles.label}>EMAIL</Text>
          <TextInput
            style={styles.input}
            autoCapitalize="none"
            autoCorrect={false}
            keyboardType="email-address"
            textContentType="emailAddress"
            placeholder="you@example.com"
            placeholderTextColor="#5E6464"
            value={email}
            editable={!busy}
            onChangeText={setEmail}
          />

          {!forgot && (
            <>
              <Text style={styles.label}>PASSWORD</Text>
              {/* Oct 18 (owner): the account password is typed on Vardum's own
                  keypad (components/SecureKeypad), never the phone keyboard —
                  no AutoFill / saved passwords, suggestions, paste, or
                  third-party keyboard ever sees it. Done = the button below. */}
              <SecureInput
                style={styles.inputBox}
                textStyle={styles.inputTxt}
                placeholder="••••••••"
                value={password}
                editable={!busy}
                onChangeText={setPassword}
                onSubmit={submit}
                doneLabel={mode === 'signup' ? 'Create' : 'Sign in'}
                accessibilityLabel="Password"
              />
            </>
          )}

          {error ? <Text style={styles.error}>{error}</Text> : null}
          {info ? <Text style={styles.info}>{info}</Text> : null}

          {busy ? (
            <ActivityIndicator color="#FFFFFF" style={styles.busy} />
          ) : (
            <TouchableOpacity
              style={[styles.cta, !forgot && (!email || !password) && styles.ctaDisabled]}
              disabled={!forgot && (!email || !password)}
              onPress={submit}
            >
              <Text style={styles.ctaText}>{forgot ? 'Back to sign in' : mode === 'signup' ? 'Create account' : 'Sign in'}</Text>
            </TouchableOpacity>
          )}

          <TouchableOpacity style={styles.link} onPress={() => { setMode(mode === 'forgot' ? 'signin' : 'forgot'); }} disabled={busy}>
            <Text style={styles.linkText}>
              {forgot ? '← Back to sign in' : 'Forgot password?'}
            </Text>
          </TouchableOpacity>

          <TouchableOpacity style={styles.link} onPress={() => { setMode(mode === 'signup' ? 'signin' : 'signup'); }} disabled={busy}>
            <Text style={styles.linkText}>
              {mode === 'signup' ? '← I already have an account' : 'New here? Create an account'}
            </Text>
          </TouchableOpacity>

          {onSwitchToIdentity ? (
            <TouchableOpacity style={styles.link} onPress={onSwitchToIdentity} disabled={busy}>
              <Text style={styles.linkText}>← No account needed — create a Vardum identity</Text>
            </TouchableOpacity>
          ) : null}
        </View>

        <Text style={styles.footing}>
          No phone number. No contact list. Messages are sealed before they leave the device.
        </Text>
      </ScrollView>
    </SecureKeypadHost>
  );
}

const styles = StyleSheet.create({
  fill: { flex: 1, backgroundColor: '#0B0B0F' },
  scroll: { flexGrow: 1, justifyContent: 'center', padding: 28 },
  brand: { alignItems: 'center', marginBottom: 36 },
  logoMark: { width: 76, height: 76, marginBottom: 18 },
  logo: { color: '#FFFFFF', fontSize: 40, fontFamily: 'Menlo', fontWeight: '600', letterSpacing: 0.5 },
  tagline: { color: '#5E6464', marginTop: 10, fontSize: 14, letterSpacing: 1 },
  card: { backgroundColor: '#15151B', borderRadius: 16, borderWidth: 1, borderColor: '#24242D', padding: 22 },
  h1: { color: '#FFFFFF', fontSize: 22, fontWeight: '600' },
  h2: { color: '#8E9696', fontSize: 13, marginTop: 6, marginBottom: 18, lineHeight: 18 },
  label: { color: '#8E9696', fontSize: 11, letterSpacing: 2, marginBottom: 6 },
  input: {
    color: '#FFFFFF', backgroundColor: '#0B0B0F', borderWidth: 1, borderColor: '#24242D',
    borderRadius: 10, padding: 14, fontSize: 16, marginBottom: 16,
  },
  // the password on the Vardum keypad: same box as `input`, text styled apart
  inputBox: {
    backgroundColor: '#0B0B0F', borderWidth: 1, borderColor: '#24242D',
    borderRadius: 10, padding: 14, marginBottom: 16,
  },
  inputTxt: { color: '#FFFFFF', fontSize: 16 },
  cta: { backgroundColor: '#FFFFFF', borderRadius: 10, padding: 15, alignItems: 'center', marginTop: 4 },
  ctaDisabled: { opacity: 0.35 },
  ctaText: { color: '#0B0B0F', fontSize: 16, fontWeight: '700' },
  busy: { marginTop: 14 },
  link: { alignItems: 'center', marginTop: 16 },
  linkText: { color: '#FFFFFF', fontSize: 13 },
  error: { color: '#ff8f8f', fontSize: 13, marginBottom: 10, lineHeight: 18 },
  info: { color: '#FFFFFF', fontSize: 13, marginBottom: 10, lineHeight: 18 },
  footing: { color: '#4A4A54', fontSize: 11, textAlign: 'center', marginTop: 28, lineHeight: 16 },
  // b116: email disclaimer card — same teal-bordered card language as the
  // Settings sections (b107), with the VEIL message orange for the one
  // line we most need every user to internalise.
  disclaimer: {
    backgroundColor: '#15151B', borderRadius: 16, borderWidth: 1, borderColor: '#3A3A44',
    padding: 22, marginBottom: 18,
  },
  disclaimerTitle: { color: '#FFFFFF', fontSize: 12, fontWeight: '700', letterSpacing: 2, marginBottom: 10 },
  disclaimerBody: { color: '#8E9696', fontSize: 13, lineHeight: 19, marginBottom: 10 },
  disclaimerBold: { color: '#d69a5c', fontSize: 14, fontWeight: '700', marginBottom: 8 },
  disclaimerRow: { flexDirection: 'row', marginBottom: 6 },
  disclaimerDot: { color: '#FFFFFF', fontSize: 13, lineHeight: 19, marginRight: 8 },
  disclaimerItem: { color: '#8E9696', fontSize: 13, lineHeight: 19, flex: 1 },
});
