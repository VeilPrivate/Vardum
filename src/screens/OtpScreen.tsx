import React, { useEffect, useRef, useState } from 'react';
import { View, Text, TextInput, TouchableOpacity, StyleSheet, Image, Platform, ActivityIndicator} from 'react-native';
import { useKbPadding } from '../hooks/useKbPadding';



export interface OtpScreenProps {
  email: string;
  busy: boolean;
  error: string | null;
  info: string | null;
  onVerify: (code: string) => void;
  onResend: () => void;
  onBack: () => void;
  /** Resend cooldown in seconds (server allows ~1/minute). */
  cooldown?: number;
}

/** 6-digit code entry for account verification / fresh-signup confirmation. */
export function OtpScreen({ email, busy, error, info, onVerify, onResend, onBack, cooldown = 60 }: OtpScreenProps) {
  const kbH = useKbPadding();
  const [code, setCode] = useState('');
  const [left, setLeft] = useState(0);
  const timer = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    if (cooldown > 0) setLeft(cooldown);
    return () => { if (timer.current) clearInterval(timer.current); };
  }, [cooldown]);

  const startCooldown = () => {
    setLeft(cooldown);
    if (timer.current) clearInterval(timer.current);
    timer.current = setInterval(() => {
      setLeft((v) => {
        if (v <= 1 && timer.current) { clearInterval(timer.current); timer.current = null; return 0; }
        return v - 1;
      });
    }, 1000);
  };

  return (
    <View style={styles.fill}>
      <View style={[styles.inner, kbH > 0 ? { paddingBottom: kbH + 24 } : null]}>
        <Image source={require('../../assets/logo.png')} style={styles.logoMark} />
        <Text style={styles.logo}><Text style={{ color: '#20D9C2' }}>V</Text>ardum</Text>
        <Text style={styles.h1}>Enter your code</Text>
        <Text style={styles.h2}>
          We sent a 6-digit code to{'\n'}{email}. It confirms this account — the email is never used to identify you to peers.
        </Text>

        <TextInput
          style={styles.code}
          keyboardType="number-pad"
          textContentType="oneTimeCode"
          maxLength={6}
          autoFocus
          value={code}
          editable={!busy}
          onChangeText={(t) => setCode(t.replace(/[^0-9]/g, ''))}
        />

        {error ? <Text style={styles.error}>{error}</Text> : null}
        {info ? <Text style={styles.info}>{info}</Text> : null}

        {busy ? (
          <ActivityIndicator color="#FFFFFF" style={styles.busy} />
        ) : (
          <TouchableOpacity
            style={[styles.cta, code.length < 6 && styles.ctaDisabled]}
            disabled={code.length < 6}
            onPress={() => onVerify(code)}
          >
            <Text style={styles.ctaText}>Verify</Text>
          </TouchableOpacity>
        )}

        <View style={styles.row}>
          <TouchableOpacity onPress={onBack} disabled={busy}>
            <Text style={styles.linkText}>← Back</Text>
          </TouchableOpacity>
          <TouchableOpacity
            disabled={busy || left > 0}
            onPress={() => { onResend(); startCooldown(); }}
          >
            <Text style={[styles.linkText, left > 0 && styles.linkDim]}>
              {left > 0 ? `Resend in ${left}s` : 'Resend code'}
            </Text>
          </TouchableOpacity>
        </View>
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  fill: { flex: 1, backgroundColor: '#0B0B0F' },
  inner: { flex: 1, justifyContent: 'center', padding: 28 },
  logoMark: { width: 64, height: 64, marginBottom: 14, alignSelf: 'center' },
  logo: { color: '#FFFFFF', fontSize: 34, fontFamily: 'Menlo', fontWeight: '600', letterSpacing: 0.5, textAlign: 'center', marginBottom: 30 },
  h1: { color: '#FFFFFF', fontSize: 22, fontWeight: '600', textAlign: 'center' },
  h2: { color: '#8E9696', fontSize: 13, textAlign: 'center', marginTop: 8, marginBottom: 26, lineHeight: 19 },
  code: {
    color: '#FFFFFF', fontSize: 30, letterSpacing: 14, textAlign: 'center',
    backgroundColor: '#0B0B0F', borderWidth: 1, borderColor: '#24242D', borderRadius: 12,
    padding: 16, marginBottom: 18, fontWeight: '600',
  },
  cta: { backgroundColor: '#FFFFFF', borderRadius: 10, padding: 15, alignItems: 'center' },
  ctaDisabled: { opacity: 0.35 },
  ctaText: { color: '#0B0B0F', fontSize: 16, fontWeight: '700' },
  busy: { marginTop: 14 },
  row: { flexDirection: 'row', justifyContent: 'space-between', marginTop: 20 },
  linkText: { color: '#FFFFFF', fontSize: 13 },
  linkDim: { color: '#4A4A54' },
  error: { color: '#ff8f8f', fontSize: 13, marginBottom: 10, textAlign: 'center', lineHeight: 18 },
  info: { color: '#FFFFFF', fontSize: 13, marginBottom: 10, textAlign: 'center', lineHeight: 18 },
});
