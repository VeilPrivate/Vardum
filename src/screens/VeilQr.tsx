/**
 * b199 Veil QR (owner request, Oct 16): every Veil ID gets its own QR that
 * people scan (any phone camera) or are sent, to add each other. It carries
 * the add link only — the public Veil ID, no keys, no account details.
 *
 * Drawn with plain Views (one per run of same-coloured modules), so it needs
 * no native module and works over Metro on the current build. Dark modules on
 * a light tile with the standard 4-module quiet zone: inverted (light-on-dark)
 * codes don't scan reliably on every camera.
 */
import React, { useMemo, useRef, useState } from 'react';
import { View, Text, TouchableOpacity, StyleSheet, Image } from 'react-native';
import { qrMatrix, veilAddLink } from '../qr';
import { withSystemSheet } from '../lock-hold';

export function QrCode({ text, size }: { text: string; size: number }) {
  const rows = useMemo(() => qrMatrix(text), [text]);
  const quiet = 4;
  const n = rows.length + quiet * 2;
  const cell = Math.floor(size / n);
  const pad = Math.floor((size - cell * rows.length) / 2);
  return (
    <View style={[styles.tile, { width: size, height: size, padding: pad }]}>
      {rows.map((row, r) => {
        const runs: { dark: boolean; len: number }[] = [];
        for (const dark of row) {
          const last = runs[runs.length - 1];
          if (last && last.dark === dark) last.len++;
          else runs.push({ dark, len: 1 });
        }
        return (
          <View key={r} style={{ flexDirection: 'row', height: cell }}>
            {runs.map((run, i) => (
              <View key={i} style={{ width: run.len * cell, height: cell, backgroundColor: run.dark ? '#0B0B0F' : 'transparent' }} />
            ))}
          </View>
        );
      })}
    </View>
  );
}

/** Full-screen "your VEIL QR" panel (overlay — no RN Modal, b25 freeze class). */
export function VeilQrSheet({ veilId, nickname, onShareLink, onClose }: {
  veilId: string;
  nickname: string;
  onShareLink: (link: string) => void;
  onClose: () => void;
}) {
  const link = veilAddLink(veilId);
  // b199: 'Send as a picture' snapshots just the QR card (name, ID, code) and
  // hands it to the share sheet. Both modules are native and loaded lazily,
  // so an older build says so instead of crashing.
  const shotRef = useRef<View>(null);
  const [picErr, setPicErr] = useState<string | null>(null);
  const sendPicture = async () => {
    setPicErr(null);
    try {
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const { captureRef } = require('react-native-view-shot') as typeof import('react-native-view-shot');
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const Sharing = require('expo-sharing') as typeof import('expo-sharing');
      const uri = await captureRef(shotRef, { format: 'png', quality: 1, result: 'tmpfile' });
      await withSystemSheet(() => Sharing.shareAsync(uri, { mimeType: 'image/png', dialogTitle: 'My Vardum QR', UTI: 'public.png' }));
    } catch (e) {
      const m = String((e as Error)?.message ?? e);
      setPicErr(/native module|RNViewShot|cannot find|undefined is not/i.test(m) ? 'Sending as a picture needs the latest Vardum build. Send the link for now.' : 'That didn’t work — try again, or send the link.');
    }
  };
  return (
    <View style={styles.backdrop}>
      <TouchableOpacity style={StyleSheet.absoluteFillObject} activeOpacity={1} onPress={onClose} />
      <View style={styles.card}>
        <View style={styles.head}>
          <Image source={require('../../assets/logo.png')} style={styles.logo} />
          <Text style={styles.kicker}>My Vardum QR</Text>
        </View>
        <Text style={[styles.nick, !nickname && styles.nickOff]} numberOfLines={1}>{nickname || 'No nickname set'}</Text>
        <Text style={styles.id} selectable numberOfLines={1} adjustsFontSizeToFit>{veilId}</Text>
        <View ref={shotRef} collapsable={false} style={styles.shot}>
          <View style={styles.qrWrap}>
            <QrCode text={link} size={248} />
          </View>
          <Text style={styles.shotLabel}>{nickname ? nickname + ' · ' : ''}{veilId} on Vardum</Text>
        </View>
        <Text style={styles.hint}>Scan with a phone camera to add me on Vardum. It holds only my Vardum ID — no keys, nothing about my account.</Text>
        <TouchableOpacity style={styles.primary} onPress={() => onShareLink(link)}>
          <Text style={styles.primaryTxt}>Send my add link</Text>
        </TouchableOpacity>
        <TouchableOpacity style={styles.secondary} onPress={() => { void sendPicture(); }}>
          <Text style={styles.secondaryTxt}>Send as a picture</Text>
        </TouchableOpacity>
        {picErr ? <Text style={styles.picErr}>{picErr}</Text> : null}
        <TouchableOpacity style={styles.close} onPress={onClose}>
          <Text style={styles.closeTxt}>Done</Text>
        </TouchableOpacity>
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  tile: { backgroundColor: '#FFFFFF', borderRadius: 14, overflow: 'hidden' },
  backdrop: { ...StyleSheet.absoluteFillObject, backgroundColor: 'rgba(11,11,15,0.9)', justifyContent: 'center', alignItems: 'center', padding: 20, zIndex: 90 },
  card: { width: '100%', maxWidth: 380, backgroundColor: '#15151B', borderRadius: 18, borderWidth: 1, borderColor: '#3A3A44', padding: 20, alignItems: 'center' },
  head: { flexDirection: 'row', alignItems: 'center', gap: 8, marginBottom: 12 },
  logo: { width: 26, height: 26, borderRadius: 7 },
  kicker: { color: '#FFFFFF', fontSize: 12, fontWeight: '800', letterSpacing: 1.2, textTransform: 'uppercase' },
  nick: { color: '#FFFFFF', fontSize: 22, fontWeight: '800' },
  nickOff: { color: '#5E6464', fontSize: 17, fontWeight: '600' },
  id: { color: '#FFFFFF', fontSize: 15, fontWeight: '700', letterSpacing: 0.5, marginTop: 4, marginBottom: 16 },
  qrWrap: { padding: 6, borderRadius: 18, borderWidth: 1, borderColor: '#3A3A44', backgroundColor: 'rgba(255,255,255,0.06)' },
  hint: { color: '#8E9696', fontSize: 12, lineHeight: 17, textAlign: 'center', marginTop: 14 },
  primary: { alignSelf: 'stretch', backgroundColor: '#FFFFFF', borderRadius: 11, paddingVertical: 13, alignItems: 'center', marginTop: 16 },
  primaryTxt: { color: '#0B0B0F', fontWeight: '800', fontSize: 14 },
  secondary: { alignSelf: 'stretch', borderWidth: 1, borderColor: '#24242D', borderRadius: 11, paddingVertical: 12, alignItems: 'center', marginTop: 8 },
  secondaryTxt: { color: '#C9CFCE', fontSize: 14, fontWeight: '600' },
  picErr: { color: '#d69a5c', fontSize: 12, textAlign: 'center', marginTop: 8 },
  shot: { alignItems: 'center', backgroundColor: '#15151B', padding: 6, borderRadius: 18 },
  shotLabel: { color: '#8E9696', fontSize: 11, marginTop: 8 },
  close: { paddingTop: 12, paddingBottom: 2 },
  closeTxt: { color: '#8E9696', fontSize: 13, fontWeight: '600' },
});
