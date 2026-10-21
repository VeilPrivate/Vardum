/**
 * b199 Veil QR (owner request, Oct 16): scan a VEIL QR inside the app.
 * Full-screen overlay (no RN Modal, b25 freeze class). Reads only QR codes,
 * and only a VEIL add link is accepted — anything else is ignored with a
 * message, never opened. The camera is used only while this screen is open.
 *
 * expo-camera is a NATIVE module: it is required lazily so a dev build made
 * before it was added shows "needs the latest build" instead of crashing.
 *
 * "Choose from Photos" (owner request, Oct 16): reads a VEIL QR someone sent
 * as a picture. The system photo picker hands over only the one picture
 * chosen (no photo-library permission); it is read on this phone and never
 * uploaded. Same rule as the camera: only a VEIL add link is accepted.
 */
import React, { useEffect, useMemo, useRef, useState } from 'react';
import { View, Text, TouchableOpacity, StyleSheet, Linking } from 'react-native';
import * as ImagePicker from 'expo-image-picker';
import { parseVeilAddLink } from '../qr';
import { withSystemSheet } from '../lock-hold';

type CameraModule = typeof import('expo-camera');

export function QrScanner({ onFound, onClose }: { onFound: (veilId: string) => void; onClose: () => void }) {
  const cam = useMemo<CameraModule | null>(() => {
    try {
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      return require('expo-camera') as CameraModule;
    } catch {
      return null;
    }
  }, []);
  const [perm, setPerm] = useState<'asking' | 'granted' | 'denied'>('asking');
  const [note, setNote] = useState<string | null>(null);
  const handled = useRef(false);

  useEffect(() => {
    console.log(`[veil-scan] open: camera module ${cam ? 'loaded' : 'MISSING'}, CameraView ${typeof cam?.CameraView}`);
    if (!cam) return;
    withSystemSheet(() => cam.Camera.requestCameraPermissionsAsync())
      .then((r) => { console.log(`[veil-scan] permission: ${r.status} granted=${r.granted} canAskAgain=${r.canAskAgain}`); setPerm(r.granted ? 'granted' : 'denied'); })
      .catch((e) => { console.log(`[veil-scan] permission request failed: ${String((e as Error)?.message || e)}`); setPerm('denied'); });
  }, [cam]);

  const onScan = ({ data, type }: { data: string; type?: string }) => {
    if (handled.current) return;
    const id = parseVeilAddLink(String(data || ''));
    console.log(`[veil-scan] code seen: type=${type} len=${String(data || '').length} start=${JSON.stringify(String(data || '').slice(0, 34))} veilId=${id ? 'yes' : 'no'}`);
    if (!id) { setNote('That isn’t a Vardum QR. Point the camera at someone’s Vardum QR.'); return; }
    handled.current = true;
    onFound(id);
  };

  const fromPhotos = async () => {
    if (!cam) return;
    try {
      const r = await withSystemSheet(() => ImagePicker.launchImageLibraryAsync({ mediaTypes: ['images'], quality: 1, allowsMultipleSelection: false }));
      if (r.canceled || !r.assets?.[0]?.uri) return;
      const codes = await cam.scanFromURLAsync(r.assets[0].uri, ['qr']);
      console.log(`[veil-scan] photo: ${codes.length} code(s) found`);
      const hit = codes.find((c) => parseVeilAddLink(String(c.data || '')));
      if (!hit) { setNote('No Vardum QR found in that picture. Choose the picture of someone’s Vardum QR.'); return; }
      onScan({ data: hit.data, type: 'photo' });
    } catch (e) {
      console.log(`[veil-scan] photo scan failed: ${String((e as Error)?.message || e)}`);
      setNote('Couldn’t read that picture. Try another one.');
    }
  };

  return (
    <View style={styles.wrap}>
      {cam && perm === 'granted' ? (
        <cam.CameraView
          style={StyleSheet.absoluteFillObject}
          facing="back"
          barcodeScannerSettings={{ barcodeTypes: ['qr'] }}
          onBarcodeScanned={onScan}
          onCameraReady={() => console.log('[veil-scan] camera ready')}
          onMountError={(e) => console.log(`[veil-scan] camera failed to start: ${e?.message}`)}
        />
      ) : null}
      <View style={styles.overlay} pointerEvents="box-none">
        <Text style={styles.title}>Scan a Vardum QR</Text>
        <Text style={styles.sub}>
          {!cam
            ? 'Scanning needs the latest Vardum build. Until then, scan with your phone’s Camera app — it opens Vardum for you.'
            : perm === 'denied'
              ? 'Vardum needs camera access to scan. Turn it on in Settings → Vardum → Camera.'
              : 'Point the camera at the other person’s Vardum QR.'}
        </Text>
        {cam && perm === 'granted' ? <View style={styles.frame} /> : <View style={styles.frameSpacer} />}
        {note ? <Text style={styles.note}>{note}</Text> : null}
        {perm === 'denied' && cam ? (
          <TouchableOpacity style={styles.secondary} onPress={() => { void Linking.openSettings(); }}>
            <Text style={styles.secondaryTxt}>Open Settings</Text>
          </TouchableOpacity>
        ) : null}
        {cam ? (
          <TouchableOpacity style={styles.secondary} onPress={() => { void fromPhotos(); }} accessibilityLabel="Choose a QR picture from Photos">
            <Text style={styles.secondaryTxt}>Choose from Photos</Text>
          </TouchableOpacity>
        ) : null}
        <TouchableOpacity style={styles.close} onPress={onClose} accessibilityLabel="Close scanner">
          <Text style={styles.closeTxt}>Cancel</Text>
        </TouchableOpacity>
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  wrap: { ...StyleSheet.absoluteFillObject, backgroundColor: '#0B0B0F', zIndex: 95 },
  overlay: { flex: 1, alignItems: 'center', justifyContent: 'center', padding: 24 },
  title: { color: '#FFFFFF', fontSize: 22, fontWeight: '800', textAlign: 'center' },
  sub: { color: '#C9CFCE', fontSize: 14, lineHeight: 20, textAlign: 'center', marginTop: 8, alignSelf: 'stretch' },
  frame: { width: 250, height: 250, borderRadius: 22, borderWidth: 3, borderColor: '#FFFFFF', marginTop: 28, backgroundColor: 'transparent' },
  frameSpacer: { height: 40 },
  note: { color: '#d69a5c', fontSize: 13, textAlign: 'center', marginTop: 16, alignSelf: 'stretch' },
  secondary: { borderWidth: 1, borderColor: '#24242D', borderRadius: 11, paddingVertical: 12, paddingHorizontal: 22, marginTop: 18, backgroundColor: '#15151B' },
  secondaryTxt: { color: '#C9CFCE', fontSize: 14, fontWeight: '600' },
  close: { marginTop: 22, backgroundColor: '#15151B', borderWidth: 1, borderColor: '#24242D', borderRadius: 22, paddingVertical: 11, paddingHorizontal: 34 },
  closeTxt: { color: '#FFFFFF', fontSize: 14, fontWeight: '700' },
});
