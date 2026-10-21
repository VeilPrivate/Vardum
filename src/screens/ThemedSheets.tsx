/**
 * ThemedSheets — VEIL-branded replacements for the system-UI surfaces the
 * owner flagged (Sept 22, b105):
 *   1. useThemedChooser — the "Where should VEIL look?" source picker for
 *      Vault and Stego uploads. Was Alert.alert: a plain white Apple box.
 *   2. useThemedShare — the Veil ID share panel. Was Share.share: jumped
 *      straight into Apple's stock share sheet with zero VEIL branding.
 *
 * Same proven pattern as ThemedPrompt (b57): absolute overlay, NOT RN Modal
 * — the b25 modal/native-picker collision freeze stays avoided.
 *
 * Note on limits: the Photos/Files browsers and the final "which app do I
 * share to" sheet are iOS system surfaces and cannot be re-skinned — no app
 * can. These panels own every surface VEIL can own: the chooser the user
 * sees first, and the branded share card with Copy as the primary action.
 */
import React, { useCallback, useState } from 'react';
import {
  View, Text, TouchableOpacity, StyleSheet, Share,
} from 'react-native';

export interface ChooserOption {
  label: string;
  sub?: string;
}

export interface ChooserSpec {
  title: string;
  message?: string;
  options: ChooserOption[];
}

interface ActiveChooser {
  spec: ChooserSpec;
  resolve: (v: number | null) => void;
}

/** Themed source chooser — resolves the chosen option index, or null on cancel. */
export function useThemedChooser(): {
  node: React.ReactNode;
  choose: (spec: ChooserSpec) => Promise<number | null>;
} {
  const [active, setActive] = useState<ActiveChooser | null>(null);

  const choose = useCallback((spec: ChooserSpec) => {
    return new Promise<number | null>((resolve) => {
      setActive({ spec, resolve });
    });
  }, []);

  const settle = useCallback((v: number | null) => {
    setActive((cur) => {
      cur?.resolve(v);
      return null;
    });
  }, []);

  const node = active ? <ThemedChooserView spec={active.spec} onSettle={settle} /> : null;
  return { node, choose };
}

function ThemedChooserView({ spec, onSettle }: { spec: ChooserSpec; onSettle: (v: number | null) => void }) {
  return (
    <View style={styles.backdrop}>
      <TouchableOpacity style={StyleSheet.absoluteFill} activeOpacity={1} onPress={() => onSettle(null)} />
      <View style={styles.card}>
        <Text style={styles.title}>{spec.title}</Text>
        {spec.message ? <Text style={styles.message}>{spec.message}</Text> : null}
        {spec.options.map((o, i) => (
          <TouchableOpacity key={o.label} style={styles.optionRow} onPress={() => onSettle(i)}>
            <Text style={styles.optionLabel}>{o.label}</Text>
            {o.sub ? <Text style={styles.optionSub}>{o.sub}</Text> : null}
          </TouchableOpacity>
        ))}
        <TouchableOpacity style={styles.btnGhost} onPress={() => onSettle(null)}>
          <Text style={styles.btnGhostText}>Cancel</Text>
        </TouchableOpacity>
      </View>
    </View>
  );
}

export interface ShareSpec {
  /** panel heading (default: "Share your Veil ID") */
  title?: string;
  /** the value shown in the card and shared/copied (e.g. the Veil ID) */
  value: string;
  /** small kicker under the value (e.g. "People use it to look you up") */
  kicker?: string;
}

interface ActiveShare {
  spec: ShareSpec;
}

/** Themed share card — Copy as the primary action, Apple's share sheet only on demand. */
export function useThemedShare(): {
  node: React.ReactNode;
  share: (spec: ShareSpec) => void;
} {
  const [active, setActive] = useState<ActiveShare | null>(null);
  const [status, setStatus] = useState<string | null>(null);

  const share = useCallback((spec: ShareSpec) => {
    setStatus(null);
    setActive({ spec });
  }, []);

  const close = useCallback(() => setActive(null), []);

  const node = active ? <ThemedShareView spec={active.spec} status={status} onStatus={setStatus} onClose={close} /> : null;
  return { node, share };
}

function ThemedShareView({
  spec, status, onStatus, onClose,
}: {
  spec: ShareSpec;
  status: string | null;
  onStatus: (s: string | null) => void;
  onClose: () => void;
}) {
  const copy = async () => {
    try {
      // expo-clipboard is a NEW dependency (b105) — its native module ships
      // with the NEXT binary build; until then this require throws and we
      // fall back to the long-press hint below (the ID text is selectable).
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const Clipboard: typeof import('expo-clipboard') = require('expo-clipboard');
      await Clipboard.setStringAsync(spec.value);
      onStatus('Copied');
    } catch {
      onStatus('Copy needs the next app build — long-press the ID above to copy it for now.');
    }
  };

  return (
    <View style={styles.backdrop}>
      <TouchableOpacity style={StyleSheet.absoluteFill} activeOpacity={1} onPress={onClose} />
      <View style={styles.card}>
        <Text style={styles.title}>{spec.title || 'Share your Vardum ID'}</Text>
        <View style={styles.valueBox}>
          <Text style={styles.valueText} selectable>{spec.value}</Text>
        </View>
        {spec.kicker ? <Text style={styles.kicker}>{spec.kicker}</Text> : null}
        {status ? <Text style={styles.status}>{status}</Text> : null}
        <TouchableOpacity style={styles.btn} onPress={copy}>
          <Text style={styles.btnText}>Copy</Text>
        </TouchableOpacity>
        <TouchableOpacity style={styles.btnGhost} onPress={() => { void Share.share({ message: spec.value }).catch(() => {}); }}>
          <Text style={styles.btnGhostText}>Share…</Text>
        </TouchableOpacity>
        <TouchableOpacity style={styles.btnGhost} onPress={onClose}>
          <Text style={styles.btnGhostText}>Close</Text>
        </TouchableOpacity>
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  backdrop: {
    ...StyleSheet.absoluteFillObject,
    backgroundColor: 'rgba(11,11,15,0.86)',
    justifyContent: 'center',
    alignItems: 'center',
    padding: 22,
    zIndex: 90,
  },
  card: {
    width: '100%', maxWidth: 420,
    backgroundColor: '#15151B',
    borderRadius: 14,
    borderWidth: 1,
    borderColor: '#24242D',
    padding: 18,
  },
  title: { color: '#FFFFFF', fontSize: 15, fontWeight: '800', marginBottom: 6 },
  message: { color: '#8E9696', fontSize: 12, lineHeight: 17, marginBottom: 12 },
  optionRow: {
    backgroundColor: '#0B0B0F',
    borderWidth: 1,
    borderColor: '#3A3A44',
    borderRadius: 10,
    paddingVertical: 11,
    paddingHorizontal: 14,
    marginBottom: 8,
  },
  optionLabel: { color: '#FFFFFF', fontSize: 14, fontWeight: '700' },
  optionSub: { color: '#8E9696', fontSize: 11, marginTop: 2 },
  valueBox: {
    backgroundColor: '#0B0B0F',
    borderWidth: 1,
    borderColor: '#3A3A44',
    borderRadius: 10,
    padding: 12,
    marginVertical: 10,
  },
  valueText: { color: '#FFFFFF', fontSize: 15, fontWeight: '700', lineHeight: 21 },
  kicker: { color: '#d69a5c', fontSize: 11, marginBottom: 10 },
  status: { color: '#FFFFFF', fontSize: 11, fontWeight: '700', marginBottom: 10 },
  btn: {
    backgroundColor: '#15151B',
    borderWidth: 1,
    borderColor: '#3A3A44',
    borderRadius: 10,
    paddingVertical: 11,
    alignItems: 'center',
    marginBottom: 8,
  },
  btnText: { color: '#FFFFFF', fontSize: 14, fontWeight: '700' },
  btnGhost: {
    borderWidth: 1,
    borderColor: '#24242D',
    borderRadius: 10,
    paddingVertical: 10,
    alignItems: 'center',
    marginBottom: 8,
  },
  btnGhostText: { color: '#8E9696', fontSize: 13, fontWeight: '600' },
});
