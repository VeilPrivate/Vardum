/**
 * "More from Vardum" — the 2x2 cross-link grid the web build shows
 * at the bottom of Vaults / Notes / Stego, pointing at the other privacy
 * tools plus Emergency codes and Move to another device (web parity, Sept 19).
 * Emergency codes + Move to another device live inside Settings on native —
 * both cards land there (Settings' Emergency access / Device transfer
 * sections are real, working destinations, not placeholders).
 */
import React from 'react';
import { View, Text, TouchableOpacity, StyleSheet } from 'react-native';

export type PrivacySuiteTarget = 'vaults' | 'notes' | 'stego' | 'settings';

interface Card {
  key: PrivacySuiteTarget;
  title: string;
  subtitle: string;
}

const ALL_TOOL_CARDS: Record<'vaults' | 'notes' | 'stego', Card> = {
  vaults: { key: 'vaults', title: 'Vaults', subtitle: 'Encrypted file containers' },
  notes: { key: 'notes', title: 'Encrypted notes', subtitle: 'Notes locked to this device' },
  stego: { key: 'stego', title: 'Steganography', subtitle: 'Hide payloads in PNG images' },
};

export function PrivacySuiteGrid({
  current,
  onNavigate,
}: {
  current: 'vaults' | 'notes' | 'stego';
  onNavigate: (target: PrivacySuiteTarget) => void;
}) {
  const otherTools = (Object.keys(ALL_TOOL_CARDS) as (keyof typeof ALL_TOOL_CARDS)[])
    .filter((k) => k !== current)
    .map((k) => ALL_TOOL_CARDS[k]);

  const cards: Card[] = [
    ...otherTools,
    { key: 'settings', title: 'Emergency codes', subtitle: 'Decoy and Duress codes' },
    { key: 'settings', title: 'Move to another device', subtitle: 'One-time encrypted transfer link' },
  ];

  return (
    <View style={styles.wrap}>
      <Text style={styles.label}>More from Vardum</Text>
      <View style={styles.grid}>
        {cards.map((c, i) => (
          <TouchableOpacity key={`${c.key}-${i}`} style={styles.card} onPress={() => onNavigate(c.key)}>
            <Text style={styles.cardTitle}>{c.title}</Text>
            <Text style={styles.cardSub}>{c.subtitle}</Text>
          </TouchableOpacity>
        ))}
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  wrap: { marginTop: 22, marginBottom: 8 },
  label: { color: '#5E6464', fontSize: 11, fontWeight: '700', letterSpacing: 0.5, marginBottom: 10 },
  grid: { flexDirection: 'row', flexWrap: 'wrap', gap: 10 },
  card: { flexBasis: '47%', flexGrow: 1, borderWidth: 1, borderColor: '#24242D', borderRadius: 10, padding: 12, backgroundColor: '#15151B' },
  cardTitle: { color: '#FFFFFF', fontSize: 13, fontWeight: '700', marginBottom: 3 },
  cardSub: { color: '#8E9696', fontSize: 11, lineHeight: 15 },
});
