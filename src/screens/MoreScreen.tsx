/**
 * "More" — index of secondary VEIL destinations (web parity, Sept 19).
 * Security centre and Emergency access both live in Settings today (real,
 * working sections there — not new screens); More is a lightweight launcher
 * that mirrors the web build's index rather than duplicating that content.
 */
import React from 'react';
import { View, Text, TouchableOpacity, StyleSheet, Linking } from 'react-native';

export function MoreScreen({ onOpenSettings, onOpenStego, onOpenSettingsTab, webBaseUrl }: {
  onOpenSettings: () => void;
  /** open the Steganography tool (web parity: More indexes all privacy tools) */
  onOpenStego: () => void;
  /** switch to the Settings tab directly */
  onOpenSettingsTab: () => void;
  webBaseUrl: string;
}) {
  return (
    <View style={styles.wrap}>
      <Text style={styles.h1}>More</Text>
      <Text style={styles.p}>More Vardum tools and destinations.</Text>

      <TouchableOpacity style={styles.card} onPress={onOpenStego}>
        <View style={{ flex: 1 }}>
          <Text style={styles.cardTitle}>Steganography</Text>
          <Text style={styles.cardSub}>Hide a message inside an ordinary picture.</Text>
        </View>
        <Text style={styles.arrow}>→</Text>
      </TouchableOpacity>

      <TouchableOpacity style={styles.card} onPress={onOpenSettingsTab}>
        <View style={{ flex: 1 }}>
          <Text style={styles.cardTitle}>Settings</Text>
          <Text style={styles.cardSub}>Privacy controls, identity, device protection and account.</Text>
        </View>
        <Text style={styles.arrow}>→</Text>
      </TouchableOpacity>

      <TouchableOpacity style={styles.card} onPress={() => Linking.openURL(webBaseUrl)}>
        <View style={{ flex: 1 }}>
          <Text style={styles.cardTitle}>Security centre</Text>
          <Text style={styles.cardSub}>Session details, claims register and account recovery.</Text>
        </View>
        <Text style={styles.arrow}>→</Text>
      </TouchableOpacity>

      <TouchableOpacity style={styles.card} onPress={onOpenSettings}>
        <View style={{ flex: 1 }}>
          <Text style={styles.cardTitle}>Emergency access</Text>
          <Text style={styles.cardSub}>Decoy and Duress codes, what they do, and their honest limits.</Text>
        </View>
        <Text style={styles.arrow}>→</Text>
      </TouchableOpacity>
    </View>
  );
}

const styles = StyleSheet.create({
  wrap: { flex: 1, padding: 16 },
  h1: { color: '#FFFFFF', fontSize: 22, fontWeight: '800', marginBottom: 4 },
  p: { color: '#8E9696', fontSize: 13, marginBottom: 20 },
  card: {
    flexDirection: 'row', alignItems: 'center', borderWidth: 1, borderColor: '#24242D',
    borderRadius: 12, padding: 14, marginBottom: 12, backgroundColor: '#15151B',
  },
  cardTitle: { color: '#FFFFFF', fontSize: 15, fontWeight: '700', marginBottom: 4 },
  cardSub: { color: '#8E9696', fontSize: 12, lineHeight: 17 },
  arrow: { color: '#5E6464', fontSize: 16, marginLeft: 10 },
});
