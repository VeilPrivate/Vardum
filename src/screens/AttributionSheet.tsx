import React, { useState } from 'react';
import { View, Text, TouchableOpacity, StyleSheet, TextInput, ScrollView } from 'react-native';
import {
  ATTRIBUTION_OPTIONS, ATTRIBUTION_MAX_DETAIL,
} from '../../vendor/device/src/funnel';

/**
 * AttributionSheet — skippable one-tap "How did you hear about VEIL?" prompt
 * (attribution-spec). Shown ONCE, on the first screen after a Veil ID is
 * created. Never gates anything: tapping any option (or the X) dismisses it
 * for good; onboarding/landing in the app never depends on the answer.
 *
 * "Other" reveals a 60-char free-text field. "Prefer not to say" is an
 * answer in its own right (recorded as a category, like every other option).
 * The X records nothing — that is the "skipped" case.
 */

export interface AttributionSheetProps {
  onAnswer: (category: string, detail: string | null) => void;
  onSkip: () => void;
}

export function AttributionSheet({ onAnswer, onSkip }: AttributionSheetProps) {
  const [freeText, setFreeText] = useState('');
  const [showOther, setShowOther] = useState(false);

  const pick = (category: string) => {
    if (category === 'other') {
      setShowOther(true);
      return;
    }
    onAnswer(category, null);
  };

  const submitOther = () => {
    onAnswer('other', freeText.trim().slice(0, ATTRIBUTION_MAX_DETAIL) || null);
  };

  return (
    <View style={styles.backdrop}>
      <TouchableOpacity style={StyleSheet.absoluteFill} activeOpacity={1} onPress={onSkip} />
      <View style={styles.card}>
        <TouchableOpacity style={styles.closeBtn} onPress={onSkip} hitSlop={{ top: 12, bottom: 12, left: 12, right: 12 }}>
          <Text style={styles.closeTxt}>✕</Text>
        </TouchableOpacity>
        <Text style={styles.title}>How did you hear about Vardum?</Text>
        <Text style={styles.sub}>Optional. One tap — it helps us know which channels work.</Text>
        <ScrollView style={styles.options} contentContainerStyle={{ paddingBottom: 4 }}>
          {ATTRIBUTION_OPTIONS.map((o) => (
            <TouchableOpacity
              key={o.category}
              style={[styles.opt, o.label === 'Other' && showOther && styles.optOn]}
              onPress={() => pick(o.category)}
            >
              <Text style={styles.optTxt}>{o.label}</Text>
            </TouchableOpacity>
          ))}
          {showOther ? (
            <View style={styles.otherWrap}>
              <TextInput
                style={styles.otherInput}
                value={freeText}
                onChangeText={setFreeText}
                placeholder="In your own words (optional)"
                placeholderTextColor="#5E6464"
                maxLength={ATTRIBUTION_MAX_DETAIL}
                autoCapitalize="sentences"
                autoCorrect={false}
                autoFocus
                underlineColorAndroid="transparent"
              />
              <TouchableOpacity style={styles.otherBtn} onPress={submitOther}>
                <Text style={styles.otherBtnTxt}>Done</Text>
              </TouchableOpacity>
            </View>
          ) : null}
        </ScrollView>
        <TouchableOpacity style={styles.skipBtn} onPress={onSkip}>
          <Text style={styles.skipTxt}>Skip this</Text>
        </TouchableOpacity>
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  backdrop: { ...StyleSheet.absoluteFillObject, backgroundColor: 'rgba(11,11,15,0.6)', justifyContent: 'center', alignItems: 'center', zIndex: 40 },
  card: { width: '100%', maxWidth: 380, maxHeight: '82%', backgroundColor: '#15151B', borderRadius: 18, borderWidth: 1, borderColor: '#24242D', padding: 20, paddingTop: 16 },
  closeBtn: { position: 'absolute', top: 10, right: 14, padding: 4 },
  closeTxt: { color: '#5E6464', fontSize: 16 },
  title: { color: '#FFFFFF', fontSize: 18, fontWeight: '700', marginBottom: 6, paddingRight: 28 },
  sub: { color: '#8E9696', fontSize: 12.5, lineHeight: 17, marginBottom: 14 },
  options: { width: '100%' },
  opt: { paddingVertical: 13, borderTopWidth: 1, borderTopColor: '#24242D', alignItems: 'center', borderRadius: 6 },
  optOn: { backgroundColor: 'rgba(255,255,255,0.06)' },
  optTxt: { color: '#FFFFFF', fontSize: 15, fontWeight: '600' },
  otherWrap: { marginTop: 12 },
  otherInput: { color: '#FFFFFF', backgroundColor: '#0B0B0F', borderWidth: 1, borderColor: '#24242D', borderRadius: 10, paddingHorizontal: 12, paddingVertical: 10, fontSize: 15 },
  otherBtn: { backgroundColor: '#24242D', borderRadius: 10, paddingVertical: 11, alignItems: 'center', marginTop: 10 },
  otherBtnTxt: { color: '#FFFFFF', fontSize: 14, fontWeight: '700' },
  skipBtn: { marginTop: 14, paddingVertical: 8, alignItems: 'center' },
  skipTxt: { color: '#FFFFFF', fontSize: 13 },
});
