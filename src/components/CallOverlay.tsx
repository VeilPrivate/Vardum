/**
 * VEIL CallOverlay (b144, W3): full-screen call surface — ring out, ring in,
 * active call with the local-only integrity dot, and the ended card.
 * Vardum palette (#15151B card, #FFFFFF accent; teal only for the V,
 * no raw error text — CallRefused reasons are surfaced verbatim from the
 * calls.ts guard rails, which never carry diagnostics).
 */
import React, { useEffect, useState } from 'react';
import { Modal, View, Text, TouchableOpacity, StyleSheet, Vibration } from 'react-native';
import { CallManager, type CallSnapshot } from '../calls/CallManager';

const CARD = '#15151B';
const ACCENT = '#FFFFFF';
const INK = '#FFFFFF';
const MUTED = '#8E9696';

function fmtDur(ms: number): string {
  const t = Math.max(0, Math.floor(ms / 1000));
  const m = Math.floor(t / 60);
  const s = t % 60;
  return `${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`;
}

function phaseLine(s: CallSnapshot, dur: string): string {
  // 21 Oct 2026: 'Ringing…' only once the other phone confirms it rings
  if (s.phase === 'calling') return s.reach === 'ringing' ? 'Ringing…' : s.reach === 'unreachable' ? 'Not reachable yet. Still trying…' : 'Calling…';
  if (s.phase === 'ringing') return 'Incoming call';
  // b151: signaling finished but the real media path hasn't connected yet —
  // say so, instead of jumping straight to a running timer.
  if (s.phase === 'connecting') return 'Connecting…';
  if (s.phase === 'active') return dur;
  return s.endedReason ? `Call ended · ${s.endedReason}` : 'Call ended';
}

const INTEGRITY_LABEL: Record<CallSnapshot['integrity'], string> = {
  ok: 'Integrity verified',
  amber: 'Minor interference detected',
  red: 'Someone may be in the middle — hang up',
};

export function CallOverlay() {
  const [snap, setSnap] = useState<CallSnapshot | null>(() => CallManager.snapshot());
  const [now, setNow] = useState(Date.now());

  useEffect(() => CallManager.subscribe(setSnap), []);
  useEffect(() => {
    if (!snap || snap.phase !== 'active') return;
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, [snap?.phase, snap?.callId]);

  if (!snap) return null;
  const dur = snap.startedAt ? fmtDur(now - snap.startedAt) : '00:00';
  const isCallee = snap.role === 'callee';

  return (
    <Modal transparent={false} animationType="fade" visible onRequestClose={() => CallManager.hangup()}>
      <View style={styles.wrap}>
        <View style={styles.card}>
          {/* arcs + wordmark — lock-screen family (owner standing design rule) */}
          <View style={styles.arcs}>
            <View style={[styles.arc, { width: 84, height: 84, opacity: 0.35 }]} />
            <View style={[styles.arc, { width: 60, height: 60, opacity: 0.55 }]} />
            <View style={[styles.arc, { width: 38, height: 38, opacity: 0.8 }]} />
          </View>
          <Text style={styles.wordmark}><Text style={{ color: '#20D9C2' }}>V</Text>ardum call</Text>
          <Text style={styles.peer} numberOfLines={1}>{snap.peerLabel}</Text>
          <Text style={[styles.phase, snap.integrity === 'red' ? styles.phaseRed : null]}>
            {phaseLine(snap, dur)}
          </Text>

          {/* local-only integrity dot — never leaves this device. Only shown
              once the call is genuinely active, not during ringing/connecting. */}
          {snap.phase === 'active' ? (
            <View style={styles.integrityRow}>
              <View style={[styles.integrityDot, styles[('dot_' + snap.integrity) as 'dot_ok' | 'dot_amber' | 'dot_red'] as never]} />
              <Text style={styles.integrityTxt}>{INTEGRITY_LABEL[snap.integrity]}</Text>
            </View>
          ) : (
            <View style={styles.integrityRowSpacer} />
          )}

          {/* controls */}
          {snap.phase === 'ringing' && isCallee ? (
            <View style={styles.btnRow}>
              <TouchableOpacity style={[styles.btn, styles.declineBtn]} onPress={() => { Vibration.cancel(); CallManager.decline(); }}>
                <Text style={styles.btnTxt}>Decline</Text>
              </TouchableOpacity>
              <TouchableOpacity style={[styles.btn, styles.answerBtn]} onPress={() => { Vibration.cancel(); void CallManager.answer(); }}>
                <Text style={styles.answerTxt}>Answer</Text>
              </TouchableOpacity>
            </View>
          ) : snap.phase === 'active' ? (
            <View style={styles.btnRow}>
              <TouchableOpacity style={[styles.btn, snap.muted ? styles.muteOnBtn : null]} onPress={() => CallManager.toggleMute()}>
                <Text style={styles.btnTxt}>{snap.muted ? 'Unmute' : 'Mute'}</Text>
              </TouchableOpacity>
              <TouchableOpacity style={[styles.btn, styles.endBtn]} onPress={() => CallManager.hangup()}>
                <Text style={styles.btnTxt}>End</Text>
              </TouchableOpacity>
            </View>
          ) : snap.phase === 'calling' || snap.phase === 'connecting' ? (
            <View style={styles.btnRow}>
              <TouchableOpacity style={[styles.btn, styles.endBtn]} onPress={() => CallManager.hangup()}>
                <Text style={styles.btnTxt}>Cancel</Text>
              </TouchableOpacity>
            </View>
          ) : null}
        </View>
      </View>
    </Modal>
  );
}

const styles = StyleSheet.create({
  wrap: { flex: 1, backgroundColor: '#0B0B0F' },
  card: { flex: 1, backgroundColor: CARD, alignItems: 'center', justifyContent: 'center', padding: 28 },
  arcs: { flexDirection: 'row', alignItems: 'center', justifyContent: 'center', marginBottom: 10 },
  arc: { borderRadius: 999, borderWidth: 2, borderColor: ACCENT, marginRight: -18 },
  wordmark: { color: INK, fontSize: 15, fontFamily: 'Menlo', fontWeight: '600', letterSpacing: 0.5, marginBottom: 18 },
  peer: { color: INK, fontSize: 26, fontWeight: '600', marginBottom: 6 },
  phase: { color: MUTED, fontSize: 15, marginBottom: 22 },
  phaseRed: { color: '#ff6b6b', fontWeight: '600' },
  integrityRow: { flexDirection: 'row', alignItems: 'center', marginBottom: 44 },
  integrityRowSpacer: { height: 9 + 44 }, // keeps controls from jumping when the dot is hidden
  integrityDot: { width: 9, height: 9, borderRadius: 999, marginRight: 8 },
  dot_ok: { backgroundColor: ACCENT },
  dot_amber: { backgroundColor: '#ffb454' },
  dot_red: { backgroundColor: '#ff6b6b' },
  integrityTxt: { color: MUTED, fontSize: 12, letterSpacing: 0.5 },
  btnRow: { flexDirection: 'row', gap: 18 },
  btn: { paddingHorizontal: 34, paddingVertical: 15, borderRadius: 14, borderWidth: 1, borderColor: ACCENT },
  btnTxt: { color: INK, fontSize: 15, fontWeight: '600' },
  answerBtn: { backgroundColor: ACCENT, borderColor: ACCENT },
  answerTxt: { color: '#0B0B0F', fontSize: 15, fontWeight: '700' },
  declineBtn: { borderColor: '#ff6b6b' },
  endBtn: { borderColor: '#ff6b6b' },
  muteOnBtn: { backgroundColor: 'rgba(255,255,255,0.18)' },
});
