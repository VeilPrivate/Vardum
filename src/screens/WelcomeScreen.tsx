import React from 'react';
import { View, Text, TouchableOpacity, StyleSheet, ScrollView, Share } from 'react-native';
import { useThemedPrompt } from './ThemedPrompt';
import { IS_ANDROID } from '../platformText';

/**
 * WelcomeScreen — the "Getting started" thread (onboarding-funnel-fix-spec,
 * item 2: a new user must land in a conversation, not an empty app).
 *
 * HONEST LIMITS (claims discipline, b187): the group protocol (veil-group-1)
 * still caps MEMBER groups at 8 with creator-device epoch rekeys, so a
 * server-side auto-add of every registration to a member group is NOT
 * possible, and a server-crafted "message from Matt" cannot exist in a
 * zero-knowledge relay (the server holds no keys). This note is therefore a
 * LOCAL, on-device welcome — clearly labelled as such. The real Founding
 * Tester Lounge is now a FOUNDER-BROADCAST lounge (b187, veil-lounge-1):
 * Matt is the only sender (per-sender signed envelopes, fail-closed
 * verification), testers join as read-only listeners via the hosted join
 * code, and replies open when member groups land. The legacy invite-link
 * member-group path remains as the fallback.
 */

/**
 * b142 (owner direction, 1 Oct): testers must NEVER have to find or paste the
 * invite link. The Join button silently fetches the CURRENT lounge invite
 * from this hosted file (owner rotates it by sending me the new link — I
 * re-upload the file; no app update needed). The request carries no user
 * identifier and happens only on an explicit tap. LOUNGE_INVITE_LINK below
 * stays as an optional baked override; the hosted file wins when it is empty.
 */
// b198: the lounge descriptor moved to OUR relay (the last Base44 runtime dependency retired)
const LOUNGE_INVITE_URL = 'https://relay.tryveil.app/api/apps/6a9dae3b8bc7a581e4ab310a/functions/getLoungeInvite';
const LOUNGE_INVITE_LINK = ''; // optional baked override; hosted file is the rotation path

/** b187: fetch the current lounge payload — either the new veil-lounge-1
 *  descriptor ({lounge:{...}}) or the legacy invite link ({invite:url}).
 *  Returns null on any failure (network, missing file, malformed content) —
 *  the paste fallback handles it. */
export async function fetchLoungePayload(): Promise<{ lounge?: unknown; invite?: string } | null> {
  try {
    const r = await fetch(LOUNGE_INVITE_URL);
    if (!r.ok) return null;
    const j = (await r.json()) as { lounge?: unknown; invite?: string | null };
    if (j && typeof j === 'object' && 'lounge' in j && j.lounge) return { lounge: j.lounge };
    const t = String((j && 'invite' in j ? j.invite : '') || '').trim();
    return /^https:/.test(t) ? { invite: t } : null;
  } catch {
    return null;
  }
}

export interface WelcomeScreenProps {
  veilId: string | null;
  onRunCheckup: () => void;
  onViewIntro: () => void;
  /** joins a pasted invite/group link — the same path every group join uses */
  onJoinInvite: (link: string) => Promise<void>;
  /** b187: joins the founder-broadcast lounge from a veil-lounge-1 descriptor */
  onJoinLounge?: (raw: unknown) => Promise<void>;
  onHide: () => void;
  onBack: () => void;
}

export function WelcomeScreen({ veilId, onRunCheckup, onViewIntro, onJoinInvite, onJoinLounge, onHide, onBack }: WelcomeScreenProps) {
  const { node: promptNode, ask } = useThemedPrompt();
  const shareId = () => {
    if (!veilId) return;
    Share.share({ message: veilId }).catch(() => undefined);
  };
  const joinLounge = async () => {
    // b141/b142 (owner direction, 1 Oct): one-tap opt-in — no link pasting.
    // The invite is resolved silently (baked override, else the hosted
    // file, else the paste fallback with a clear reason).
    const tryJoin = async (link: string, why: string) => {
      try {
        await onJoinInvite(link);
        await ask({ title: 'Joined', message: 'The Founding Tester Lounge is now in your conversations.', info: true });
        onBack();
      } catch (e) {
        const t = (await ask({
          title: 'Could not join automatically',
          message: IS_ANDROID ? `${why} Paste the invite link from the beta download page and you're in.` : `${why} Paste the invite link from TestFlight's "What to test" notes and you're in.`,
          input: 'text',
          submitLabel: 'Join',
        })) as string | null;
        const fallback = (t || '').trim();
        if (fallback) {
          try {
            await onJoinInvite(fallback);
            await ask({ title: 'Joined', message: 'The Founding Tester Lounge is now in your conversations.', info: true });
            onBack();
          } catch (e2) {
            await ask({ title: 'Could not join', message: String((e2 as Error).message || e2), info: true });
          }
        }
      }
    };
    const go = (await ask({
      title: 'Join the Founding Tester Lounge',
      message: 'One tap and you are in. It is the Founding Tester Lounge — a forum where Matt and every founding tester can talk. End-to-end encrypted, same as everything else in Vardum.',
      confirm: true,
      submitLabel: 'Join',
    })) as boolean | null;
    if (!go) return;
    // b187: prefer the veil-lounge-1 descriptor (founder-broadcast listener
    // join); fall back to the legacy member-group invite link.
    if (onJoinLounge) {
      const payload = await fetchLoungePayload();
      if (payload?.lounge) {
        try {
          await onJoinLounge(payload.lounge);
          await ask({ title: 'Joined', message: 'The Founding Tester Lounge is now in your conversations — you and every founding tester can post.', info: true });
          onBack();
          return;
        } catch (e) {
          await ask({ title: 'Could not join the lounge', message: String((e as Error).message || e), info: true });
          return;
        }
      }
    }
    const link = LOUNGE_INVITE_LINK || (await fetchLoungePayload())?.invite || '';
    await tryJoin(link, link ? 'The lounge invite did not work.' : 'The lounge invite is not set up yet.');
  };
  return (
    <View style={styles.fill}>
      <View style={styles.topBar}>
        <TouchableOpacity onPress={onBack}><Text style={styles.backTxt}>‹ Conversations</Text></TouchableOpacity>
        <TouchableOpacity onPress={onHide} hitSlop={{ top: 10, bottom: 10, left: 10, right: 10 }}>
          <Text style={styles.hideTxt}>Don't show again</Text>
        </TouchableOpacity>
      </View>
      <ScrollView style={styles.scroll} contentContainerStyle={styles.wrap}>
        <Text style={styles.kicker}>GETTING STARTED</Text>
        <Text style={styles.title}>Welcome to Vardum.</Text>
        <View style={styles.bubble}>
          <Text style={styles.bubbleWho}>A note from Matt, Vardum's developer</Text>
          <Text style={styles.bubbleTxt}>
            Thanks for testing Vardum. Your identity and keys were created on this device — nothing to verify, nothing to hand over.
          </Text>
          <Text style={styles.bubbleTxt}>
            Three things worth doing in your first hour: start a conversation, run the privacy checkup to set your protections, and keep your 24-word recovery phrase somewhere safe.
          </Text>
          <Text style={styles.bubbleTxt}>
            Found something odd? Tell me in the Founding Tester Lounge — one tap, no invite link needed.
          </Text>
          <Text style={styles.bubbleNote}>This welcome note lives only on your device. It is not a message and nothing was sent.</Text>
        </View>

        <TouchableOpacity style={styles.actionBtn} onPress={onRunCheckup}>
          <Text style={styles.actionTxt}>Run the privacy checkup</Text>
          <Text style={styles.actionSub}>Set your protections — nothing is pre-set, every control is yours.</Text>
        </TouchableOpacity>
        <TouchableOpacity style={styles.actionBtn} onPress={onViewIntro}>
          <Text style={styles.actionTxt}>View the introduction</Text>
          <Text style={styles.actionSub}>What Vardum protects against — and what it honestly does not.</Text>
        </TouchableOpacity>
        <TouchableOpacity style={styles.actionBtn} onPress={shareId} disabled={!veilId}>
          <Text style={styles.actionTxt}>Share your Vardum ID</Text>
          <Text style={styles.actionSub}>People use it to look you up. Keys stay sealed in the device keychain.</Text>
        </TouchableOpacity>
        <TouchableOpacity style={styles.actionBtn} onPress={() => { void joinLounge(); }}>
          <Text style={styles.actionTxt}>Join the Founding Tester Lounge</Text>
          <Text style={styles.actionSub}>One tap and you are in.</Text>
        </TouchableOpacity>
      </ScrollView>
      {promptNode}
    </View>
  );
}

const styles = StyleSheet.create({
  fill: { flex: 1, backgroundColor: '#0B0B0F' },
  topBar: { flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between', paddingHorizontal: 20, paddingTop: 16, paddingBottom: 10 },
  backTxt: { color: '#FFFFFF', fontSize: 14 },
  hideTxt: { color: '#5E6464', fontSize: 12.5 },
  scroll: { flex: 1 },
  wrap: { padding: 20, paddingTop: 8 },
  kicker: { color: '#5E6464', fontSize: 11, fontWeight: '700', letterSpacing: 1.2, marginBottom: 4 },
  title: { color: '#FFFFFF', fontSize: 24, fontWeight: '800', marginBottom: 16 },
  bubble: { backgroundColor: '#15151B', borderWidth: 1, borderColor: '#24242D', borderRadius: 16, padding: 18, marginBottom: 18 },
  bubbleWho: { color: '#FFFFFF', fontSize: 12, fontWeight: '700', marginBottom: 8 },
  bubbleTxt: { color: '#C9CFCE', fontSize: 14.5, lineHeight: 21, marginBottom: 10 },
  bubbleNote: { color: '#5E6464', fontSize: 11.5, lineHeight: 16, marginTop: 4 },
  actionBtn: { backgroundColor: '#15151B', borderWidth: 1, borderColor: '#24242D', borderRadius: 14, padding: 16, marginBottom: 12 },
  actionTxt: { color: '#FFFFFF', fontSize: 15, fontWeight: '700', marginBottom: 4 },
  actionSub: { color: '#8E9696', fontSize: 12.5, lineHeight: 17 },
});
