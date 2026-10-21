import React, { memo, useEffect, useRef, useState } from 'react';
import { burnCountdownText } from '../burn';
import { ScrollView, View, Text, TextInput, TouchableOpacity, Pressable, FlatList, StyleSheet, Platform, Image, Modal, ActivityIndicator, Keyboard } from 'react-native';
import { useKbPadding } from '../hooks/useKbPadding';
import { Video, ResizeMode } from 'expo-av';
import { Ionicons } from '@expo/vector-icons';
import * as Clipboard from 'expo-clipboard';
import { useThemedChooser } from './ThemedSheets';
import { useThemedPrompt } from './ThemedPrompt';

// b69: Android saves through the system folder picker (no gallery permission)
const SAVE_MEDIA_LABEL = Platform.OS === 'android' ? 'Save to…' : 'Save to Photos';

/** b199: media error marker for a file the relay no longer has (404). */
export const MEDIA_GONE = 'gone';

/** b140: above this size the pick preview shows a soft warning (send still allowed). */
const MEDIA_SOFT_WARN_BYTES = 26214400; // 25 MB — matches chat.ts MEDIA_SOFT_WARN_BYTES

export interface ChatMediaUI {
  name: string;
  mime: string;
  size: number;
  dl: boolean;
  /** render source: resolved decrypted data: URI, or the sender's local pick */
  src: string | null;
  loading: boolean;
  error: string | null;
}

export interface ChatMessageUI {
  id: string;
  text: string;
  mine: boolean;
  ts: string | null;
  media?: ChatMediaUI;
  read?: boolean;
  /** b62 groups: short sender label above the bubble (web parity) */
  sender?: string;
  /** b62 groups: per-sender Ed25519 signature verified against the roster */
  senderVerified?: boolean;
  /** b62 groups: centered system line (member joined / keys rotated / sig discard) */
  systemNote?: string;
  /** b72: epoch ms this message was first displayed here — burn-countdown anchor */
  openedAt?: number;
  /** b199: group invitation card (Join / Decline) */
  groupInvite?: { name: string; link: string; from?: string };
  /** b199: reactions — one per side */
  reactions?: { mine?: string; peer?: string };
}

/** b199 (owner request, Oct 17): the quick reactions on a held message */
const REACTIONS = ['👍', '👎', '❤️', '🙏', '😂', '😮'];

/** b62 groups: admin + roster context for group threads */
export interface ChatGroupInfoUI {
  isCreator: boolean;
  /** Batch F (R4-2-01): the forum — no key rotation; "Remove" blocks and removes posts */
  forum?: boolean;
  epoch: number;
  fingerprint: string | null;
  members: { veilId: string; nick?: string; ikPub: string; role: string; joinedEpoch: number; tag: string }[];
  busy: boolean;
  onRotate: () => Promise<void>;
  onEvict: (member: { veilId: string; ikPub: string }) => Promise<void>;
}

export interface PendingPick {
  uri: string;
  name: string;
  mime: string;
  size: number;
  /** b62: set when this pick is a recorded voice note (drives the preview UI) */
  voiceSeconds?: number;
}

export interface ChatScreenProps {
  title: string;
  subtitle: string;
  status: 'pending' | 'active' | 'ended';
  busy: boolean;
  error: string | null;
  /** b172: honest notice when history is not being saved on this device. */
  historyNotice?: string | null;
  messages: ChatMessageUI[];
  /** b179: thread session token — re-arms memoized rows on thread switches. */
  threadKey: string;
  /** b180: dismiss the transient error banner (App-level error state). */
  onDismissError: () => void;
  draft: string;
  onDraftChange: (t: string) => void;
  onSend: () => void;
  /** b199: hold a message to react (pairwise threads); omitted = off */
  onReactMessage?: (id: string, emoji: string) => void;
  /** Play UGC: long-press menu on someone else's group / forum message (each optional) */
  onReportMessage?: (id: string, reason: string) => Promise<void>;
  onBlockSender?: (id: string) => Promise<void>;
  /** forum founder only: remove a post for everyone */
  onRemoveMessage?: (id: string) => Promise<void>;
  /** Play UGC: block this 1:1 contact (⋯ sheet; ends the chat) */
  onBlockContact?: () => void;
  onBack: () => void;
  /** b144 W3: start an encrypted call on this thread (1:1, ready threads only) */
  onStartCall?: () => void;
  onEndSession: () => void;
  onAttach: () => void;
  pendingPick: PendingPick | null;
  onSendMedia: () => void;
  onCancelPick: () => void;
  allowDl: boolean;
  onAllowDlChange: (v: boolean) => void;
  onMediaRetry: (id: string) => void;
  onMediaSave: (id: string) => void;
  mediaSaving: Record<string, 'saving' | 'saved' | 'error'>;
  /** b199 group invitations: joined/declined state kept on this phone */
  inviteState?: Record<string, 'joined' | 'declined'>;
  onJoinGroupInvite?: (msgId: string, link: string) => Promise<void>;
  onDeclineGroupInvite?: (msgId: string) => Promise<void>;
  /** b62 voice notes */
  voiceRec: { active: boolean; seconds: number };
  onVoiceRecord: () => void;
  onVoiceCancel: () => void;
  onVoiceSend: () => void;
  /** web parity: true when the peer of THIS thread is a pinned contact —
   *  enables the 'New chat thread with the same person' header button */
  canNewThread: boolean;
  onNewThread: () => void;
  /** b155 decision A: contact (pinned) session — badge shows 'Pinned contact',
   *  no ceremony, no 'waiting for peer'. Trust comes from the pin. */
  contact?: boolean;
  /** per-session verify ceremony state (web parity: 'Verified for this session') */
  myVerified: boolean;
  peerVerified: boolean;
  /** b161 (parity handoff): resolves true only when the RELAY confirms our slot's
   *  verified flag — the panel stays open and shows an INLINE retry on false. */
  onVerifySession: () => Promise<boolean>;
  /** b126: session fingerprint — viewable in the panel pre AND post verification */
  sessionFingerprint?: string | null;
  /** b126: peer veil id (pairwise only) — gates the "Pin as contact" affordance */
  peerVeilId?: string | null;
  /** b126: peer already pinned — flips the panel button to "Pinned" */
  readOnly?: boolean;
  textOnly?: boolean;
  peerPinned?: boolean;
  /** b126: promote the session peer into the permanent contacts (pins table) */
  onPinContact?: () => void;
  /** b62 groups: present only on group threads */
  group?: ChatGroupInfoUI;
  /** b72 web parity: "burn N hours after open" countdown — set only when the
   *  session's burn-after-open dial is on; burnSeconds is the window. */
  burnAfterOpen?: boolean;
  burnSeconds?: number;
  /** b95 (owner-approved Sept 21): one-time dismissible "verify fingerprints"
   *  card on first open of an unverified pairwise thread. Non-blocking — the
   *  ceremony stays Signal-style; the card just surfaces it loudly once. */
  showVerifyCard?: boolean;
  onVerifyCardDismiss?: () => void;
  /** b123: rename this thread locally (chat sheet) — shown only when the
   *  peer veil-id is known. Name is device-local, never transmitted. */
  canRename?: boolean;
  threadNickname?: string | null;
  onRenameThread?: (name: string) => void;
}

function mediaCaption(m: ChatMediaUI): string {
  const mb = (m.size / 1048576).toFixed(1);
  return `${m.name || 'media'} · ${mb} MB${m.dl ? ' · saving allowed' : ''}`;
}

function fmtSecs(n: number): string {
  const m = Math.floor(n / 60), s = n % 60;
  return `${m}:${String(s).padStart(2, '0')}`;
}

/**
 * b176: leaf burn-after-open countdown. Owns its own 1s interval so the
 * per-second re-render is confined to this Text node instead of re-rendering
 * every bubble in the FlatList (see b176 note above). Unmounted automatically
 * when burn-after-open is off or the row disappears.
 */
const BurnCountdown = memo(function BurnCountdown({ openedAt, burnSeconds }: { openedAt?: number; burnSeconds: number }) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const iv = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(iv);
  }, []);
  return <Text> · {burnCountdownText(openedAt, burnSeconds, now)}</Text>;
});

/**
 * b179 (owner report Oct 2: "the txt is still shaking" — even after the
 * b176 countdown memo). ROOT CAUSE: App re-renders on EVERY keystroke
 * (draft lives in App state) and every sync/presence/unread poll, and the
 * uiMessages map built per render hands FlatList brand-new object
 * identities — so EVERY message row re-rendered on EVERY keystroke and
 * EVERY poll tick. On iOS that wholesale row re-render is visible as the
 * text jittering ("shaking"). Fix: the row is now its own memo component
 * with a VALUE comparator — it re-renders only when its own content
 * (text/timestamp/read-tick/media state) actually changes. Callbacks are
 * deliberately NOT compared: they're invoked on press, and presses always
 * re-render the row first via the state they flip. `threadKey` guards
 * against a stale closure surviving a thread switch (ChatScreen's instance
 * is reused across threads, so rows must re-arm when the token changes).
 */
interface MessageRowProps {
  item: ChatMessageUI;
  group?: ChatGroupInfoUI;
  burnAfterOpen?: boolean;
  burnSeconds?: number;
  threadKey: string;
  playing: boolean;
  avErrMsg: string | null;
  saveState?: 'saving' | 'saved' | 'error';
  onMediaRetry: (id: string) => void;
  onMediaSave: (id: string) => void;
  onToggleAudio: (id: string, src: string, mime: string) => void;
  onOpenLightbox: (src: string, name: string) => void;
  onOpenVideo: (src: string, name: string) => void;
  /** b199 group invite card state + actions */
  inviteStatus?: 'joined' | 'declined' | 'joining' | 'error';
  onJoinInvite?: (id: string, link: string) => void;
  onDeclineInvite?: (id: string) => void;
  /** b199 reactions: undefined = reactions off for this thread */
  onReactOpen?: (id: string) => void;
  reactOpen?: boolean;
  onReact?: (id: string, emoji: string) => void;
  /** Play UGC: long-press menu (report / block / remove); undefined = off */
  onMenu?: (id: string) => void;
}

const MessageRow = memo(function MessageRow({
  item, group, burnAfterOpen, burnSeconds, threadKey,
  playing, avErrMsg, saveState,
  onMediaRetry, onMediaSave, onToggleAudio, onOpenLightbox, onOpenVideo,
  inviteStatus, onJoinInvite, onDeclineInvite,
  onReactOpen, reactOpen, onReact, onMenu,
}: MessageRowProps) {
  const renderMedia = () => {
    const media = item.media!;
    if (media.loading && !media.src) {
      return (
        <View style={styles.mediaStub}>
          <ActivityIndicator color="#FFFFFF" size="small" />
          <Text style={styles.mediaStubTxt}>Decrypting media…</Text>
        </View>
      );
    }
    if (media.error && !media.src) {
      // b199 (ZTE device run): the relay answered 404 — the file was deleted
      // (burn window or expiry). Retrying can never bring it back.
      if (media.error === MEDIA_GONE) {
        return (
          <View style={styles.mediaStub}>
            <Text style={styles.mediaErrTxt}>Deleted — this media has burned</Text>
          </View>
        );
      }
      return (
        <TouchableOpacity style={styles.mediaStub} onPress={() => onMediaRetry(item.id)}>
          <Text style={styles.mediaErrTxt}>Couldn't load media — tap to retry</Text>
        </TouchableOpacity>
      );
    }
    if (media.src) {
      const isVideo = media.mime.startsWith('video/');
      const isAudio = media.mime.startsWith('audio/');
      // Audio (voice note): compact play row — no bubble image
      if (isAudio) {
        return (
          <View style={styles.audioRow}>
            <TouchableOpacity style={styles.audioBtn} onPress={() => onToggleAudio(item.id, media.src!, media.mime)}>
              <Text style={styles.audioBtnTxt}>{playing ? '⏸' : '▶'}</Text>
            </TouchableOpacity>
            <Text style={[styles.audioLbl, avErrMsg ? styles.mediaErrTxt : null]}>
              {avErrMsg ?? (playing ? 'Playing…' : 'Voice note')}
            </Text>
          </View>
        );
      }
      // Video: poster-style inline player
      if (isVideo) {
        return (
          <View>
            <TouchableOpacity activeOpacity={0.9} style={styles.videoBox} onPress={() => onOpenVideo(media.src!, media.name)}>
              <Text style={styles.videoIcon}>▶</Text>
              <Text style={styles.videoLbl}>Video — tap to play full screen</Text>
            </TouchableOpacity>
            {media.dl ? (
              <TouchableOpacity
                style={styles.saveBtn}
                onPress={() => onMediaSave(item.id)}
                disabled={saveState === 'saving' || saveState === 'saved'}
              >
                <Text style={styles.saveBtnTxt}>
                  {saveState === 'saving' ? 'Saving…' : saveState === 'saved' ? 'Saved ✓' : saveState === 'error' ? 'Save failed — tap to retry' : SAVE_MEDIA_LABEL}
                </Text>
              </TouchableOpacity>
            ) : null}
          </View>
        );
      }
      // Image (original path)
      return (
        <View>
          <TouchableOpacity activeOpacity={0.9} onPress={() => onOpenLightbox(media.src!, media.name)}>
            <Image source={{ uri: media.src }} style={styles.mediaImg} resizeMode="cover" />
          </TouchableOpacity>
          {media.dl ? (
            <TouchableOpacity
              style={styles.saveBtn}
              onPress={() => onMediaSave(item.id)}
              disabled={saveState === 'saving' || saveState === 'saved'}
            >
              <Text style={styles.saveBtnTxt}>
                {saveState === 'saving' ? 'Saving…' : saveState === 'saved' ? 'Saved ✓' : saveState === 'error' ? 'Save failed — tap to retry' : SAVE_MEDIA_LABEL}
              </Text>
            </TouchableOpacity>
          ) : null}
        </View>
      );
    }
    // b75: peer media that this device hasn't cached — a stub, never silence
    return (
      <TouchableOpacity style={styles.mediaStub} onPress={() => onMediaRetry(item.id)}>
        <Text style={styles.mediaStubTxt}>Tap to load media</Text>
      </TouchableOpacity>
    );
  };

  if (item.systemNote) {
    // b62 groups: centered system line (member joined / keys rotated /
    // signature discard) — same visual family as the capture notice
    return <Text style={styles.captureNotice}>{item.systemNote}</Text>;
  }
  if (item.text && item.text.startsWith('\u26a0')) {
    // b61: capture notice (screenshot/recording) — a centered system
    // line, not a chat bubble. Travels as a normal E2EE message so
    // web peers see the plain text too.
    return <Text style={styles.captureNotice}>{item.text}</Text>;
  }
  if (item.groupInvite) {
    // b199: group invitation sent privately inside this encrypted chat
    const inv = item.groupInvite;
    return (
      <View style={[styles.bubbleRow, item.mine ? styles.mineRow : styles.peerRow]}>
        <View style={styles.inviteCard}>
          <Text style={styles.inviteKicker}>Group invitation</Text>
          <Text style={styles.inviteName} numberOfLines={2}>{inv.name}</Text>
          {item.mine ? (
            <Text style={styles.inviteSub}>You invited them. Only their phone can take this seat. The link carries the group’s key, so keep it private.</Text>
          ) : inviteStatus === 'joined' ? (
            <Text style={styles.inviteDone}>✓ Joined — find it in Conversations</Text>
          ) : inviteStatus === 'declined' ? (
            <Text style={styles.inviteSub}>Declined</Text>
          ) : (
            <>
              <Text style={styles.inviteSub}>You've been invited to join this group. This seat is for you.</Text>
              {inviteStatus === 'error' ? <Text style={styles.inviteErr}>Couldn't join — the invite may have expired. Ask for a new one.</Text> : null}
              <View style={styles.inviteActions}>
                <TouchableOpacity style={styles.inviteJoin} onPress={() => onJoinInvite?.(item.id, inv.link)} disabled={inviteStatus === 'joining'}>
                  <Text style={styles.inviteJoinTxt}>{inviteStatus === 'joining' ? 'Joining…' : 'Join'}</Text>
                </TouchableOpacity>
                <TouchableOpacity style={styles.inviteDecline} onPress={() => onDeclineInvite?.(item.id)} disabled={inviteStatus === 'joining'}>
                  <Text style={styles.inviteDeclineTxt}>Decline</Text>
                </TouchableOpacity>
              </View>
            </>
          )}
          {item.ts ? (
            <Text style={item.mine ? [styles.mineTs, styles.mineTsOnDark] : styles.peerTs}>
              {new Date(item.ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
            </Text>
          ) : null}
        </View>
      </View>
    );
  }
  const canReact = !!onReact && !item.systemNote && (!item.mine || !!item.id);
  const reacts = [item.reactions?.peer, item.reactions?.mine].filter(Boolean) as string[];
  return (
    <View style={[styles.bubbleRow, item.mine ? styles.mineRow : styles.peerRow]}>
      <View style={[styles.bubbleCol, item.mine ? styles.bubbleColMine : styles.bubbleColPeer]}>
      {reactOpen && canReact ? (
        <View style={[styles.reactBar, item.mine ? styles.reactBarMine : styles.reactBarPeer]}>
          {REACTIONS.map((e) => (
            <TouchableOpacity
              key={e}
              style={[styles.reactBtn, item.reactions?.mine === e ? styles.reactBtnOn : null]}
              onPress={() => onReact?.(item.id, e)}
              accessibilityLabel={item.reactions?.mine === e ? `Remove ${e} reaction` : `React ${e}`}
            >
              <Text style={styles.reactEmoji}>{e}</Text>
            </TouchableOpacity>
          ))}
          {/* b54 (owner, device test Oct 18): copy a text message — needed to
              pass invite links between phones from inside a chat */}
          {!item.media && item.text ? (
            <TouchableOpacity
              style={styles.reactBtn}
              onPress={() => { Clipboard.setStringAsync(item.text).catch(() => undefined); onReactOpen?.(item.id); }}
              accessibilityLabel="Copy message text"
            >
              <Ionicons name="copy-outline" size={20} color="#FFFFFF" />
            </TouchableOpacity>
          ) : null}
        </View>
      ) : null}
      <Pressable
        onLongPress={canReact ? () => onReactOpen?.(item.id) : (onMenu && !item.mine && !item.systemNote ? () => onMenu(item.id) : undefined)}
        delayLongPress={350}
        style={[styles.bubble, styles.bubbleInCol, item.mine ? styles.mineBubble : styles.peerBubble, item.media ? styles.mediaBubble : null]}
      >
        {group && !item.mine && item.sender ? (
          <Text style={styles.senderLbl}>
            {item.sender}{item.senderVerified ? ' ✓' : ''}
          </Text>
        ) : null}
        {item.media ? (
          <>
            {renderMedia()}
            <Text style={styles.mediaCaption}>{mediaCaption(item.media)}</Text>
          </>
        ) : (
          <Text style={item.mine ? styles.mineText : styles.peerText}>{item.text}</Text>
        )}
        {item.ts ? (
          <Text style={item.mine ? [styles.mineTs, item.media ? styles.mineTsOnDark : null] : styles.peerTs}>
            {new Date(item.ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
            {/* b123: read-receipt tick — teal ✓ read, replacing the washed-out
                plain " · read" text (owner live-test ask, Sept 24). */}
            {item.mine && item.read ? <Text style={styles.readTick}>  ✓ read</Text> : null}
            {/* b198 two-dial: the SENDER's countdown only exists once the peer's
                read receipt landed (openedAt restamped at receipt) — pre-receipt
                there is no burn clock to show, matching the relay copy */}
            {burnAfterOpen && !item.systemNote && (!item.mine || item.read) ? <BurnCountdown openedAt={item.openedAt} burnSeconds={burnSeconds ?? 86400} /> : null}
          </Text>
        ) : null}
      </Pressable>
      {reacts.length ? (
        <View style={[styles.reactBadge, item.mine ? styles.reactBadgeMine : styles.reactBadgePeer]}>
          <Text style={styles.reactBadgeTxt}>{reacts.join(' ')}</Text>
        </View>
      ) : null}
      </View>
    </View>
  );
}, (a, b) => {
  // VALUE compare — new object identities from the per-render map must NOT
  // re-render the row (that's the shake). Callbacks excluded by design.
  const ai = a.item, bi = b.item;
  if (ai.id !== bi.id || ai.text !== bi.text || ai.mine !== bi.mine || ai.ts !== bi.ts
    || ai.read !== bi.read || ai.sender !== bi.sender || ai.senderVerified !== bi.senderVerified
    || ai.systemNote !== bi.systemNote || ai.openedAt !== bi.openedAt) return false;
  if ((ai.reactions?.mine ?? '') !== (bi.reactions?.mine ?? '') || (ai.reactions?.peer ?? '') !== (bi.reactions?.peer ?? '')
    || a.reactOpen !== b.reactOpen || !!a.onReact !== !!b.onReact || !!a.onMenu !== !!b.onMenu) return false;
  if ((ai.groupInvite?.link ?? '') !== (bi.groupInvite?.link ?? '') || a.inviteStatus !== b.inviteStatus) return false;
  const am = ai.media, bm = bi.media;
  if (!!am !== !!bm) return false;
  if (am && bm && (am.name !== bm.name || am.mime !== bm.mime || am.size !== bm.size
    || am.dl !== bm.dl || am.src !== bm.src || am.loading !== bm.loading || am.error !== bm.error)) return false;
  if (a.group !== b.group || a.burnAfterOpen !== b.burnAfterOpen || a.burnSeconds !== b.burnSeconds
    || a.threadKey !== b.threadKey || a.playing !== b.playing || a.avErrMsg !== b.avErrMsg
    || a.saveState !== b.saveState) return false;
  return true;
});

export function ChatScreen({ title, subtitle, status, busy, error, historyNotice, messages, threadKey, onDismissError, draft, onDraftChange, onSend, onBack, onStartCall, onEndSession, canNewThread, onNewThread, contact, myVerified, peerVerified, onVerifySession, onAttach, pendingPick, onSendMedia, onCancelPick, allowDl, onAllowDlChange, onMediaRetry, onMediaSave, mediaSaving, voiceRec, onVoiceRecord, onVoiceCancel, onVoiceSend, group, burnAfterOpen, burnSeconds, showVerifyCard, onVerifyCardDismiss, canRename, threadNickname, onRenameThread, sessionFingerprint, peerVeilId, peerPinned,
  readOnly, textOnly, onPinContact, inviteState, onJoinGroupInvite, onDeclineGroupInvite, onReactMessage,
  onReportMessage, onBlockSender, onRemoveMessage, onBlockContact }: ChatScreenProps) {
  // Play UGC (18 Oct 2026): long-press someone else's group / forum message ->
  // report it to the founder, block its sender, or (founder) remove it for
  // everyone. Rows get one stable callback; the live props ride a ref.
  const { node: chooserNode, choose } = useThemedChooser();
  const { node: promptNode, ask } = useThemedPrompt();
  const menuRef = useRef({ onReportMessage, onBlockSender, onRemoveMessage, messages });
  menuRef.current = { onReportMessage, onBlockSender, onRemoveMessage, messages };
  const hasMessageMenu = !!(onReportMessage || onBlockSender || onRemoveMessage);
  const onMessageMenu = React.useCallback(async (id: string) => {
    const { onReportMessage: report, onBlockSender: block, onRemoveMessage: remove, messages: list } = menuRef.current;
    const item = list.find((m) => m.id === id);
    if (!item || item.mine || item.systemNote) return;
    const who = item.sender || 'this sender';
    const actions: { label: string; sub?: string; run: () => Promise<void> }[] = [];
    if (remove) actions.push({ label: 'Remove for everyone', sub: 'Deletes this post from the forum on every phone', run: async () => {
      const ok = await ask({ title: 'Remove this post for everyone?', message: 'It disappears from the forum on every phone running a current Vardum. This can’t be undone.', confirm: true, danger: true, submitLabel: 'Remove' });
      if (ok === true) await remove(id);
    } });
    if (report) actions.push({ label: 'Report post', sub: 'Only the founder can read it', run: async () => {
      const reasons = ['Abuse or harassment', 'Hate or threats of violence', 'Sexual content', 'Spam or scam', 'Something else'];
      const r = await choose({ title: 'Report this post', message: 'What you write and a copy of the post go only to the forum founder, end-to-end encrypted. The server and other forum members can see that you sent a report, but not what it says. The person you report isn’t notified.', options: reasons.map((label) => ({ label })) });
      if (r === null) return;
      let reason = reasons[r];
      if (r === reasons.length - 1) {
        const t = await ask({ title: 'What’s wrong with this post?', input: 'text', placeholder: 'A few words (optional)', maxLength: 300, submitLabel: 'Send report' });
        if (t === null || t === false) return;
        reason = String(t).trim() ? `Something else: ${String(t).trim()}` : 'Something else';
      }
      await report(id, reason);
      await ask({ title: 'Report sent', message: 'Thank you. It goes to the founder’s phone and is opened in turn, so it may take a while. You can also block the sender from the same menu.', info: true });
    } });
    if (block) actions.push({ label: `Block ${who}`, sub: 'Hide their posts and messages on this phone', run: async () => {
      const ok = await ask({ title: `Block ${who}?`, message: 'You won’t see their posts or messages on this phone, and they won’t notify you. They aren’t told. You can unblock them in Settings.', confirm: true, danger: true, submitLabel: 'Block' });
      if (ok === true) await block(id);
    } });
    if (!actions.length) return;
    const i = await choose({ title: 'This message', options: actions.map(({ label, sub }) => ({ label, sub })) });
    if (i === null) return;
    try {
      await actions[i].run();
    } catch (e) {
      console.log('[veil-ugc] message action failed:', String((e as Error)?.message ?? e));
      await ask({ title: 'That didn’t work', message: String((e as Error)?.message || 'Please try again in a moment.'), info: true });
    }
  }, [choose, ask]);
  const confirmBlockContact = React.useCallback(async () => {
    if (!onBlockContact) return;
    const ok = await ask({ title: `Block ${title}?`, message: 'This ends the chat on both sides and hides them on this phone: no messages, no notifications, no new chat requests from them. They aren’t told why. You can unblock them in Settings.', confirm: true, danger: true, submitLabel: 'Block' });
    if (ok === true) onBlockContact();
  }, [ask, onBlockContact, title]);
  // b199 reactions: which message's bar is open. Rows get stable callbacks
  // (their memo compare skips callbacks), routed through a ref.
  const [reactOpenId, setReactOpenId] = React.useState<string | null>(null);
  const onReactRef = useRef(onReactMessage);
  onReactRef.current = onReactMessage;
  const openReact = React.useCallback((id: string) => setReactOpenId((cur) => (cur === id ? null : id)), []);
  const pickReact = React.useCallback((id: string, emoji: string) => { setReactOpenId(null); onReactRef.current?.(id, emoji); }, []);
  useEffect(() => { setReactOpenId(null); }, [threadKey]);
  // b199 group invitations: in-flight / failed joins (persisted outcome lives in inviteState)
  const [inviteBusy, setInviteBusy] = React.useState<Record<string, 'joining' | 'error'>>({});
  const joinInvite = React.useCallback((id: string, link: string) => {
    if (!onJoinGroupInvite) return;
    setInviteBusy((s) => ({ ...s, [id]: 'joining' }));
    onJoinGroupInvite(id, link)
      .then(() => setInviteBusy((s) => { const n = { ...s }; delete n[id]; return n; }))
      .catch((e) => { console.log('[veil-group-invite] join failed:', String((e as Error)?.message ?? e)); setInviteBusy((s) => ({ ...s, [id]: 'error' })); });
  }, [onJoinGroupInvite]);
  const declineInvite = React.useCallback((id: string) => { void onDeclineGroupInvite?.(id); }, [onDeclineGroupInvite]);
  // b62 groups: Members overlay + evict two-tap arming
  const [groupPanel, setGroupPanel] = React.useState(false);
  // the members panel needs the whole screen — drop the message keyboard when it opens
  React.useEffect(() => { if (groupPanel) Keyboard.dismiss(); }, [groupPanel]);
  const [evictArmed, setEvictArmed] = React.useState<string | null>(null);
  const [groupErr, setGroupErr] = React.useState<string | null>(null);
  React.useEffect(() => { if (!group) { setGroupPanel(false); setEvictArmed(null); setGroupErr(null); } }, [group]);

  // b111 (owner report: keyboard covers what you're typing): RN's
  // KeyboardAvoidingView "padding" mode proved unreliable on device — replaced
  // with deterministic keyboard-height padding: the composer grows by exactly
  // the keyboard height, the message list shrinks, and the input always sits
  // directly above the keys. Raw height comes from iOS's keyboardWillShow /
  // WillHide / WillChangeFrame (floating keyboard included).
  const kbH = useKbPadding();
  // follow the keyboard: once it's up, bring the newest message (and what
  // you're typing) into view — a small delay lets the shrunken list lay out.
  useEffect(() => {
    if (kbH > 0) { const t = setTimeout(() => listRef.current?.scrollToEnd?.({ animated: false }), 60); return () => clearTimeout(t); }
  }, [kbH]);
  // b180 (owner report: the "server is briefly busy" banner never goes away
  // unless you exit the thread): chat errors are TRANSIENT by design — the
  // banner says "wait a few seconds and try again", so it must hold itself
  // to that promise. Self-dismiss after 6s; a new error resets the clock,
  // a successful send clears it instantly (App: b180 success-path clear).
  useEffect(() => {
    if (!error) return;
    const t = setTimeout(() => onDismissError(), 6000);
    return () => clearTimeout(t);
  }, [error, onDismissError]);
  // b62: media playback (voice notes + video). One shared AV player: playing a
  // new item stops the previous. data: URIs work with expo-av via source={{ uri }}.
  const [audioPlayingId, setAudioPlayingId] = useState<string | null>(null);
  const soundRef = useRef<{ unloadAsync: () => Promise<unknown> } | null>(null);
  // b198 watchdog: expo-av's status callback proved unreliable as an end-of-
  // playback signal on real voice notes (owner: row stuck "Playing…" until a
  // manual pause — persisted across the didJustFinish + isPlaying callback
  // fixes). Poll the player DIRECTLY once a second: any loaded player that is
  // not playing past the start, or reports didJustFinish, is done. Cleared on
  // every stop, so it never outlives the playback.
  const audioWatchRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const stopAudio = async () => {
    if (audioWatchRef.current) { clearInterval(audioWatchRef.current); audioWatchRef.current = null; }
    const s = soundRef.current as ({ unloadAsync: () => Promise<unknown>; setOnPlaybackStatusUpdate?: (cb: null) => void } | null);
    soundRef.current = null;
    if (s) {
      // b199 (seen on the first expo-av 15 device run: ~150 "ended" resets
      // after one voice note): an unloaded player keeps emitting isLoaded:false
      // status updates, and each one re-ran this stop. Detach the listener
      // before unloading.
      try { s.setOnPlaybackStatusUpdate?.(null); } catch { /* older player */ }
      try { await s.unloadAsync(); } catch { /* already gone */ }
    }
    setAudioPlayingId(null);
  };
  const [audioErr, setAudioErr] = useState<{ id: string; msg: string } | null>(null);
  const toggleAudio = async (id: string, src: string, mime: string) => {
    if (audioPlayingId === id) { await stopAudio(); return; }
    await stopAudio();
    setAudioErr(null);
    console.log(`[veil-av] play tapped (${mime || 'no mime'}, ${src.slice(0, 5) === 'data:' ? 'data uri' : 'file'})`);
    try {
      // b73 (owner report: receive-side voice notes viewable but silently
      // dead on tap): a prior recording session on this device leaves iOS's
      // audio session in .playAndRecord — reset it to plain playback first,
      // best-effort, so a stale record-mode session can't mute playback.
      const { Audio } = require('expo-av');
      try { await Audio.setAudioModeAsync({ allowsRecordingIOS: false, playsInSilentModeIOS: true, staysActiveInBackground: false }); } catch { /* best-effort */ }
      // b199: this playback ends exactly once, however many status updates
      // follow — and only once it has really started: expo-av 15 can report
      // isLoaded:false BEFORE createAsync resolves, which used to end the
      // playback before it began (row stuck on "Playing").
      let ended = false;
      let live: unknown = null;
      const end = (why: string) => { if (ended || !live) return; ended = true; console.log(`[veil-av] ${why} — resetting row`); void stopAudio(); };
      // b199 (Android device run): a player that never finishes loading used
      // to leave the row silent with no log and no error. Give it 10 s.
      const created = Audio.Sound.createAsync(
        { uri: src },
        { shouldPlay: true },
        (st: { isLoaded?: boolean; didJustFinish?: boolean; isPlaying?: boolean; positionMillis?: number }) => {
          if (ended || !live || soundRef.current !== live) return;
          if (!st.isLoaded || st.didJustFinish) { end('status ended the playback'); return; }
          if (st.isPlaying === false && (st.positionMillis ?? 0) > 0) end('status stopped-without-finish');
        },
      );
      const { sound } = await Promise.race([
        created,
        new Promise<never>((_, rej) => setTimeout(() => rej(new Error('player did not load within 10 s')), 10000)),
      ]);
      console.log('[veil-av] player loaded — playing');
      soundRef.current = sound as unknown as { unloadAsync: () => Promise<unknown> };
      live = sound; // b199: from here on, status updates and the watchdog count
      setAudioPlayingId(id);
      let ticks = 0;
      const watchdog = setInterval(async () => {
        try {
          const s = await (sound as unknown as { getStatusAsync: () => Promise<{ isLoaded?: boolean; didJustFinish?: boolean; isPlaying?: boolean; positionMillis?: number; durationMillis?: number; isBuffering?: boolean; volume?: number; isMuted?: boolean }> }).getStatusAsync();
          if (ticks++ < 3) console.log(`[veil-av] tick ${ticks}: playing=${!!s.isPlaying} pos=${s.positionMillis ?? '?'} dur=${s.durationMillis ?? '?'} buffering=${!!s.isBuffering} vol=${s.volume ?? '?'} muted=${!!s.isMuted}`);
          // b199 (ZTE device run): Android can load a note and never start it
          // (shouldPlay ignored — the row sat on "Playing" at 0:00 in silence).
          // Nudge it once at 2 s; if it still hasn't moved by 5 s, say so.
          if (s.isLoaded && !s.isPlaying && (s.positionMillis ?? 0) === 0 && !s.isBuffering) {
            if (ticks === 2) { console.log('[veil-av] not started — nudging play'); void (sound as unknown as { playAsync: () => Promise<unknown> }).playAsync().catch(() => undefined); }
            if (ticks >= 5) { ended = true; console.log('[veil-av] never started — giving up'); void stopAudio(); setAudioErr({ id, msg: 'Could not play — tap to retry' }); }
          }
          if (!s.isLoaded || s.didJustFinish || (s.isPlaying === false && (s.positionMillis ?? 0) > 0)) {
            end(`watchdog: playback ended (loaded=${!!s.isLoaded} finish=${!!s.didJustFinish} playing=${!!s.isPlaying} pos=${s.positionMillis ?? 0})`);
          }
        } catch { end('watchdog: status read failed'); }
      }, 1000);
      audioWatchRef.current = watchdog;
    } catch (e) {
      // b73: was silently swallowed — a dead ▶ with no feedback is exactly
      // the owner-reported symptom. Now visible + logged for Metro triage.
      console.log('[veil-av] playback failed:', String(e));
      // b74 (owner report: voice note SENT FROM WEB taps to "error"): the web
      // app records voice notes as audio/webm;codecs=opus (Chrome/Firefox
      // MediaRecorder) — iOS's AVPlayer CANNOT decode webm/opus at all, so
      // the tap fails no matter how clean the decrypt/cache was. Native-to-
      // native notes (.m4a) play fine. Real fix is web-side (WAV transcode
      // work order to builder); until it lands, say WHY instead of a generic
      // retry that can never succeed.
      const m = (mime || '').toLowerCase();
      if (m.includes('webm') || m.includes('ogg')) {
        setAudioErr({ id, msg: 'Web app voice notes use a codec iOS can\'t play — web fix in progress' });
      } else {
        setAudioErr({ id, msg: 'Could not play — tap to retry' });
      }
    }
  };
  useEffect(() => { return () => { void stopAudio(); }; }, []);
  const listRef = useRef<FlatList<ChatMessageUI>>(null);
  const [lightbox, setLightbox] = useState<{ src: string; name: string } | null>(null);
  // b140: full-screen video player — a video bubble taps straight into a
  // native-controls player covering the screen (voice notes keep the inline row).
  const [videoFS, setVideoFS] = useState<{ src: string; name: string } | null>(null);
  useEffect(() => {
    if (messages.length) listRef.current?.scrollToEnd?.({ animated: false });
  }, [messages.length]);

  // b163 (web P1.2 parity, owner decision Oct 2): sending requires BOTH sides'
  // fingerprint ceremony on EVERY pairwise path — pinned contact threads no
  // longer send on keys alone. Groups are exempt: their trust anchor is the
  // group signature scheme, not a pairwise ceremony.
  const verifyGate = !group && !(myVerified && peerVerified);
  const composerLocked = readOnly || status !== 'active' || busy || verifyGate;
  // b187: lounge read-only notice — the composer is locked by design; this
  // replaces any silence with the honest reason, styled as a soft system note.
  const loungeNote = readOnly
    ? 'Founder broadcast — only Matt posts here. Replies open when member groups land.'
    : (textOnly ? 'Founding testers forum — end-to-end encrypted. Photos and voice notes land in the next build.' : null);

  // (b66) the ✕ sheet is now VEIL-styled instead of the plain system action
  // sheet: End renders as a true RED destructive button (the system sheet showed
  // plain text on device), and a stray tap still can't end the session — End
  // requires a deliberate press on the red row.
  const [sheet, setSheet] = useState(false);
  // b126: verification panel replaces the system Alert — the fingerprint is
  // shown BEFORE "Mark verified" unlocks (two-step comparison gate), and the
  // same panel stays viewable any time AFTER verification via the badge.
  const [verifyPanel, setVerifyPanel] = useState<'ceremony' | 'view' | null>(null);
  /** b161: panel-LOCAL verify failure — never the app-wide error state (suppression rule). */
  const [verifyFail, setVerifyFail] = useState(false);
  const [compareArmed, setCompareArmed] = useState(false);
  // b123: local thread rename (device-local nickname against the peer veil-id)
  const [renameOpen, setRenameOpen] = useState(false);
  const [renameInput, setRenameInput] = useState('');
  // b176 (owner report Oct 2, live on-device: bubbles visibly "shaking"
  // side-to-side during rapid-fire bursts on a burn-after-open thread): the
  // b72 design ticked ONE parent-level clock state every second, which
  // re-rendered the ENTIRE message list 1×/s — stacked with per-message
  // renders from the burst it read as a continuous wobble. The tick now
  // lives inside <BurnCountdown> below, so a per-second update touches
  // only that one countdown Text node, and the FlatList renders only
  // when messages actually change.

  // b179: renderMedia moved into memoized MessageRow (shake fix) — see above.

  return (
    <View style={styles.fill}>
    <View style={styles.fill}>
      {/* header */}
      {/* b199 UI redesign (owner, Oct 16): one clean bar — back, avatar, name +
          status, call, ⋯. "＋ New" lived here AND in the ✕ sheet; it is now
          only in the ⋯ sheet, and ⋯ replaces ✕ (✕ read as "close"). */}
      <View style={styles.header}>
        <TouchableOpacity onPress={onBack} style={styles.backBtn} hitSlop={{ top: 10, bottom: 10, left: 10, right: 6 }} accessibilityLabel="Back">
          <Ionicons name="chevron-back" size={26} color="#FFFFFF" />
        </TouchableOpacity>
        <View style={[styles.hAvatar, group && styles.hAvatarGroup]}>
          <Text style={styles.hAvatarTxt}>{group ? '#' : title.slice(0, 2).toUpperCase()}</Text>
        </View>
        <View style={styles.headerMid}>
          <Text style={styles.title} numberOfLines={1}>{title}</Text>
          {status === 'pending' || status === 'ended' ? (
            <Text style={styles.subtitle} numberOfLines={1}>{status === 'pending' ? 'Waiting for your contact to accept…' : 'Session ended'}</Text>
          ) : null}
          {group ? (
            <TouchableOpacity style={styles.vBadge} onPress={() => setGroupPanel(true)} hitSlop={{ top: 10, bottom: 10 }}>
              <Text style={styles.vBadgeTxtGroup}>Members · epoch {group.epoch} ›</Text>
            </TouchableOpacity>
          ) : status !== 'ended' ? (
            /* b163 (web P1.2 parity): pinned contact threads show the SAME
             * ceremony state as invite threads — the 'Pinned contact' trust
             * chip is gone; sending unlocks only when both sides confirm.
             * The pin still anchors identity (panel shows the pinned state);
             * the ceremony is the human comparison on top of it. */
            <TouchableOpacity
              style={[styles.vBadge, myVerified && peerVerified ? styles.vBadgeOk : myVerified || peerVerified ? styles.vBadgeHalf : styles.vBadgeNone]}
              onPress={() => { setCompareArmed(false); setVerifyPanel(myVerified ? 'view' : 'ceremony'); }}
            >
              <Text style={[styles.vBadgeTxt, myVerified && peerVerified ? styles.vBadgeTxtOk : myVerified || peerVerified ? styles.vBadgeTxtHalf : styles.vBadgeTxtNone]}>
                {myVerified && peerVerified ? '✓ Verified' : myVerified ? 'You verified · waiting for peer' : peerVerified ? 'Peer verified · tap to verify' : 'Not verified'}
              </Text>
            </TouchableOpacity>
          ) : null}
        </View>
        {onStartCall && status !== 'ended' && status !== 'pending' ? (
          <TouchableOpacity onPress={onStartCall} style={styles.callBtn} hitSlop={{ top: 10, bottom: 10, left: 6, right: 6 }} accessibilityLabel="Call">
            {/* b198 (owner): a proper phone icon replaces the two-ring glyph */}
            <Ionicons name="call-outline" size={22} color="#FFFFFF" />
          </TouchableOpacity>
        ) : null}
        {status !== 'ended' ? (
          <TouchableOpacity onPress={() => setSheet(true)} disabled={busy} style={styles.menuBtn} hitSlop={{ top: 12, bottom: 12, left: 8, right: 12 }} accessibilityLabel="Chat options">
            <Ionicons name="ellipsis-horizontal" size={22} color="#8E9696" />
          </TouchableOpacity>
        ) : null}
      </View>

      {/* b62 groups: Members overlay — roster, epoch fingerprint, creator admin */}
      {group && groupPanel ? (
        <View style={styles.groupOverlay}>
          <View style={styles.groupPanel}>
            <View style={styles.groupPanelHead}>
              <Text style={styles.groupPanelTitle}>Group members</Text>
              <TouchableOpacity onPress={() => { setGroupPanel(false); setEvictArmed(null); setGroupErr(null); }} hitSlop={{ top: 10, bottom: 10 }}>
                <Text style={styles.groupCloseTxt}>✕</Text>
              </TouchableOpacity>
            </View>
            <Text style={styles.groupFp}>
              Epoch {group.epoch} fingerprint{'\n'}
              {group.fingerprint || 'Not available yet — opens with the group'}
            </Text>
            <ScrollView style={styles.groupMemberList}>
              {group.members.length === 0 ? (
                <Text style={styles.groupEmpty}>The roster opens with the group.</Text>
              ) : group.members.map((m) => (
                <View key={m.veilId} style={styles.groupMemberRow}>
                  <View style={{ flex: 1 }}>
                    <Text style={styles.groupMemberName}>{m.nick ? m.nick : m.veilId.slice(0, 10) + '…'}</Text>
                    {!!m.nick && <Text style={styles.groupMemberMeta}>{m.veilId.slice(0, 10)}…</Text>}
                    <Text style={styles.groupMemberMeta}>{m.role === 'creator' ? 'Creator' : m.role === 'pending' ? 'Waiting to be confirmed — no group keys yet' : 'Member'} · joined epoch {m.joinedEpoch}</Text>
                  </View>
                  {group.isCreator ? (
                    <TouchableOpacity
                      style={[styles.evictBtn, evictArmed === m.veilId ? styles.evictBtnArmed : null]}
                      disabled={group.busy || m.role === 'creator'}
                      onPress={async () => {
                        if (evictArmed !== m.veilId) { setEvictArmed(m.veilId); setTimeout(() => setEvictArmed((cur) => (cur === m.veilId ? null : cur)), 6000); return; }
                        setEvictArmed(null); setGroupErr(null);
                        try { await group.onEvict({ veilId: m.veilId, ikPub: m.ikPub }); } catch (e) { setGroupErr('That did not work — please try again.'); console.log('[veil-error] group-evict:', String((e as Error).message ?? e)); }
                      }}
                    >
                      <Text style={styles.evictBtnTxt}>{group.forum ? (evictArmed === m.veilId ? 'Block & remove posts?' : 'Block & remove posts') : (evictArmed === m.veilId ? 'Remove?' : 'Remove')}</Text>
                    </TouchableOpacity>
                  ) : null}
                </View>
              ))}
            </ScrollView>
            {group.isCreator && !group.forum ? (
              <TouchableOpacity
                style={styles.rotateBtn}
                disabled={group.busy}
                onPress={async () => {
                  setGroupErr(null);
                  try { await group.onRotate(); } catch (e) { setGroupErr('That did not work — please try again.'); console.log('[veil-error] group-evict:', String((e as Error).message ?? e)); }
                }}
              >
                <Text style={styles.rotateBtnTxt}>{group.busy ? 'Working…' : 'Rotate keys now'}</Text>
              </TouchableOpacity>
            ) : null}
            {groupErr ? <Text style={styles.groupErr}>{groupErr}</Text> : null}
          </View>
        </View>
      ) : null}

      {error ? <Text style={styles.error}>{error}</Text> : null}

      {historyNotice ? <Text style={styles.notice}>{historyNotice}</Text> : null}

      {showVerifyCard && !myVerified ? (
        <View style={styles.vCard}>
          <View style={styles.vCardBody}>
            <Text style={styles.vCardTitle}>Verify this session</Text>
            <Text style={styles.vCardTxt}>Sending unlocks once you both compare the verification code out-of-band (call them or meet) and confirm it. This is a security check against interception on every chat path.</Text>
            <View style={styles.vCardRow}>
              <TouchableOpacity style={styles.vCardBtn} onPress={() => { setCompareArmed(false); setVerifyFail(false); setVerifyPanel('ceremony'); }} accessibilityLabel="Verify fingerprints now">
                <Text style={styles.vCardBtnTxt}>Verify fingerprints</Text>
              </TouchableOpacity>
              <TouchableOpacity style={styles.vCardSkip} onPress={onVerifyCardDismiss} accessibilityLabel="Dismiss verification reminder">
                <Text style={styles.vCardSkipTxt}>Not now</Text>
              </TouchableOpacity>
            </View>
          </View>
        </View>
      ) : null}

      {/* messages */}
      <FlatList
        ref={listRef}
        style={styles.list}
        keyboardShouldPersistTaps="handled"
        // b199: the keyboard goes down when the person scrolls the chat (or
        // taps an empty part of it — "handled" above), not when they send
        keyboardDismissMode="on-drag"
        onScrollBeginDrag={() => setReactOpenId(null)}
        data={messages}
        keyExtractor={(m) => m.id}
        renderItem={({ item }) => (
          <MessageRow
            item={item}
            group={group}
            burnAfterOpen={burnAfterOpen}
            burnSeconds={burnSeconds}
            threadKey={threadKey}
            playing={audioPlayingId === item.id}
            avErrMsg={audioErr?.id === item.id ? audioErr.msg : null}
            saveState={mediaSaving[item.id]}
            onMediaRetry={onMediaRetry}
            onMediaSave={onMediaSave}
            onToggleAudio={toggleAudio}
            onOpenLightbox={(s, n) => setLightbox({ src: s, name: n })}
            onOpenVideo={(s, n) => { stopAudio(); setVideoFS({ src: s, name: n }); }}
            inviteStatus={inviteState?.[item.id] ?? inviteBusy[item.id]}
            onJoinInvite={joinInvite}
            onDeclineInvite={declineInvite}
            onReactOpen={onReactMessage ? openReact : undefined}
            reactOpen={reactOpenId === item.id}
            onReact={onReactMessage ? pickReact : undefined}
            onMenu={hasMessageMenu ? onMessageMenu : undefined}
          />
        )}
        ListEmptyComponent={
          <View style={styles.empty}>
            <Text style={styles.emptyTxt}>{status === 'pending' ? 'Your contact hasn\u2019t accepted yet — messages will flow once they do.' : 'No messages yet. Say hi.'}</Text>
          </View>
        }
      />

      {/* composer */}
      <View style={[styles.composer, kbH > 0 && { paddingBottom: kbH + 12 }]}>
        {verifyGate && status === 'active' && !busy ? (
          /* b163 (web P1.2 parity): blocked-send state explains itself and the
           * ceremony stays reachable from the composer — no dead-end lock. */
          <View style={styles.verifyNotice}>
            <Text style={styles.verifyNoticeTxt}>🔒 Sending unlocks once you both compare the verification code and confirm it.</Text>
            <TouchableOpacity
              style={styles.verifyNowBtn}
              onPress={() => { setCompareArmed(false); setVerifyFail(false); setVerifyPanel(myVerified ? 'view' : 'ceremony'); }}
              accessibilityLabel="Verify now"
            >
              <Text style={styles.verifyNowBtnTxt}>Verify now</Text>
            </TouchableOpacity>
          </View>
        ) : null}
        {loungeNote ? (
          <Text style={styles.loungeNoteTxt}>{loungeNote}</Text>
        ) : null}
        {/* b199 UI redesign (owner, Oct 16): attach · message · mic/send. The
            mic becomes a send arrow as soon as there is text; while recording,
            the bar becomes cancel · timer · send. */}
        {voiceRec.active ? (
          <>
            <TouchableOpacity style={[styles.roundBtn, styles.roundBtnGhost]} onPress={onVoiceCancel} accessibilityLabel="Cancel voice note">
              <Ionicons name="close" size={20} color="#8E9696" />
            </TouchableOpacity>
            <View style={styles.recBar}>
              <View style={styles.recDot} />
              <Text style={styles.recTxt}>Recording {fmtSecs(voiceRec.seconds)}</Text>
            </View>
            <TouchableOpacity style={[styles.roundBtn, styles.roundBtnSend]} onPress={onVoiceSend} accessibilityLabel="Send voice note">
              <Ionicons name="arrow-up" size={20} color="#0B0B0F" />
            </TouchableOpacity>
          </>
        ) : (
          <>
            <TouchableOpacity
              style={[styles.roundBtn, styles.roundBtnGhost, (composerLocked || textOnly) && styles.roundBtnOff]}
              disabled={composerLocked || !!textOnly}
              onPress={onAttach}
              accessibilityLabel="Attach a photo or video"
            >
              <Ionicons name="add" size={24} color="#FFFFFF" />
            </TouchableOpacity>
            <TextInput
              style={[styles.input, composerLocked && styles.inputLocked]}
              placeholder={readOnly ? 'Read-only founder broadcast' : status === 'pending' ? 'Locked until your contact accepts' : verifyGate ? 'Locked until you both verify' : 'Message'}
              placeholderTextColor="#5E6464"
              value={draft}
              onChangeText={onDraftChange}
              // b199 (owner request): the keyboard stays up after Send. The box
              // used to go non-editable while a send was in flight (busy), and
              // iOS drops the keyboard when the focused input is disabled.
              // Busy still blocks a second send via the button.
              editable={!readOnly && status === 'active' && !verifyGate}
              multiline
            />
            {draft.trim() || textOnly ? (
              <TouchableOpacity
                style={[styles.roundBtn, (!composerLocked && draft.trim()) ? styles.roundBtnSend : [styles.roundBtnGhost, styles.roundBtnOff]]}
                disabled={composerLocked || !draft.trim()}
                onPress={onSend}
                accessibilityLabel="Send"
              >
                <Ionicons name="arrow-up" size={20} color={(!composerLocked && draft.trim()) ? '#0B0B0F' : '#8E9696'} />
              </TouchableOpacity>
            ) : (
              /* b62 voice notes: mic in the composer; recording UI replaces the bar */
              <TouchableOpacity
                style={[styles.roundBtn, styles.roundBtnGhost, composerLocked && styles.roundBtnOff]}
                disabled={composerLocked}
                onPress={onVoiceRecord}
                accessibilityLabel="Record a voice note"
              >
                <Ionicons name="mic-outline" size={21} color="#FFFFFF" />
              </TouchableOpacity>
            )}
          </>
        )}
      </View>
    </View>

      {/* attach confirm — web parity: preview + Cancel/Send before anything is encrypted.
          Rendered as a plain in-screen overlay, NOT React Native's <Modal>. The photo
          picker (ImagePicker.launchImageLibraryAsync) itself presents a native iOS modal
          (PHPickerViewController); opening a SECOND native modal (RN's <Modal>) the instant
          it resolves collides with iOS's dismiss animation and freezes the whole screen
          (build 25 bug — looked like a total hang, no scroll/back). A plain absolutely
          positioned View has no native presentation of its own, so there's nothing to
          collide with. Kept OUTSIDE the KeyboardAvoidingView (build 26 bug: 'padding'
          behavior pads the AvoidingView's own box when the keyboard is up, which pushes
          this absolutely-positioned overlay's bottom edge off-screen behind the keyboard,
          clipping Cancel/Send — being outside means it's always anchored to the real
          screen bounds regardless of keyboard state; handleAttach also dismisses the
          keyboard proactively as a belt-and-suspenders fix). */}
      {pendingPick ? (
        <View style={styles.pickOverlay} pointerEvents="auto">
          <View style={styles.pickSheet}>
            {pendingPick.voiceSeconds ? (
              <>
                <Text style={styles.pickTitle}>Send this voice note?</Text>
                <View style={styles.pickAudioPreview}>
                  <Text style={styles.pickAudioIcon}>🎤</Text>
                  <Text style={styles.pickAudioMeta}>{fmtSecs(pendingPick.voiceSeconds)} · encrypted end-to-end before upload</Text>
                </View>
              </>
            ) : pendingPick.mime.startsWith('video/') ? (
              <>
                <Text style={styles.pickTitle}>Send this video?</Text>
                <View style={styles.pickAudioPreview}>
                  <Text style={styles.pickAudioIcon}>▶</Text>
                  <Text style={styles.pickAudioMeta}>{pendingPick.name || 'video'}</Text>
                </View>
                <Text style={styles.pickMeta}>{(pendingPick.size / 1048576).toFixed(1)} MB · encrypted on this phone before it is uploaded</Text>
                {pendingPick.size > MEDIA_SOFT_WARN_BYTES ? <Text style={styles.pickWarn}>Large file — encrypting and sending may take a few minutes. Keep Vardum open until it sends.</Text> : null}
              </>
            ) : (
              <>
                <Text style={styles.pickTitle}>Send this image?</Text>
                <Image source={{ uri: pendingPick.uri }} style={styles.pickPreview} resizeMode="contain" />
                <Text style={styles.pickMeta}>{pendingPick.name || 'media'}</Text>
                <Text style={styles.pickMeta}>{(pendingPick.size / 1048576).toFixed(1)} MB · encrypted on this phone before it is uploaded</Text>
                {pendingPick.size > MEDIA_SOFT_WARN_BYTES ? <Text style={styles.pickWarn}>Large file — encrypting and sending may take a few minutes. Keep Vardum open until it sends.</Text> : null}
              </>
            )}
            <TouchableOpacity style={styles.dlToggle} onPress={() => onAllowDlChange(!allowDl)} activeOpacity={0.7}>
              <View style={[styles.dlBox, allowDl && styles.dlBoxOn]}>
                {allowDl ? <Text style={styles.dlBoxTxt}>✓</Text> : null}
              </View>
              <Text style={styles.dlToggleTxt}>Allow recipient to save this {pendingPick.voiceSeconds ? 'voice note' : pendingPick.mime.startsWith('video/') ? 'video' : 'image'}</Text>
            </TouchableOpacity>
            <View style={styles.pickBtns}>
              <TouchableOpacity style={styles.pickCancel} onPress={onCancelPick}>
                <Text style={styles.pickCancelTxt}>Cancel</Text>
              </TouchableOpacity>
              <TouchableOpacity style={styles.pickSend} onPress={onSendMedia} disabled={busy}>
                <Text style={styles.pickSendTxt}>{busy ? 'Sending…' : 'Send'}</Text>
              </TouchableOpacity>
            </View>
          </View>
        </View>
      ) : null}

      {/* lightbox — full-screen media view */}
      {/* (b66) VEIL-styled ✕ sheet — End is a real red destructive button */}
      <Modal visible={sheet} transparent animationType="slide" onRequestClose={() => setSheet(false)}>
        <TouchableOpacity style={styles.sheetBackdrop} activeOpacity={1} onPress={() => setSheet(false)}>
          <TouchableOpacity style={styles.sheetPanel} activeOpacity={1} onPress={() => undefined}>
            {canRename && onRenameThread ? (
              <TouchableOpacity style={styles.sheetRow} onPress={() => { setSheet(false); setRenameInput(threadNickname ?? ''); setRenameOpen(true); }}>
                <Text style={styles.sheetRowTxt}>Rename this thread</Text>
                <Text style={styles.sheetRowSub}>Device-local only — never transmitted, never synced</Text>
              </TouchableOpacity>
            ) : null}
            {canNewThread ? (
              <TouchableOpacity style={styles.sheetRow} onPress={() => { setSheet(false); onNewThread(); }}>
                <Text style={styles.sheetRowTxt}>New chat thread with the same person</Text>
                <Text style={styles.sheetRowSub}>All-new keys — no new invitation needed</Text>
              </TouchableOpacity>
            ) : null}
            {onBlockContact ? (
              <TouchableOpacity style={styles.sheetRowDanger} onPress={() => { setSheet(false); void confirmBlockContact(); }}>
                <Text style={styles.sheetRowDangerTxt}>Block this contact</Text>
                <Text style={styles.sheetRowDangerSub}>Ends this chat and hides them on this phone</Text>
              </TouchableOpacity>
            ) : null}
            <TouchableOpacity style={styles.sheetRowDanger} onPress={() => { setSheet(false); onEndSession(); }}>
              {group ? (
                <>
                  <Text style={styles.sheetRowDangerTxt}>Delete this group thread</Text>
                  <Text style={styles.sheetRowDangerSub}>Removes the thread from this device</Text>
                </>
              ) : (
                <>
                  <Text style={styles.sheetRowDangerTxt}>End this session</Text>
                  <Text style={styles.sheetRowDangerSub}>Ends it on both sides — permanently</Text>
                </>
              )}
            </TouchableOpacity>
            <TouchableOpacity style={styles.sheetRowCancel} onPress={() => setSheet(false)}>
              <Text style={styles.sheetCancelTxt}>Cancel</Text>
            </TouchableOpacity>
          </TouchableOpacity>
        </TouchableOpacity>
      </Modal>
      {/* b126 verification panel — fingerprint viewable pre AND post verification;
          "Mark verified" only unlocks after an explicit out-of-band comparison
          confirmation. Vardum palette (#15151B card, white primary). */}
      <Modal visible={!!verifyPanel} transparent animationType="fade" onRequestClose={() => setVerifyPanel(null)}>
        <TouchableOpacity style={styles.rnBackdrop} activeOpacity={1} onPress={() => setVerifyPanel(null)}>
          <TouchableOpacity style={styles.rnCard} activeOpacity={1} onPress={() => undefined}>
            {verifyPanel === 'ceremony' ? (
              <>
                <Text style={styles.rnTitle}>Verify this session</Text>
                <Text style={styles.fpBox} selectable>
                  {sessionFingerprint ?? 'No safety code yet. It appears here once the other phone has opened Vardum and joined this chat. Keep Vardum open on both phones and wait a few seconds; starting another new chat resets this.'}
                </Text>
                <Text style={styles.rnBody}>Compare it with your peer out-of-band — read it to them on a call, or side by side in person. Only continue if every group of characters matches exactly.</Text>
                <TouchableOpacity
                  style={[styles.fpStepBtn, compareArmed && styles.fpStepBtnOn]}
                  onPress={() => setCompareArmed(true)}
                  disabled={compareArmed || !sessionFingerprint} // Batch G (NF-1)
                >
                  <Text style={[styles.fpStepBtnTxt, compareArmed && styles.fpStepBtnTxtOn]}>
                    {compareArmed ? '✓ Compared — they match' : 'I compared them — they match'}
                  </Text>
                </TouchableOpacity>
                {verifyPanel === 'ceremony' && verifyFail ? (
                  <Text style={styles.fpFailTxt}>Verification failed to save — tap to retry.</Text>
                ) : null}
                <View style={styles.rnActions}>
                  <TouchableOpacity style={styles.rnBtnGhost} onPress={() => setVerifyPanel(null)}>
                    <Text style={styles.rnBtnGhostTxt}>Cancel</Text>
                  </TouchableOpacity>
                  <TouchableOpacity
                    style={[styles.rnBtnTeal, (!compareArmed || !sessionFingerprint) && styles.fpBtnDisabled]}
                    disabled={!compareArmed || !sessionFingerprint}
                    onPress={() => {
                      setVerifyFail(false);
                      void onVerifySession().then((ok) => { if (!ok) setVerifyFail(true); else setVerifyPanel(null); });
                    }}
                  >
                    <Text style={styles.rnBtnTealTxt}>{verifyFail ? 'Retry' : 'Mark verified'}</Text>
                  </TouchableOpacity>
                </View>
              </>
            ) : verifyPanel === 'view' ? (
              <>
                <Text style={styles.rnTitle}>Session fingerprint</Text>
                <Text style={styles.fpBox} selectable>
                  {sessionFingerprint ?? '(fingerprint unavailable on this device)'}
                </Text>
                <Text style={styles.fpStatus}>
                  You verified this session ✓{'\n'}{peerVerified ? 'Peer verified this session ✓' : 'Peer has not verified yet'}
                </Text>
                {peerVeilId ? (
                  peerPinned ? (
                    <Text style={styles.fpPinned}>✓ Pinned in contacts</Text>
                  ) : (
                    <TouchableOpacity style={styles.rnBtnTeal} onPress={() => onPinContact?.()}>
                      <Text style={styles.rnBtnTealTxt}>Pin as contact</Text>
                    </TouchableOpacity>
                  )
                ) : null}
                <View style={styles.rnActions}>
                  <TouchableOpacity style={styles.rnBtnGhost} onPress={() => setVerifyPanel(null)}>
                    <Text style={styles.rnBtnGhostTxt}>Close</Text>
                  </TouchableOpacity>
                </View>
              </>
            ) : null}
          </TouchableOpacity>
        </TouchableOpacity>
      </Modal>
      {/* b123: rename modal — same VEIL modal pattern as the Contacts nickname */}
      <Modal visible={renameOpen} transparent animationType="fade" onRequestClose={() => setRenameOpen(false)}>
        <TouchableOpacity style={styles.rnBackdrop} activeOpacity={1} onPress={() => setRenameOpen(false)}>
          <TouchableOpacity style={styles.rnCard} activeOpacity={1} onPress={() => undefined}>
            <Text style={styles.rnTitle}>Rename this thread</Text>
            <Text style={styles.rnBody}>Stored on this device only. Never transmitted, never synced, never on the server.</Text>
            <TextInput
              style={styles.rnInput}
              placeholder="e.g. Founder Tester Lounge"
              placeholderTextColor="#5E6464"
              value={renameInput}
              onChangeText={setRenameInput}
              maxLength={40}
            />
            <View style={styles.rnActions}>
              <TouchableOpacity style={styles.rnBtnGhost} onPress={() => setRenameOpen(false)}>
                <Text style={styles.rnBtnGhostTxt}>Cancel</Text>
              </TouchableOpacity>
              <TouchableOpacity
                style={styles.rnBtnTeal}
                onPress={() => { setRenameOpen(false); onRenameThread?.(renameInput.trim()); }}
              >
                <Text style={styles.rnBtnTealTxt}>Save</Text>
              </TouchableOpacity>
            </View>
          </TouchableOpacity>
        </TouchableOpacity>
      </Modal>
      <Modal visible={!!videoFS} animationType="fade" onRequestClose={() => setVideoFS(null)} supportedOrientations={['portrait', 'landscape', 'landscape-left', 'landscape-right']}>
        {videoFS ? (
          <View style={styles.videoFSBg}>
            <Video
              source={{ uri: videoFS.src }}
              style={styles.videoFSPlayer}
              useNativeControls
              shouldPlay
              resizeMode={ResizeMode.CONTAIN}
              onError={() => setVideoFS(null)}
            />
            <TouchableOpacity style={styles.videoFSClose} onPress={() => setVideoFS(null)}>
              <Text style={styles.videoFSCloseTxt}>✕</Text>
            </TouchableOpacity>
            <Text style={styles.videoFSHint}>{videoFS.name} — decrypted on this phone</Text>
          </View>
        ) : null}
      </Modal>
      <Modal visible={!!lightbox} transparent animationType="fade" onRequestClose={() => setLightbox(null)}>
        <TouchableOpacity style={styles.lightbox} activeOpacity={1} onPress={() => setLightbox(null)}>
          {lightbox ? <Image source={{ uri: lightbox.src }} style={styles.lightboxImg} resizeMode="contain" /> : null}
          <Text style={styles.lightboxHint}>{lightbox?.name ?? ''} — tap anywhere to close</Text>
        </TouchableOpacity>
      </Modal>
      {chooserNode}
      {promptNode}
    </View>
  );
}

const styles = StyleSheet.create({
  fpFailTxt: { color: '#e8896b', fontSize: 13, lineHeight: 18, marginBottom: 10 },
  fill: { flex: 1, backgroundColor: '#0B0B0F' },
  header: { flexDirection: 'row', alignItems: 'center', paddingHorizontal: 8, paddingBottom: 10, paddingTop: 48, borderBottomWidth: 1, borderBottomColor: '#24242D', backgroundColor: '#0B0B0F' },
  backBtn: { paddingVertical: 4, paddingRight: 2 },
  hAvatar: { width: 36, height: 36, borderRadius: 18, backgroundColor: '#24242D', alignItems: 'center', justifyContent: 'center', marginLeft: 2 },
  hAvatarGroup: { borderRadius: 11, backgroundColor: '#24242D' },
  hAvatarTxt: { color: '#FFFFFF', fontSize: 13, fontWeight: '700' },
  callBtn: { paddingVertical: 6, paddingHorizontal: 8 },
  callGlyph: { color: '#FFFFFF', fontSize: 20, lineHeight: 24 },
  // b62 groups
  senderLbl: { color: '#FFFFFF', fontSize: 11, marginBottom: 2 },
  groupOverlay: { ...StyleSheet.absoluteFillObject, backgroundColor: 'rgba(11,11,15,0.86)', justifyContent: 'center', padding: 18, zIndex: 40 },
  groupPanel: { backgroundColor: '#0B0B0F', borderColor: '#24242D', borderWidth: 1, borderRadius: 14, padding: 16, maxHeight: '72%' },
  groupPanelHead: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 },
  groupPanelTitle: { color: '#FFFFFF', fontSize: 16, fontWeight: '700' },
  groupCloseTxt: { color: '#8E9696', fontSize: 18, paddingHorizontal: 6 },
  groupFp: { color: '#8a6d3b', fontSize: 11, marginBottom: 10 },
  groupMemberList: { flexGrow: 0 },
  groupEmpty: { color: '#8E9696', fontSize: 13, paddingVertical: 8 },
  groupMemberRow: { flexDirection: 'row', alignItems: 'center', paddingVertical: 8, borderBottomWidth: StyleSheet.hairlineWidth, borderBottomColor: '#24242D' },
  groupMemberName: { color: '#FFFFFF', fontSize: 13 },
  groupMemberMeta: { color: '#8E9696', fontSize: 11, marginTop: 1 },
  evictBtn: { borderColor: '#7c3a3a', borderWidth: 1, borderRadius: 8, paddingHorizontal: 10, paddingVertical: 5 },
  evictBtnArmed: { backgroundColor: '#7c3a3a' },
  evictBtnTxt: { color: '#f0b8b8', fontSize: 11 },
  rotateBtn: { backgroundColor: '#24242D', borderColor: '#3A3A44', borderWidth: 1, borderRadius: 10, paddingVertical: 10, alignItems: 'center', marginTop: 12 },
  rotateBtnTxt: { color: '#FFFFFF', fontSize: 13, fontWeight: '600' },
  groupErr: { color: '#f0b8b8', fontSize: 12, marginTop: 8 },
  backTxt: { color: '#FFFFFF', fontSize: 14 },
  headerMid: { flex: 1, minWidth: 0, marginHorizontal: 10 },
  title: { color: '#FFFFFF', fontSize: 16, fontWeight: '700' },
  subtitle: { color: '#8E9696', fontSize: 12, marginTop: 2 },
  vBadge: { alignSelf: 'flex-start', marginTop: 3, borderWidth: 1, borderColor: 'transparent', borderRadius: 999, paddingHorizontal: 7, paddingVertical: 1 },
  vBadgeTxtGroup: { color: '#FFFFFF', fontSize: 12, fontWeight: '600' },
  vBadgeOk: { borderColor: '#3A3A44', backgroundColor: 'rgba(255,255,255,0.10)' },
  vBadgeHalf: { borderColor: '#5c4526', backgroundColor: 'rgba(214,154,92,0.10)' },
  vBadgeNone: { borderColor: '#3A3A44', backgroundColor: 'transparent' },
  vBadgeTxt: { fontSize: 11, fontWeight: '600' },
  vBadgeTxtOk: { color: '#20D9C2' }, // b199 (owner, Oct 17): the logo's teal "V"
  vBadgeTxtHalf: { color: '#d69a5c' },
  vBadgeTxtNone: { color: '#8E9696' },
  newThreadBtn: { borderWidth: 1, borderColor: '#3A3A44', borderRadius: 8, paddingHorizontal: 10, height: 34, minWidth: 56, alignItems: 'center', justifyContent: 'center' },
  newThreadTxt: { color: '#FFFFFF', fontSize: 13, fontWeight: '600' },
  menuBtn: { paddingHorizontal: 8, paddingVertical: 6 },
  menuTxt: { color: '#8E9696', fontSize: 22, fontWeight: '700' },
  // (b66) ✕ sheet
  sheetBackdrop: { flex: 1, backgroundColor: 'rgba(11,11,15,0.8)', justifyContent: 'flex-end' },
  sheetPanel: { backgroundColor: '#15151B', borderTopLeftRadius: 18, borderTopRightRadius: 18, borderWidth: 1, borderColor: '#24242D', paddingHorizontal: 14, paddingBottom: 34, paddingTop: 6 },
  sheetRow: { paddingVertical: 16, borderBottomWidth: 1, borderBottomColor: '#24242D' },
  sheetRowTxt: { color: '#FFFFFF', fontSize: 15, fontWeight: '700', textAlign: 'center' },
  sheetRowSub: { color: '#8E9696', fontSize: 12, marginTop: 3, textAlign: 'center' },
  sheetRowDanger: { paddingVertical: 16, borderBottomWidth: 1, borderBottomColor: '#24242D' },
  sheetRowDangerTxt: { color: '#ff5a4e', fontSize: 15, fontWeight: '800', textAlign: 'center' },
  sheetRowDangerSub: { color: '#8a5450', fontSize: 12, marginTop: 3, textAlign: 'center' },
  sheetRowCancel: { paddingVertical: 16 },
  // b123: read-receipt tick appended to my read bubbles' timestamps
  // Vardum: inherits the timestamp colour so it reads on the white sent bubble and on dark media bubbles
  readTick: { fontWeight: '700' },
  // b123: rename-thread modal (Vardum palette: #15151B card, white primary)
  rnBackdrop: { flex: 1, backgroundColor: 'rgba(11,11,15,0.8)', justifyContent: 'center', alignItems: 'center', padding: 28 },
  rnCard: { width: '100%', backgroundColor: '#15151B', borderRadius: 16, borderWidth: 1, borderColor: '#24242D', padding: 18 },
  rnTitle: { color: '#FFFFFF', fontSize: 17, fontWeight: '800', textAlign: 'center' },
  rnBody: { color: '#8E9696', fontSize: 12, textAlign: 'center', marginTop: 6, marginBottom: 14 },
  rnInput: { backgroundColor: '#15151B', borderWidth: 1, borderColor: '#3A3A44', borderRadius: 10, color: '#FFFFFF', paddingHorizontal: 12, paddingVertical: 10, fontSize: 15 },
  rnActions: { flexDirection: 'row', marginTop: 14 },
  rnBtnGhost: { flex: 1, alignItems: 'center', paddingVertical: 12, borderRadius: 10, borderWidth: 1, borderColor: '#24242D', marginRight: 8 },
  rnBtnGhostTxt: { color: '#8E9696', fontSize: 14, fontWeight: '700' },
  rnBtnTeal: { flex: 1, alignItems: 'center', paddingVertical: 12, borderRadius: 10, backgroundColor: '#FFFFFF' },
  rnBtnTealTxt: { color: '#0B0B0F', fontSize: 14, fontWeight: '800' },
  sheetCancelTxt: { color: '#8E9696', fontSize: 15, fontWeight: '700', textAlign: 'center' },
  endBtn: { padding: 6 },
  endTxt: { color: '#8a4b55', fontSize: 13 },
  error: { color: '#d98b8b', fontSize: 12, paddingHorizontal: 16, paddingTop: 8 },
  notice: { color: '#e0a458', fontSize: 12, paddingHorizontal: 16, paddingTop: 4 },
  list: { flex: 1, paddingHorizontal: 12 },
  bubbleRow: { flexDirection: 'row', marginVertical: 3 },
  // b199 reactions: bar above, bubble, badge below, all on the bubble's side
  bubbleCol: { maxWidth: '78%' },
  bubbleColMine: { alignItems: 'flex-end' },
  bubbleColPeer: { alignItems: 'flex-start' },
  bubbleInCol: { maxWidth: '100%' },
  reactBar: { flexDirection: 'row', backgroundColor: '#15151B', borderWidth: 1, borderColor: '#24242D', borderRadius: 22, paddingHorizontal: 4, paddingVertical: 3, marginBottom: 4 },
  reactBarMine: { alignSelf: 'flex-end' },
  reactBarPeer: { alignSelf: 'flex-start' },
  reactBtn: { width: 38, height: 38, borderRadius: 19, alignItems: 'center', justifyContent: 'center' },
  reactBtnOn: { backgroundColor: '#3A3A44' },
  reactEmoji: { fontSize: 22 },
  reactBadge: { marginTop: -6, backgroundColor: '#15151B', borderWidth: 1, borderColor: '#24242D', borderRadius: 12, paddingHorizontal: 6, paddingVertical: 1 },
  reactBadgeMine: { marginRight: 6 },
  reactBadgePeer: { marginLeft: 6 },
  reactBadgeTxt: { fontSize: 14 },
  mineRow: { justifyContent: 'flex-end' },
  peerRow: { justifyContent: 'flex-start' },
  // b199 group invitation card
  inviteCard: { maxWidth: '86%', borderWidth: 1, borderColor: '#3A3A44', backgroundColor: '#15151B', borderRadius: 14, padding: 14 },
  inviteKicker: { color: '#FFFFFF', fontSize: 10, fontWeight: '800', letterSpacing: 0.8, textTransform: 'uppercase' },
  inviteName: { color: '#FFFFFF', fontSize: 17, fontWeight: '700', marginTop: 4 },
  inviteSub: { color: '#8E9696', fontSize: 12, lineHeight: 17, marginTop: 6 },
  inviteDone: { color: '#FFFFFF', fontSize: 13, fontWeight: '600', marginTop: 8 },
  inviteErr: { color: '#e8836f', fontSize: 12, marginTop: 6 },
  inviteActions: { flexDirection: 'row', gap: 8, marginTop: 12 },
  inviteJoin: { backgroundColor: '#FFFFFF', borderRadius: 10, paddingVertical: 9, paddingHorizontal: 22 },
  inviteJoinTxt: { color: '#0B0B0F', fontWeight: '800', fontSize: 14 },
  inviteDecline: { borderWidth: 1, borderColor: '#24242D', borderRadius: 10, paddingVertical: 9, paddingHorizontal: 16 },
  inviteDeclineTxt: { color: '#8E9696', fontWeight: '600', fontSize: 14 },
  bubble: { maxWidth: '78%', borderRadius: 16, paddingHorizontal: 12, paddingVertical: 8 },
  // Vardum: media bubbles stay dark (white sent bubble would hide the white audio/play controls)
  mediaBubble: { padding: 6, backgroundColor: '#24242D' },
  mineBubble: { backgroundColor: '#FFFFFF' },
  peerBubble: { backgroundColor: '#15151B' },
  mineText: { color: '#0B0B0F', fontSize: 14 },
  peerText: { color: '#FFFFFF', fontSize: 14 },
  mineTs: { color: '#5E6464', fontSize: 9, marginTop: 3, textAlign: 'right' },
  mineTsOnDark: { color: '#8E9696' },
  peerTs: { color: '#5E6464', fontSize: 9, marginTop: 3 },
  mediaImg: { width: 220, height: 220, borderRadius: 12, backgroundColor: '#0B0B0F' },
  mediaStub: { width: 220, height: 120, borderRadius: 12, backgroundColor: '#0B0B0F', alignItems: 'center', justifyContent: 'center' },
  mediaStubTxt: { color: '#5E6464', fontSize: 12, marginTop: 8 },
  mediaErrTxt: { color: '#d98b8b', fontSize: 12 },
  mediaCaption: { color: '#8E9696', fontSize: 10, marginTop: 4, maxWidth: 220 },
  micBtnRec: { backgroundColor: 'rgba(214,160,84,0.15)', borderWidth: 1, borderColor: '#8a6d3b', borderRadius: 8, paddingHorizontal: 10, paddingVertical: 9, marginLeft: 4 },
  micBtnTxt: { color: '#d6a054', fontSize: 12, fontWeight: '600' },
  audioRow: { flexDirection: 'row', alignItems: 'center', paddingVertical: 2 },
  audioBtn: { width: 34, height: 34, borderRadius: 17, backgroundColor: 'rgba(255,255,255,0.12)', borderWidth: 1, borderColor: '#3A3A44', alignItems: 'center', justifyContent: 'center' },
  audioBtnTxt: { color: '#FFFFFF', fontSize: 14 },
  audioLbl: { color: '#C9CFCE', fontSize: 12, marginLeft: 8 },
  videoBox: { width: 220, height: 120, borderRadius: 8, backgroundColor: '#15151B', borderWidth: 1, borderColor: '#24242D', alignItems: 'center', justifyContent: 'center' },
  videoIcon: { color: '#FFFFFF', fontSize: 22 },
  videoLbl: { color: '#8E9696', fontSize: 10, marginTop: 4 },
  pickAudioPreview: { alignItems: 'center', paddingVertical: 14 },
  pickAudioIcon: { fontSize: 34 },
  pickAudioMeta: { color: '#C9CFCE', fontSize: 12, marginTop: 6 },
  empty: { padding: 40, alignItems: 'center' },
  captureNotice: {
    color: '#d6a054', textAlign: 'center', fontSize: 11, lineHeight: 15,
    paddingHorizontal: 24, paddingVertical: 6, marginVertical: 4,
  },
  emptyTxt: { color: '#4A4A54', fontSize: 13, textAlign: 'center', lineHeight: 20 },
  vCard: { marginHorizontal: 12, marginTop: 8, borderRadius: 12, borderWidth: 1, borderColor: '#3A3A44', backgroundColor: '#15151B' },
  vCardBody: { padding: 14 },
  vCardTitle: { color: '#FFFFFF', fontSize: 13, fontWeight: '700', marginBottom: 4 },
  vCardTxt: { color: '#8E9696', fontSize: 12, lineHeight: 17 },
  vCardRow: { flexDirection: 'row', alignItems: 'center', marginTop: 10 },
  vCardBtn: { borderRadius: 8, backgroundColor: '#FFFFFF', paddingHorizontal: 12, paddingVertical: 8 },
  vCardBtnTxt: { color: '#0B0B0F', fontSize: 12, fontWeight: '700' },
  vCardSkip: { marginLeft: 10, padding: 6 },
  vCardSkipTxt: { color: '#5E6464', fontSize: 12 },
  // b126 verification panel
  fpBox: { backgroundColor: '#15151B', borderWidth: 1, borderColor: '#3A3A44', borderRadius: 10, paddingHorizontal: 12, paddingVertical: 12, color: '#FFFFFF', fontSize: 13, lineHeight: 19, marginTop: 12 },
  fpStepBtn: { alignItems: 'center', paddingVertical: 11, borderRadius: 10, borderWidth: 1, borderColor: '#24242D', marginTop: 12 },
  fpStepBtnOn: { borderColor: '#FFFFFF', backgroundColor: 'rgba(255,255,255,0.08)' },
  fpStepBtnTxt: { color: '#8E9696', fontSize: 13, fontWeight: '700' },
  fpStepBtnTxtOn: { color: '#FFFFFF' },
  fpBtnDisabled: { opacity: 0.35 },
  fpStatus: { color: '#8E9696', fontSize: 12, textAlign: 'center', marginTop: 12, lineHeight: 17 },
  fpPinned: { color: '#FFFFFF', fontSize: 13, fontWeight: '700', textAlign: 'center', marginTop: 12 },
  composer: { flexDirection: 'row', flexWrap: 'wrap', alignItems: 'flex-end', paddingHorizontal: 10, paddingTop: 10, paddingBottom: 12, borderTopWidth: 1, borderTopColor: '#24242D', backgroundColor: '#0B0B0F', gap: 8 },
  input: { flex: 1, minWidth: 120, minHeight: 40, maxHeight: 120, borderRadius: 20, borderWidth: 1, borderColor: '#24242D', color: '#FFFFFF', paddingHorizontal: 15, paddingTop: 10, paddingBottom: 10, fontSize: 15, backgroundColor: '#15151B' },
  roundBtn: { width: 40, height: 40, borderRadius: 20, alignItems: 'center', justifyContent: 'center' },
  roundBtnGhost: { backgroundColor: '#15151B', borderWidth: 1, borderColor: '#24242D' },
  roundBtnSend: { backgroundColor: '#FFFFFF' },
  roundBtnOff: { opacity: 0.4 },
  recBar: { flex: 1, minHeight: 40, flexDirection: 'row', alignItems: 'center', borderRadius: 20, borderWidth: 1, borderColor: '#5c4526', backgroundColor: 'rgba(214,154,92,0.10)', paddingHorizontal: 15 },
  recDot: { width: 9, height: 9, borderRadius: 5, backgroundColor: '#e8836f', marginRight: 8 },
  recTxt: { color: '#d69a5c', fontSize: 14, fontWeight: '600' },
  inputLocked: { opacity: 0.5 },
  // b163: composer-level ceremony-gate notice (web P1.2 parity)
  verifyNotice: { flexBasis: '100%', width: '100%', flexDirection: 'row', alignItems: 'center', gap: 8, marginBottom: 2, paddingLeft: 6, paddingRight: 2 },
  verifyNoticeTxt: { flex: 1, color: '#d69a5c', fontSize: 12, lineHeight: 16 },
  verifyNowBtn: { borderColor: '#FFFFFF', borderWidth: 1, borderRadius: 8, paddingHorizontal: 10, paddingVertical: 6 },
  verifyNowBtnTxt: { color: '#FFFFFF', fontSize: 12, fontWeight: '700' },
  attachBtn: { marginLeft: 8, height: 42, width: 42, borderRadius: 21, alignItems: 'center', justifyContent: 'center' },
  attachBtnOn: { backgroundColor: '#15151B' },
  attachBtnOff: { backgroundColor: '#0B0B0F', opacity: 0.5 },
  attachTxt: { fontSize: 20, color: '#FFFFFF' },
  attachTxtOff: { color: '#5E6464' },
  sendBtn: { marginLeft: 8, borderRadius: 20, paddingHorizontal: 18, paddingVertical: 12 },
  sendBtnOn: { backgroundColor: '#FFFFFF' },
  sendBtnOff: { backgroundColor: '#15151B' },
  sendTxt: { fontSize: 13, fontWeight: '700', color: '#5E6464' },
  sendTxtOn: { color: '#0B0B0F' },
  pickOverlay: { position: 'absolute', top: 0, left: 0, right: 0, bottom: 0, backgroundColor: 'rgba(11,11,15,0.75)', alignItems: 'center', justifyContent: 'center', padding: 16, zIndex: 50, elevation: 50 },
  pickSheet: { width: '100%', maxWidth: 340, borderRadius: 20, backgroundColor: '#15151B', borderWidth: 1, borderColor: '#24242D', padding: 18, alignItems: 'center' },
  pickTitle: { color: '#FFFFFF', fontSize: 15, fontWeight: '700', marginBottom: 12 },
  pickPreview: { width: '100%', height: 240, borderRadius: 12, backgroundColor: '#0B0B0F' },
  pickMeta: { color: '#8E9696', fontSize: 11, marginTop: 8 },
  pickBtns: { flexDirection: 'row', marginTop: 16 },
  dlToggle: { flexDirection: 'row', alignItems: 'center', marginTop: 14, alignSelf: 'flex-start' },
  dlBox: { width: 18, height: 18, borderRadius: 5, borderWidth: 1.5, borderColor: '#3A3A44', marginRight: 8, alignItems: 'center', justifyContent: 'center' },
  dlBoxOn: { backgroundColor: '#24242D', borderColor: '#FFFFFF' },
  dlBoxTxt: { color: '#FFFFFF', fontSize: 12, fontWeight: '700' },
  dlToggleTxt: { color: '#8E9696', fontSize: 12 },
  saveBtn: { marginTop: 6, alignSelf: 'flex-end', paddingVertical: 4, paddingHorizontal: 10, borderRadius: 8, backgroundColor: '#15151B', borderWidth: 1, borderColor: '#24242D' },
  saveBtnTxt: { color: '#FFFFFF', fontSize: 11 },
  pickCancel: { flex: 1, borderRadius: 14, backgroundColor: '#15151B', paddingVertical: 12, alignItems: 'center', marginRight: 8 },
  pickCancelTxt: { color: '#8E9696', fontSize: 14, fontWeight: '600' },
  pickSend: { flex: 1, borderRadius: 14, backgroundColor: '#FFFFFF', paddingVertical: 12, alignItems: 'center' },
  pickSendTxt: { color: '#0B0B0F', fontSize: 14, fontWeight: '700' },
  lightbox: { flex: 1, backgroundColor: 'rgba(11,11,15,0.94)', alignItems: 'center', justifyContent: 'center', padding: 16 },
  lightboxImg: { width: '100%', height: '82%' },
  lightboxHint: { color: '#8E9696', fontSize: 11, marginTop: 14 },
  // b140: soft large-file warning in the pick preview (send still allowed)
  pickWarn: { color: '#e8a33d', fontSize: 11, marginTop: 6, marginHorizontal: 18, textAlign: 'center' },
  // b140: full-screen video player
  videoFSBg: { flex: 1, backgroundColor: '#0B0B0F' },
  videoFSPlayer: { flex: 1 },
  videoFSClose: { position: 'absolute', top: 54, right: 20, width: 40, height: 40, borderRadius: 20, backgroundColor: 'rgba(11,11,15,0.55)', alignItems: 'center', justifyContent: 'center' },
  videoFSCloseTxt: { color: '#FFFFFF', fontSize: 20, lineHeight: 22 },
  videoFSHint: { color: '#8E9696', fontSize: 11, textAlign: 'center', paddingVertical: 10 },

  // b187: lounge read-only notice
  loungeNoteTxt: {
    flexBasis: '100%',
    width: '100%',
    color: '#FFFFFF',
    fontSize: 12,
    textAlign: 'center',
    paddingBottom: 6,
  },
});
