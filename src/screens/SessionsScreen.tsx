import React from 'react';
import { View, Text, TouchableOpacity, StyleSheet, ScrollView, RefreshControl, Alert, Share, ActivityIndicator, Image } from 'react-native';
import { useThemedPrompt } from './ThemedPrompt';
import { IdentityCard } from './SettingsScreen';

export interface SessionRow {
  token: string;
  /** relay VeilSession record id (for hard-delete fallbacks when the end gate 403s) */
  recId?: string;
  /** Display name: contact nickname, else peer veil-id, else 'Anonymous session'. */
  title: string;
  subtitle: string;
  status: 'active' | 'pending' | 'ended';
  verified: boolean;
  unread: number;
  /** role-aware PEER veil-id (the other party), for re-session actions */
  peerVeilId?: string;
  /** MY side completed the per-session verify ceremony */
  myVerified?: boolean;
  /** the PEER's side completed it */
  peerVerified?: boolean;
  /** b155: contact (pinned) session — trust comes from the pin, no ceremony state */
  contact?: boolean;
  /** b178: true when this account was the INITIATOR (we created it) — the
   *  new-invite banner must not fire for our own creations. */
  mine?: boolean;
  /** b162: PEER's last presence beat (relay seen_at, ms epoch; 0 = never seen).
   *  Web parity: fresh within 15 s reads as online. Groups never carry this. */
  peerSeenAt?: number;
  /** b62 groups: set when this row is a veil-group-1 thread */
  groupToken?: string;
  /** b71 dedupe (internal, never rendered): true when this row is the
   *  group's MAIN session — mine AND no peer on the row. Used by
   *  collapseGroupRows() to prefer the canonical thread over invite rows. */
  mainGroupRow?: boolean;

  /** b187/b188: lounge/forum thread — local record, no invite session.
   *  lounge = founder broadcast (read-only); forum = writable. */
  lounge?: boolean;
  forum?: boolean;
}

export interface SessionsScreenProps {
  sessions: SessionRow[];
  busy: boolean;
  onRefresh: () => void;
  onOpenSession: (token: string) => void;
  /** one-tap session: jump to pinned contacts */
  onNewSession: () => void;
  /** web parity: create a pending invite session, return the shareable link */
  onCreateInvite: () => Promise<string>;
  /** web parity: join a session from a pasted invite link */
  onJoinInvite: (link: string) => Promise<void>;
  /** b139 funnel fix: pinned local welcome thread (shown until dismissed) */
  welcomeVisible?: boolean;
  onOpenWelcome?: () => void;
  /** b196-r5: Founding Tester Forum banner (non-members only) */
  forumBannerVisible?: boolean;
  forumBannerBusy?: boolean;
  onJoinForum?: () => void;
  onDismissForumBanner?: () => void;
  /** b199 (owner, Oct 16): the identity card from Settings sits at the top of Conversations */
  identity?: { veilId: string | null; nickname: string; onShare: () => void; onShowQr?: () => void };
}

/**
 * Conversations list (Phase B step 4). Rows come from the relay session list
 * joined with local ratchet state; opening a row mounts the chat pane (next step).
 *
 * b199 UI redesign (owner, Oct 16): same grouped format as Settings and
 * Contacts — one inset card per section, hairline dividers, one line per
 * thread. Sections answer "what is this thread?" at a glance: Groups, Chats,
 * Waiting to join, Ended.
 */
export function SessionsScreen({ sessions, busy, onRefresh, onOpenSession, onNewSession, onCreateInvite, onJoinInvite, welcomeVisible, onOpenWelcome, forumBannerVisible, forumBannerBusy, onJoinForum, onDismissForumBanner, identity }: SessionsScreenProps) {
  const [inviteBusy, setInviteBusy] = React.useState(false);
  const [inviteLink, setInviteLink] = React.useState<string | null>(null);
  // BUG FIXED (Sept 19): "+ New" used to open ActionSheetIOS — a plain system
  // sheet that renders in iOS's own light/system styling, not VEIL's palette.
  // Replaced with an in-screen overlay (same pattern already proven for
  // ChatScreen's preview dialog) so it's themed and can't collide with
  // another native modal.
  const [pickerOpen, setPickerOpen] = React.useState(false);
  // (b57) themed prompt — the OS Alert.prompt here was an unthemeable system box
  const { node: promptNode, ask } = useThemedPrompt();

  const onNew = () => setPickerOpen(true);

  const doJoinPrompt = async () => {
    const t = (await ask({
      title: 'Join with an invite link',
      message: 'Paste the link your peer sent you.',
      input: 'text',
      submitLabel: 'Join',
    })) as string | null;
    const link = (t || '').trim();
    if (!link) return;
    setInviteBusy(true);
    try {
      await onJoinInvite(link);
    } catch (e) {
      await ask({ title: 'Could not join', message: String((e as Error).message || e), info: true });
    } finally {
      setInviteBusy(false);
    }
  };

  const doCreateInvite = async () => {
    setInviteBusy(true); setInviteLink(null);
    try { setInviteLink(await onCreateInvite()); } catch (e) {
      Alert.alert('Invite could not be created', String((e as Error).message || e));
    } finally { setInviteBusy(false); }
  };

  const isGroupRow = (s: SessionRow) => !!(s.groupToken || s.lounge || s.forum);
  const groups = sessions.filter(isGroupRow);
  const rest = sessions.filter((s) => !isGroupRow(s));
  const chats = rest.filter((s) => s.status === 'active');
  const waiting = rest.filter((s) => s.status === 'pending');
  const ended = rest.filter((s) => s.status === 'ended');

  const renderRow = (s: SessionRow, i: number, all: SessionRow[]) => {
    const group = isGroupRow(s);
    const online = !group && s.status === 'active' && !!s.peerSeenAt && Date.now() - s.peerSeenAt < 15000;
    return (
      <TouchableOpacity key={s.token} style={[styles.row, i === all.length - 1 && styles.rowLast]} onPress={() => onOpenSession(s.token)} disabled={busy}>
        <View style={[styles.avatar, group && styles.avatarGroup, s.status === 'pending' && styles.avatarPending, s.status === 'ended' && styles.avatarEnded]}>
          <Text style={[styles.avatarText, s.status === 'ended' && styles.avatarTextEnded]}>{group ? '#' : s.title.slice(0, 2).toUpperCase()}</Text>
          {online ? <View style={styles.onlineDot} /> : null}
        </View>
        <View style={styles.rowBody}>
          <View style={styles.rowTop}>
            <Text style={[styles.rowTitle, s.unread > 0 && styles.rowTitleUnread]} numberOfLines={1}>{s.title}</Text>
            {s.verified ? <Text style={styles.verified}>✓</Text> : null}
          </View>
          <Text style={styles.rowSub} numberOfLines={1}>{s.subtitle}</Text>
        </View>
        {s.unread > 0 ? (
          <View style={styles.badge}><Text style={styles.badgeText}>{s.unread > 9 ? '9+' : s.unread}</Text></View>
        ) : (
          <Text style={styles.chevron}>›</Text>
        )}
      </TouchableOpacity>
    );
  };

  const section = (title: string, rows: SessionRow[], note?: string) => rows.length === 0 ? null : (
    <View key={title}>
      <Text style={styles.groupTitle}>{title}</Text>
      <View style={styles.group}>{rows.map((s, i) => renderRow(s, i, rows))}</View>
      {note ? <Text style={styles.groupNote}>{note}</Text> : null}
    </View>
  );

  return (
    <View style={styles.fill}>
      <View style={styles.topBar}>
        <Text style={styles.h1}>Conversations</Text>
        <TouchableOpacity style={styles.newBtn} onPress={onNew} disabled={inviteBusy}>
          {inviteBusy ? <ActivityIndicator color="#0B0B0F" size="small" /> : <Text style={styles.newBtnText}>＋ New</Text>}
        </TouchableOpacity>
      </View>

      {pickerOpen ? (
        <View style={styles.pickerOverlay}>
          <TouchableOpacity style={styles.pickerBackdrop} activeOpacity={1} onPress={() => setPickerOpen(false)} />
          <View style={styles.pickerCard}>
            <Text style={styles.pickerTitle}>Start a conversation</Text>
            <View style={styles.group}>
              <TouchableOpacity style={styles.pickerRow} onPress={() => { setPickerOpen(false); onNewSession(); }}>
                <View style={styles.rowBody}>
                  <Text style={styles.pickerRowTxt}>Message a contact</Text>
                  <Text style={styles.pickerRowSub}>Pick someone from your contacts</Text>
                </View>
                <Text style={styles.chevron}>›</Text>
              </TouchableOpacity>
              <TouchableOpacity style={styles.pickerRow} onPress={() => { setPickerOpen(false); doCreateInvite(); }}>
                <View style={styles.rowBody}>
                  <Text style={styles.pickerRowTxt}>Create an invite link</Text>
                  <Text style={styles.pickerRowSub}>For one person who isn't a contact yet</Text>
                </View>
                <Text style={styles.chevron}>›</Text>
              </TouchableOpacity>
              <TouchableOpacity style={[styles.pickerRow, styles.rowLast]} onPress={() => { setPickerOpen(false); doJoinPrompt(); }}>
                <View style={styles.rowBody}>
                  <Text style={styles.pickerRowTxt}>Join with an invite link</Text>
                  <Text style={styles.pickerRowSub}>Paste a link someone sent you</Text>
                </View>
                <Text style={styles.chevron}>›</Text>
              </TouchableOpacity>
            </View>
            <TouchableOpacity style={styles.pickerCancelRow} onPress={() => setPickerOpen(false)}>
              <Text style={styles.pickerCancelTxt}>Cancel</Text>
            </TouchableOpacity>
          </View>
        </View>
      ) : null}

      <ScrollView
        style={styles.fill}
        contentContainerStyle={sessions.length === 0 ? styles.emptyWrap : styles.list}
        refreshControl={<RefreshControl tintColor="#FFFFFF" refreshing={busy} onRefresh={onRefresh} />}
      >
        {identity?.veilId ? (
          <View style={styles.idWrap}>
            <IdentityCard veilId={identity.veilId} nickname={identity.nickname} onShare={identity.onShare} onShowQr={identity.onShowQr} />
          </View>
        ) : null}
        {inviteLink ? (
          <View style={styles.inviteCard}>
            <Text style={styles.inviteTitle}>Invite link ready</Text>
            <Text style={styles.inviteText}>
              Share it with one person. It opens the Vardum web app, and the key lives only in the link. The conversation unlocks when they join.
            </Text>
            <TouchableOpacity style={styles.inviteBtn} onPress={() => Share.share({ message: inviteLink }).catch(() => {})}>
              <Text style={styles.inviteBtnTxt}>Share / copy the link</Text>
            </TouchableOpacity>
            <TouchableOpacity onPress={() => setInviteLink(null)}>
              <Text style={styles.inviteDismiss}>Dismiss</Text>
            </TouchableOpacity>
          </View>
        ) : null}
        {forumBannerVisible ? (
          <View style={styles.forumBanner}>
            <Text style={styles.forumBannerTitle}>⚡ The Founding Tester Forum is live — from Matt, your founder</Text>
            <Text style={styles.forumBannerBody}>Big news: we've upgraded Vardum's security and moved to our own servers and relay. The Founding Tester Forum is where I'll be talking with you all directly — one tap to join, no invite link, end-to-end encrypted, history kept for 30 days. To use it you'll need to migrate over to the new native build — the upgrade only runs there. Come across, say hello — look forward to talking to you all. — Matt</Text>
            <View style={styles.forumBannerActions}>
              <TouchableOpacity style={styles.forumJoinBtn} onPress={onJoinForum} disabled={forumBannerBusy || busy}>
                <Text style={styles.forumJoinBtnText}>{forumBannerBusy ? 'Joining…' : 'Join the forum →'}</Text>
              </TouchableOpacity>
              <TouchableOpacity onPress={onDismissForumBanner} disabled={forumBannerBusy}>
                <Text style={styles.forumBannerDismiss}>Not now</Text>
              </TouchableOpacity>
            </View>
          </View>
        ) : null}
        {welcomeVisible && onOpenWelcome ? (
          <View>
            <Text style={[styles.groupTitle, styles.groupTitleFirst]}>Start here</Text>
            <View style={styles.group}>
              <TouchableOpacity style={[styles.row, styles.rowLast]} onPress={onOpenWelcome} disabled={busy}>
                <View style={[styles.avatar, styles.avatarWelcome]}>
                  <Text style={styles.avatarText}>VE</Text>
                </View>
                <View style={styles.rowBody}>
                  <View style={styles.rowTop}>
                    <Text style={styles.rowTitle} numberOfLines={1}>Getting started</Text>
                  </View>
                  <Text style={styles.rowSub} numberOfLines={1}>A welcome note from Matt, plus your first three moves.</Text>
                </View>
                <Text style={styles.chevron}>›</Text>
              </TouchableOpacity>
            </View>
          </View>
        ) : null}
        {sessions.length === 0 ? (
          <View style={styles.empty}>
            {/* Big, visible brand mark for the empty state — owner reverted the
                glow box (Sept 19): just the ring/arcs, no background/shadow. */}
            <Image source={require('../../assets/logo-mark.png')} style={styles.emptyLogo} resizeMode="contain" />
            <Text style={styles.emptyTitle}>No conversations yet</Text>
            <Text style={styles.emptyText}>
              Tap ＋ New to message a contact or share an invite link. Messages are sealed with post-quantum keys that never leave this device.
            </Text>
          </View>
        ) : (
          <>
            {section('Groups', groups)}
            {section('Chats', chats)}
            {section('Waiting to join', waiting, 'These open as soon as the other person accepts.')}
            {section('Ended', ended, 'No new messages can be sent here. Start a new chat from Contacts.')}
          </>
        )}
      </ScrollView>
      {promptNode}
    </View>
  );
}

const styles = StyleSheet.create({
  pickerOverlay: { position: 'absolute', left: 0, right: 0, top: 0, bottom: 0, justifyContent: 'flex-end', zIndex: 20 },
  pickerBackdrop: { position: 'absolute', left: 0, right: 0, top: 0, bottom: 0, backgroundColor: 'rgba(11,11,15,0.86)' },
  pickerCard: { backgroundColor: '#15151B', borderTopLeftRadius: 16, borderTopRightRadius: 16, borderWidth: 1, borderColor: '#24242D', borderBottomWidth: 0, paddingTop: 16, paddingBottom: 28, paddingHorizontal: 16 },
  pickerTitle: { color: '#FFFFFF', fontSize: 11, fontWeight: '800', letterSpacing: 0.8, textTransform: 'uppercase', marginBottom: 8, marginLeft: 6 },
  pickerRow: { flexDirection: 'row', alignItems: 'center', paddingVertical: 12, paddingHorizontal: 14, borderBottomWidth: 1, borderBottomColor: '#24242D', minHeight: 56 },
  pickerRowTxt: { color: '#FFFFFF', fontSize: 15, fontWeight: '600' },
  pickerRowSub: { color: '#8E9696', fontSize: 12, marginTop: 2 },
  pickerCancelRow: { paddingVertical: 13, marginTop: 10, borderRadius: 11, borderWidth: 1, borderColor: '#24242D', alignItems: 'center' },
  pickerCancelTxt: { color: '#C9CFCE', fontSize: 14, fontWeight: '600' },
  avatarWelcome: { backgroundColor: '#24242D' },
  inviteCard: { borderWidth: 1, borderColor: '#3A3A44', borderRadius: 12, padding: 14, marginTop: 4, marginBottom: 6, backgroundColor: 'rgba(255,255,255,0.05)' },
  // b198 (owner): the Founding Tester Forum banner in FLUORO BLUE — it is the
  // home-page announcement and must be unmissable.
  forumBanner: { borderWidth: 2, borderColor: '#FFFFFF', borderRadius: 12, padding: 14, marginTop: 4, marginBottom: 6, backgroundColor: 'rgba(255,255,255,0.12)' },
  forumBannerTitle: { color: '#FFFFFF', fontSize: 15, fontWeight: '800', marginBottom: 6 },
  forumBannerBody: { color: '#C9CFCE', fontSize: 12, lineHeight: 18, marginBottom: 10 },
  forumBannerActions: { flexDirection: 'row', alignItems: 'center', gap: 14 },
  forumJoinBtn: { backgroundColor: '#FFFFFF', borderRadius: 10, paddingVertical: 10, paddingHorizontal: 16 },
  forumJoinBtnText: { color: '#0B0B0F', fontSize: 13, fontWeight: '800' },
  forumBannerDismiss: { color: '#8E9696', fontSize: 12 },
  inviteTitle: { color: '#FFFFFF', fontSize: 14, fontWeight: '700', marginBottom: 6 },
  inviteText: { color: '#8E9696', fontSize: 12, lineHeight: 17, marginBottom: 10 },
  inviteBtn: { backgroundColor: '#FFFFFF', borderRadius: 11, paddingVertical: 11, alignItems: 'center', marginBottom: 8 },
  inviteBtnTxt: { color: '#0B0B0F', fontSize: 13, fontWeight: '800' },
  inviteDismiss: { color: '#8E9696', fontSize: 12, fontWeight: '600', textAlign: 'center', paddingVertical: 4 },
  fill: { flex: 1 },
  idWrap: { marginTop: 6, marginBottom: 6 },
  topBar: { flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between', paddingHorizontal: 20, paddingTop: 16, paddingBottom: 6 },
  h1: { color: '#FFFFFF', fontSize: 22, fontWeight: '700' },
  newBtn: { backgroundColor: '#FFFFFF', borderRadius: 9, paddingHorizontal: 14, paddingVertical: 7, minWidth: 72, alignItems: 'center' },
  newBtnText: { color: '#0B0B0F', fontSize: 13, fontWeight: '800' },
  list: { paddingHorizontal: 16, paddingBottom: 32 },
  // b199 (owner device report, Oct 16): was `flex: 1`, which pinned the empty
  // state's content box to the screen height and centred inside it — with the
  // forum banner + Getting started row above the empty state the content was
  // taller than the screen, so centring pushed the banner's top under the
  // "Conversations" bar and "No conversations yet" off the bottom, and nothing
  // could scroll. flexGrow fills the screen when the content fits (still
  // centred) and grows + scrolls when it doesn't. Same side gutter as `list`.
  emptyWrap: { flexGrow: 1, justifyContent: 'center', paddingHorizontal: 12, paddingTop: 4, paddingBottom: 24 },
  empty: { alignItems: 'center', paddingHorizontal: 30, marginTop: 24 },
  emptyLogo: { width: 96, height: 96, marginBottom: 22 },
  emptyTitle: { color: '#FFFFFF', fontSize: 16, fontWeight: '600', marginBottom: 8 },
  emptyText: { color: '#8E9696', fontSize: 13, lineHeight: 19, textAlign: 'center' },
  // grouped list (b199 redesign): same tokens as Settings / Contacts
  groupTitle: { color: '#FFFFFF', fontSize: 11, fontWeight: '800', letterSpacing: 0.8, textTransform: 'uppercase', marginTop: 20, marginBottom: 6, marginLeft: 6 },
  groupTitleFirst: { marginTop: 12 },
  group: { backgroundColor: '#15151B', borderWidth: 1, borderColor: '#24242D', borderRadius: 12, overflow: 'hidden' },
  groupNote: { color: '#8E9696', fontSize: 11, lineHeight: 16, marginTop: 6, marginHorizontal: 6 },
  row: { flexDirection: 'row', alignItems: 'center', paddingHorizontal: 12, paddingVertical: 10, borderBottomWidth: 1, borderBottomColor: '#24242D', minHeight: 60 },
  rowLast: { borderBottomWidth: 0 },
  avatar: { width: 40, height: 40, borderRadius: 20, backgroundColor: '#24242D', alignItems: 'center', justifyContent: 'center', marginRight: 12 },
  avatarGroup: { borderRadius: 12, backgroundColor: '#24242D' },
  avatarPending: { backgroundColor: '#2a2413' },
  avatarEnded: { backgroundColor: '#15151B' },
  avatarText: { color: '#FFFFFF', fontSize: 14, fontWeight: '700' },
  avatarTextEnded: { color: '#4A4A54' },
  onlineDot: { position: 'absolute', right: -1, bottom: -1, width: 12, height: 12, borderRadius: 6, backgroundColor: '#FFFFFF', borderWidth: 2, borderColor: '#24242D' },
  rowBody: { flex: 1, minWidth: 0 },
  rowTop: { flexDirection: 'row', alignItems: 'center' },
  rowTitle: { color: '#FFFFFF', fontSize: 15, fontWeight: '600', flexShrink: 1, marginRight: 6 },
  rowTitleUnread: { fontWeight: '800' },
  verified: { color: '#FFFFFF', fontSize: 13, fontWeight: '800' },
  rowSub: { color: '#8E9696', fontSize: 12, marginTop: 2 },
  badge: { backgroundColor: '#FFFFFF', borderRadius: 10, minWidth: 20, paddingHorizontal: 6, paddingVertical: 3, alignItems: 'center', marginLeft: 8 },
  badgeText: { color: '#0B0B0F', fontSize: 11, fontWeight: '800' },
  chevron: { color: '#4A4A54', fontSize: 20, marginLeft: 8 },
});
