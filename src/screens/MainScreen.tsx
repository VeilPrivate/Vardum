import React from 'react';
import { View, Text, TextInput, TouchableOpacity, StyleSheet, Image, Keyboard } from 'react-native';
import { useKbPadding } from '../hooks/useKbPadding';
import { PASSWORD_MAX } from '../password';
import { useThemedShare } from './ThemedSheets';
import { VeilQrSheet } from './VeilQr';
import { Ionicons } from '@expo/vector-icons';
import { SessionsScreen, type SessionRow } from './SessionsScreen';
import { ContactsScreen, type ContactRow, type LookupResult, type GroupInviteResult, type ContactChatChoice } from './ContactsScreen';
import { SettingsScreen } from './SettingsScreen';
import { VaultsScreen, NotesScreen, StegoScreen } from './ToolsScreen';
import type { VeilApp } from '../veil-app';
import { type VeilSettings } from '../../vendor/device/src/settings';

export interface MainScreenProps {
  decoyMode: boolean;
  veilId: string | null;
  email?: string | null;
  busy: boolean;
  onSignOut: () => void;
  sessions: SessionRow[];
  onRefreshSessions: () => void;
  onOpenSession: (token: string) => void;
  onNewSession: () => void;
  onCreateInvite: () => Promise<string>;
  onJoinInvite: (link: string) => Promise<void>;
  contacts: ContactRow[];
  contactsError: string | null;
  onLookup: (veilId: string) => Promise<LookupResult | null>;
  onPin: (lookup: LookupResult) => Promise<void>;
  /** b57: unpin a contact (device-local pin removal, two-tap confirm in the UI) */
  onUnpin: (veilId: string) => Promise<void>;
  onMessage: (veilId: string) => void;
  onVerify: (veilId: string) => Promise<void>;
  onSetNickname: (veilId: string, nickname: string) => void;
  /** b199 groups: create with pinned contacts (+ optional backup links) */
  onCreateGroup: (name: string, invitees: string[], linkCount: number) => Promise<GroupInviteResult>;
  /** b199: open your existing chat with a contact; never starts one silently */
  onOpenContact: (veilId: string, choice?: { open?: string; start?: boolean }) => Promise<ContactChatChoice[] | null>;
  /** b199: groups created on this phone + "Add people" */
  myGroups: { groupToken: string; name: string }[];
  onAddGroupPeople: (groupToken: string, invitees: string[], linkCount: number) => Promise<GroupInviteResult>;
  /** b199 Veil QR: add link opened — Contacts looks it up and asks to confirm */
  prefillAdd?: { veilId: string; nonce: number } | null;
  /** Play UGC: device-local block list (Settings > Blocked) */
  blockedIds?: string[];
  onUnblock?: (veilId: string) => Promise<void>;
  settings: VeilSettings;
  onSettingsChange: (s: VeilSettings) => void;
  onRunCheckup: () => void;
  appLockEnabled: boolean;
  onSetAppLock: (pass: string, decoy?: string | null, duress?: string | null) => Promise<void>;
  onRemoveAppLock: (pass: string) => Promise<boolean>;
  onLockNow: () => void;
  onWipeDevice: () => Promise<void>;
  onDeleteAccount: () => Promise<void>;
  onViewIntro: () => void;
  webBaseUrl: string;
  onCreateTransfer: () => Promise<{ link: string; sessionCount: number; groupCount: number; hasIdentity: boolean }>;
  onReceiveTransfer: (link: string) => Promise<{ sessionCount: number; importedCount: number; skippedExisting: number; identityImported: boolean; identityKept: boolean }>;
  onVerifyPhrase: (phrase: string) => Promise<boolean>;
  onSwitchToPhraseSignIn?: (phrase: string) => Promise<'ok' | 'wrong-phrase'>;
  onRemoveIdentity: () => Promise<void>;
  onGenerateNewVeilId: () => Promise<void>;
  onCreateIdentity: () => void;
  /** dismissible in-app "Secure your VEIL" prompt (checkup + app lock) */
  securePrompt: boolean;
  onDismissSecurePrompt: () => void;
  /** b139 funnel fix: the local "Getting started" welcome thread row */
  welcomeVisible: boolean;
  onOpenWelcome: () => void;
  /** b196-r5: Founding Tester Forum banner (non-members only) */
  forumBannerVisible?: boolean;
  forumBannerBusy?: boolean;
  onJoinForum?: () => void;
  onDismissForumBanner?: () => void;
  tab: 'sessions' | 'contacts' | 'vaults' | 'stego' | 'notes' | 'settings';
  onTab: (tab: 'sessions' | 'contacts' | 'vaults' | 'stego' | 'notes' | 'settings') => void;
  app: VeilApp;
}

/**
 * Signed-in shell (Phase B step 4): identity strip + Conversations/Contacts tabs.
 * The chat pane mounts on session open (next step).
 */
export function MainScreen({
  app, decoyMode, veilId, email, busy, onSignOut,
  sessions, onRefreshSessions, onOpenSession, onNewSession, onCreateInvite, onJoinInvite,
  contacts, contactsError, onLookup, onPin, onUnpin, onMessage, onVerify, onSetNickname, onCreateGroup, onOpenContact, myGroups, onAddGroupPeople, prefillAdd, settings, onSettingsChange, onRunCheckup, tab, onTab,
  blockedIds, onUnblock,
  appLockEnabled, onSetAppLock, onRemoveAppLock,
  onLockNow, onWipeDevice, onDeleteAccount, onViewIntro, webBaseUrl,
  onCreateTransfer, onReceiveTransfer, onVerifyPhrase, onSwitchToPhraseSignIn, onRemoveIdentity, onGenerateNewVeilId, onCreateIdentity,
  securePrompt, onDismissSecurePrompt, welcomeVisible, onOpenWelcome,
  forumBannerVisible, forumBannerBusy, onJoinForum, onDismissForumBanner,
}: MainScreenProps) {
  // b198 (owner direction, battery): NOTES ARE GATED — entering the Notes tab
  // demands the app-lock passcode, every time. The whole-app lock covers the
  // shell; this gate covers the one screen that holds long-lived private
  // text. Re-locks on every tab entry; the app-lock record is the only key.
  const [notesUnlocked, setNotesUnlocked] = React.useState(false);
  const [notesCode, setNotesCode] = React.useState('');
  const [notesErr, setNotesErr] = React.useState<string | null>(null);
  const [notesBusy, setNotesBusy] = React.useState(false);
  // b199: keyboard height for the Notes lock (the tab bar under it is ~58pt tall)
  const kbRaw = useKbPadding();
  const notesKb = Math.max(0, kbRaw - 58);
  // b199: full-screen VEIL QR (opened from the identity card)
  const [qrOpen, setQrOpen] = React.useState(false);
  React.useEffect(() => { if (tab === 'notes') { setNotesUnlocked(false); setNotesCode(''); setNotesErr(null); } }, [tab]);
  const unlockNotes = async () => {
    if (notesBusy || !notesCode) return;
    setNotesBusy(true);
    try {
      const kind = await app.appLock.verify(notesCode);
      if (kind === 'real') { setNotesUnlocked(true); setNotesErr(null); setNotesCode(''); }
      else { setNotesErr('Wrong password.'); setNotesCode(''); }
    } catch (e) {
      // Batch D (D-11): verify enforces the shared lockout here too
      const m = String((e as Error)?.message ?? '');
      setNotesErr(/too many|could not be read/i.test(m) ? m : 'Could not verify — try again.');
    }
    finally { setNotesBusy(false); }
  };
  // b105: VEIL-branded share card for the Veil ID (owner request Sept 22 —
  // the identity strip jumped straight into Apple's stock share sheet)
  const { node: shareNode, share: openShare } = useThemedShare();
  const tabIcon = (name: keyof typeof Ionicons.glyphMap, active: boolean) => (
    <Ionicons name={name} size={21} color={active ? '#FFFFFF' : '#5E6464'} />
  );
  // b90: total unread across threads — highlights the Chat tab icon
  const unreadTotal = sessions.reduce((n, r) => n + (r.unread || 0), 0);

  return (
    <View style={styles.fill}>
      {shareNode}
      <View style={styles.header}>
        <View style={styles.brandRow}>
          <Image source={require('../../assets/logo.png')} style={styles.logoSmall} />
          <Text style={styles.logo}><Text style={{ color: '#20D9C2' }}>V</Text>ardum</Text>
        </View>
        <TouchableOpacity onPress={onSignOut} disabled={busy}>
          <Text style={styles.signOut}>{busy ? '…' : 'Sign out'}</Text>
        </TouchableOpacity>
      </View>

      {/* b199 (owner, Oct 16): the Veil ID strip that sat on every tab is gone —
          the identity card now lives at the top of Conversations (and Settings). */}

      {securePrompt ? (
        <View style={styles.secureBox}>
          <Text style={styles.secureTitle}>Lock down this phone</Text>
          <Text style={styles.secureTxt}>Run the privacy checkup and set an app lock. Nothing is pre-set — every control is yours.</Text>
          <View style={{ flexDirection: 'row', gap: 10, marginTop: 10 }}>
            <TouchableOpacity style={styles.secureBtn} onPress={onRunCheckup}>
              <Text style={styles.secureBtnTxt}>Run the privacy checkup</Text>
            </TouchableOpacity>
            <TouchableOpacity style={styles.secureBtnGhost} onPress={onDismissSecurePrompt}>
              <Text style={styles.secureBtnGhostTxt}>Not now</Text>
            </TouchableOpacity>
          </View>
        </View>
      ) : null}

      <View style={styles.body}>
        {tab === 'sessions' ? (
          <SessionsScreen sessions={sessions} busy={busy} onRefresh={onRefreshSessions} onOpenSession={onOpenSession} onNewSession={onNewSession} onCreateInvite={onCreateInvite} onJoinInvite={onJoinInvite} welcomeVisible={welcomeVisible} onOpenWelcome={onOpenWelcome} forumBannerVisible={forumBannerVisible} forumBannerBusy={forumBannerBusy} onJoinForum={onJoinForum} onDismissForumBanner={onDismissForumBanner} identity={{ veilId: veilId ?? null, nickname: settings.nickname, onShare: () => { if (veilId) openShare({ value: veilId, kicker: 'People use it to look you up and start verified conversations.' }); }, onShowQr: () => setQrOpen(true) }} />
        ) : tab === 'contacts' ? (
          <ContactsScreen contacts={contacts} busy={busy} error={contactsError} onLookup={onLookup} onPin={onPin} onUnpin={onUnpin} onMessage={onMessage} onVerify={onVerify} onSetNickname={onSetNickname} onCreateGroup={onCreateGroup} onOpenContact={onOpenContact} myGroups={myGroups} onAddGroupPeople={onAddGroupPeople} prefillAdd={prefillAdd} />
        ) : tab === 'vaults' ? (
          <VaultsScreen app={app} decoy={decoyMode} veilId={veilId} />
        ) : tab === 'notes' ? (
          // b199 UI redesign (owner, Oct 16: "the gate is very plain"): same
          // look as the app lock screen — lock mark, passcode dots, keypad.
          !appLockEnabled ? (
            <View style={styles.notesGate}>
              <View style={styles.notesGateIcon}><Ionicons name="lock-closed" size={30} color="#FFFFFF" /></View>
              <Text style={styles.notesGateTitle}>Notes are locked</Text>
              <Text style={styles.notesGateBody}>Notes open only behind the app password. Set one in Settings → App lock, then come back.</Text>
              <TouchableOpacity style={styles.notesGateBtn} onPress={() => onTab('settings')}><Text style={styles.notesGateBtnTxt}>Go to Settings</Text></TouchableOpacity>
            </View>
          ) : !notesUnlocked ? (
            // b199 (owner, Oct 16): big lock mark + words; the slim bar at the
            // bottom IS the password field — tapping it opens the dark iPhone
            // keyboard (any characters, up to 50; AutoFill and saving are off).
            <View style={[styles.notesGateFull, notesKb > 0 ? { paddingBottom: notesKb } : null]}>
              <TouchableOpacity style={styles.notesGateTop} activeOpacity={1} onPress={() => Keyboard.dismiss()}>
                <View style={[styles.notesGateIconBig, notesKb > 0 && styles.notesGateIconSmall]}><Ionicons name="document-lock-outline" size={notesKb > 0 ? 30 : 46} color="#FFFFFF" /></View>
                <Text style={styles.notesGateTitleBig}>Notes are locked</Text>
                <Text style={styles.notesGateBodyBig}>Enter your app password to open Notes.</Text>
              </TouchableOpacity>
              <Text style={styles.notesGateErr}>{notesBusy ? 'Checking…' : (notesErr ?? '')}</Text>
              <View style={[styles.notesBar, notesCode.length > 0 && styles.notesBarOn]}>
                <Ionicons name="lock-closed-outline" size={18} color={notesCode.length > 0 ? '#FFFFFF' : '#8E9696'} />
                <TextInput
                  style={styles.notesBarInput}
                  value={notesCode}
                  onChangeText={(t) => { setNotesErr(null); setNotesCode(t.slice(0, PASSWORD_MAX)); }}
                  onSubmitEditing={unlockNotes}
                  editable={!notesBusy}
                  secureTextEntry
                  maxLength={PASSWORD_MAX}
                  placeholder="Enter password"
                  placeholderTextColor="#5E6464"
                  keyboardAppearance="dark"
                  returnKeyType="go"
                  autoCapitalize="none"
                  autoCorrect={false}
                  spellCheck={false}
                  textContentType="oneTimeCode" // suppresses iOS Use Strong Password
                  autoComplete="off"
                  importantForAutofill="no"
                  accessibilityLabel="Password"
                />
              </View>
              <TouchableOpacity style={[styles.notesGateBtn, styles.notesGateBtnBar, (notesBusy || !notesCode) && styles.notesGateBtnOff]} disabled={notesBusy || !notesCode} onPress={unlockNotes}>
                <Text style={styles.notesGateBtnTxt}>{notesBusy ? 'Checking…' : 'Unlock Notes'}</Text>
              </TouchableOpacity>
            </View>
          ) : (
            <NotesScreen app={app} decoy={decoyMode} veilId={veilId} />
          )
        ) : tab === 'stego' ? (
          <StegoScreen storage={app.storage} />
        ) : (
          <SettingsScreen
            settings={settings} onChange={onSettingsChange} veilId={veilId} email={email}
            onRunCheckup={onRunCheckup} appLockEnabled={appLockEnabled}
            onSetAppLock={onSetAppLock} onRemoveAppLock={onRemoveAppLock}
            onSignOut={onSignOut} onLockNow={onLockNow} onWipeDevice={onWipeDevice}
            onDeleteAccount={onDeleteAccount} onViewIntro={onViewIntro} onOpenWelcome={onOpenWelcome} webBaseUrl={webBaseUrl}
            onOpenTools={() => onTab('vaults')} onOpenContacts={() => onTab('contacts')}
            onCreateTransfer={onCreateTransfer} onReceiveTransfer={onReceiveTransfer}
            onVerifyPhrase={onVerifyPhrase} onSwitchToPhraseSignIn={onSwitchToPhraseSignIn} onRemoveIdentity={onRemoveIdentity}
            onGenerateNewVeilId={onGenerateNewVeilId} onCreateIdentity={onCreateIdentity} onShowQr={() => setQrOpen(true)}
            blockedIds={blockedIds} onUnblock={onUnblock}
          />
        )}
      </View>

      {/* (b118) owner request (Sept 24): the 'account: <email>' line is gone — Settings must never show the signed-in identity/email. */}
      {/* (b67) owner request: Chat - Contacts - Vault - Stego - Notes - Settings */}
      <View style={styles.bottomBar}>
        <TouchableOpacity style={styles.bottomTab} onPress={() => onTab('sessions')}>
          <View>
            {tabIcon(tab === 'sessions' ? 'chatbubble' : 'chatbubble-outline', tab === 'sessions')}
            {unreadTotal > 0 ? (
              <View style={styles.tabBadge}><Text style={styles.tabBadgeText}>{unreadTotal > 9 ? '9+' : unreadTotal}</Text></View>
            ) : null}
          </View>
          <Text style={[styles.bottomLabel, tab === 'sessions' && styles.bottomLabelOn]}>Chat</Text>
        </TouchableOpacity>
        <TouchableOpacity style={styles.bottomTab} onPress={() => onTab('contacts')}>
          {tabIcon(tab === 'contacts' ? 'person' : 'person-outline', tab === 'contacts')}
          <Text style={[styles.bottomLabel, tab === 'contacts' && styles.bottomLabelOn]}>Contacts</Text>
        </TouchableOpacity>
        <TouchableOpacity style={styles.bottomTab} onPress={() => onTab('vaults')}>
          {tabIcon(tab === 'vaults' ? 'lock-closed' : 'lock-closed-outline', tab === 'vaults')}
          <Text style={[styles.bottomLabel, tab === 'vaults' && styles.bottomLabelOn]}>Vault</Text>
        </TouchableOpacity>
        <TouchableOpacity style={styles.bottomTab} onPress={() => onTab('stego')}>
          {tabIcon(tab === 'stego' ? 'images' : 'images-outline', tab === 'stego')}
          <Text style={[styles.bottomLabel, tab === 'stego' && styles.bottomLabelOn]}>Stego</Text>
        </TouchableOpacity>
        <TouchableOpacity style={styles.bottomTab} onPress={() => onTab('notes')}>
          {tabIcon(tab === 'notes' ? 'document-text' : 'document-text-outline', tab === 'notes')}
          <Text style={[styles.bottomLabel, tab === 'notes' && styles.bottomLabelOn]}>Notes</Text>
        </TouchableOpacity>
        <TouchableOpacity style={styles.bottomTab} onPress={() => onTab('settings')}>
          {tabIcon(tab === 'settings' ? 'settings' : 'settings-outline', tab === 'settings')}
          <Text style={[styles.bottomLabel, tab === 'settings' && styles.bottomLabelOn]}>Settings</Text>
        </TouchableOpacity>
      </View>
      {qrOpen && veilId ? (
        <VeilQrSheet
          veilId={veilId}
          nickname={settings.nickname}
          onClose={() => setQrOpen(false)}
          onShareLink={(link) => { setQrOpen(false); openShare({ value: link, kicker: 'Send this to someone so they can add you on Vardum. It holds only your Vardum ID.' }); }}
        />
      ) : null}
    </View>
  );
}

const styles = StyleSheet.create({
  // b198 Notes gate — the passcode prompt covering the Notes tab
  notesGate: { flex: 1, alignItems: 'center', justifyContent: 'center', paddingHorizontal: 24, paddingVertical: 12, backgroundColor: '#0B0B0F' },
  notesGateIcon: { width: 68, height: 68, borderRadius: 34, borderWidth: 1, borderColor: '#3A3A44', backgroundColor: 'rgba(255,255,255,0.08)', alignItems: 'center', justifyContent: 'center', marginBottom: 14 },
  notesGateTitle: { fontSize: 19, fontWeight: '700', color: '#FFFFFF', marginBottom: 6 },
  notesGateBody: { fontSize: 13, color: '#8E9696', textAlign: 'center', marginBottom: 16, lineHeight: 19 },
  notesDots: { flexDirection: 'row', gap: 12, marginBottom: 4 },
  notesDot: { width: 13, height: 13, borderRadius: 7, borderWidth: 1, borderColor: '#3A3A44' },
  notesDotOn: { backgroundColor: '#FFFFFF', borderColor: '#FFFFFF' },
  notesGateErr: { color: '#e8836f', fontSize: 13, height: 20, textAlign: 'center', marginBottom: 4 },
  notesPad: { flexDirection: 'row', flexWrap: 'wrap', justifyContent: 'center', width: 240, marginBottom: 10 },
  notesKey: { width: '30%', height: 50, alignItems: 'center', justifyContent: 'center', borderRadius: 12, margin: 4, borderWidth: 1, borderColor: '#24242D', backgroundColor: '#15151B' },
  notesKeyBusy: { opacity: 0.4 },
  notesKeyTxt: { color: '#C9CFCE', fontSize: 21, fontWeight: '600' },
  notesKeyDel: { color: '#8E9696', fontSize: 18 },
  notesGateFull: { flex: 1, backgroundColor: '#0B0B0F', paddingHorizontal: 16, paddingBottom: 12 },
  notesGateTop: { flex: 1, alignItems: 'center', justifyContent: 'center', paddingHorizontal: 16 },
  notesGateIconBig: { width: 104, height: 104, borderRadius: 52, borderWidth: 1, borderColor: '#3A3A44', backgroundColor: 'rgba(255,255,255,0.08)', alignItems: 'center', justifyContent: 'center', marginBottom: 20 },
  notesGateTitleBig: { fontSize: 26, fontWeight: '800', color: '#FFFFFF', marginBottom: 8 },
  notesGateBodyBig: { fontSize: 16, color: '#8E9696', textAlign: 'center', lineHeight: 22 },
  notesBar: { flexDirection: 'row', alignItems: 'center', gap: 10, minHeight: 48, borderRadius: 24, borderWidth: 1, borderColor: '#24242D', backgroundColor: '#15151B', paddingHorizontal: 18 },
  notesBarOn: { borderColor: '#3A3A44' },
  notesBarTxt: { color: '#8E9696', fontSize: 15 },
  notesBarInput: { flex: 1, color: '#FFFFFF', fontSize: 16, paddingVertical: 12 },
  notesGateIconSmall: { width: 64, height: 64, borderRadius: 32, marginBottom: 12 },
  notesGateBtnBar: { alignSelf: 'stretch', maxWidth: undefined, marginTop: 10 },
  notesBarDots: { flexDirection: 'row', gap: 9 },
  notesBarDot: { width: 10, height: 10, borderRadius: 5, backgroundColor: '#FFFFFF' },
  notesPadSheet: { marginTop: 10, marginHorizontal: -16, marginBottom: -12, paddingTop: 12, paddingBottom: 14, paddingHorizontal: 16, backgroundColor: '#15151B', borderTopLeftRadius: 16, borderTopRightRadius: 16, borderWidth: 1, borderBottomWidth: 0, borderColor: '#24242D', alignItems: 'center' },
  notesPadGrid: { flexDirection: 'row', flexWrap: 'wrap', justifyContent: 'center', width: '100%', maxWidth: 360, marginBottom: 8 },
  notesGateBtn: { width: '100%', maxWidth: 360, paddingVertical: 13, borderRadius: 11, backgroundColor: '#FFFFFF', alignItems: 'center' },
  notesGateBtnOff: { opacity: 0.35 },
  notesGateBtnTxt: { color: '#0B0B0F', fontWeight: '800', fontSize: 14 },
  secureBox: { borderWidth: 1, borderColor: '#FFFFFF', borderRadius: 10, padding: 12, marginHorizontal: 14, marginTop: 8, marginBottom: 4, backgroundColor: 'rgba(255,255,255,0.04)' },
  secureTitle: { color: '#FFFFFF', fontSize: 13, fontWeight: '800', marginBottom: 4 },
  secureTxt: { color: '#8E9696', fontSize: 11, lineHeight: 15 },
  secureBtn: { backgroundColor: '#FFFFFF', borderRadius: 8, paddingHorizontal: 12, paddingVertical: 8 },
  secureBtnTxt: { color: '#0B0B0F', fontWeight: '800', fontSize: 12 },
  secureBtnGhost: { borderWidth: 1, borderColor: '#3A3A44', borderRadius: 8, paddingHorizontal: 12, paddingVertical: 8 },
  secureBtnGhostTxt: { color: '#8E9696', fontSize: 12 },
  fill: { flex: 1, backgroundColor: '#0B0B0F' },
  // "VEIL nice and visible top-left" (Sept 19): bigger logo mark + wider
  // letter-spacing, matches the target mock's prominent wordmark.
  header: { flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between', paddingHorizontal: 20, paddingTop: 18, paddingBottom: 16, borderBottomWidth: 1, borderBottomColor: '#24242D' },
  brandRow: { flexDirection: 'row', alignItems: 'center' },
  logoSmall: { width: 34, height: 34, marginRight: 11 },
  logo: { color: '#FFFFFF', fontSize: 22, fontFamily: 'Menlo', fontWeight: '600', letterSpacing: 0.5 },
  signOut: { color: '#5E6464', fontSize: 13 },
  identityStrip: { paddingHorizontal: 20, paddingTop: 12, paddingBottom: 4 },
  // Owner request (Sept 19): Veil ID itself reads BLUE, the keychain
  // subtitle reads YELLOW (same yellow family as the Tools descriptions).
  veilId: { color: '#FFFFFF', fontSize: 12, letterSpacing: 0.5 },
  veilIdRow: { flexDirection: 'row', alignItems: 'center', gap: 6 },
  idDot: { width: 7, height: 7, borderRadius: 3.5, backgroundColor: '#35d07f' }, // b57 green status dot
  ok: { color: '#8a6d3b', fontSize: 11, marginTop: 3 },
  body: { flex: 1 },
  // Bottom icon tab bar (Sept 19): moved from top-of-screen text tabs to a
  // standard bottom nav bar with icon + label, matching the target mock.
  // SafeAreaView already wraps the whole app (b46 notch fix), so this bar
  // naturally clears the home-indicator area on notched iPhones.
  bottomBar: { flexDirection: 'row', borderTopWidth: 1, borderTopColor: '#24242D', backgroundColor: '#0B0B0F', paddingTop: 8, paddingBottom: 6 },
  bottomTab: { flex: 1, alignItems: 'center', gap: 3 },
  // b90: unread badge pinned to the top-right of the Chat tab icon
  tabBadge: { position: 'absolute', top: -6, right: -12, backgroundColor: '#FFFFFF', borderRadius: 9, minWidth: 18, paddingHorizontal: 5, paddingVertical: 2, alignItems: 'center', justifyContent: 'center' },
  tabBadgeText: { color: '#0B0B0F', fontSize: 10, fontWeight: '800' },
  bottomLabel: { color: '#5E6464', fontSize: 10, fontWeight: '600' },
  bottomLabelOn: { color: '#FFFFFF' },
});
