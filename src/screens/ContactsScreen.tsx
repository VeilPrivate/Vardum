import React, { useState } from 'react';
import {
  View, Text, TextInput, TouchableOpacity, StyleSheet, ScrollView, Share, ActivityIndicator,
} from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import { useThemedPrompt } from './ThemedPrompt';
import { QrScanner } from './QrScanner';
import { PERMISSION_DECLINED } from '../platformText';

export interface ContactRow {
  veilId: string;
  nickname: string | null;
  verified: boolean;
  fingerprint: string;
}

export interface LookupResult {
  veilId: string;
  fingerprint: string;
  ikPubB64: string;
}

/** b199: an anonymous (invite-link) chat offered when a contact has no contact chat */
export interface ContactChatChoice {
  token: string;
  title: string;
  subtitle: string;
}

/** b199: what creating a group / adding people produced */
export interface GroupInviteResult {
  groupName: string;
  /** backup links for people who aren't contacts (shared by hand) */
  inviteLinks: string[];
  /** contacts whose invite was delivered inside your encrypted chat */
  invited: string[];
  /** contacts whose chat isn't accepted yet — the invite sends automatically once it is */
  queued: string[];
  /** contacts whose invite could not be delivered */
  failed: string[];
}

export interface ContactsScreenProps {
  contacts: ContactRow[];
  busy: boolean;
  error: string | null;
  /** Look up a veil-id on the relay (public keys only). */
  onLookup: (veilId: string) => Promise<LookupResult | null>;
  /** Pin after the user confirms the safety code. */
  onPin: (lookup: LookupResult) => Promise<void>;
  /** b57: unpin — device-local trust anchor removal; two-tap confirm below. */
  onUnpin: (veilId: string) => Promise<void>;
  /** b199: open your existing chat with this contact. Never starts one
   *  silently: returns null when a chat opened, or the anonymous chats to
   *  offer when there is no contact chat yet (then the screen asks). */
  onOpenContact: (veilId: string, choice?: { open?: string; start?: boolean }) => Promise<ContactChatChoice[] | null>;
  /** Start a NEW chat with fresh keys (supersedes the old one, K-17). */
  onMessage: (veilId: string) => void;
  /** Mark "I compared the safety code" — verifies the pin. */
  onVerify: (veilId: string) => Promise<void>;
  /** Device-local nickname — never transmitted, never synced. */
  onSetNickname: (veilId: string, nickname: string) => void;
  /** b199 groups: create with pinned contacts (+ optional backup links) */
  onCreateGroup: (name: string, invitees: string[], linkCount: number) => Promise<GroupInviteResult>;
  /** b199 groups you created on this phone (the ones you can add people to) */
  myGroups: { groupToken: string; name: string }[];
  onAddGroupPeople: (groupToken: string, invitees: string[], linkCount: number) => Promise<GroupInviteResult>;
  /** b199 Veil QR: an add link was opened (camera scan or tapped link) — look
   *  this ID up and show the usual safety-code confirm. nonce re-triggers. */
  prefillAdd?: { veilId: string; nonce: number } | null;
}

/**
 * Contacts (b199 redesign, owner request Oct 16 2026): one clean list —
 * tap a contact to message them, ⋯ for everything else (safety code, rename,
 * fresh chat, remove). Groups are created by picking contacts; each invite
 * travels privately inside your encrypted chat and only works for that person.
 * Pinning is unchanged: the pinned key IS the identity, names stay on device.
 */

/**
 * b111 (owner directive: no raw internal errors on screen, ever): raw
 * exception text goes to the Metro console; the UI gets one human sentence.
 */
function friendlyError(e: unknown, what: string): string {
  const err = e as Error;
  console.log(`[veil-error] ${what}:`, String(err?.message ?? e), err?.stack ?? '');
  const s = String(err?.message ?? e).toLowerCase();
  if (s.includes('network') || s.includes('timeout') || s.includes('fetch') || s.includes('request failed'))
    return 'Connection problem — check your internet and try again.';
  if (s.includes('permission') || s.includes('denied') || s.includes('not authorized'))
    return PERMISSION_DECLINED;
  if (s.includes('rate limit'))
    // b175: the relay's anti-abuse limiter is a few-second self-healing cooldown
    return 'The server is briefly busy — wait a few seconds and try again.';
  if (s.includes('choose at least one') || s.includes('give the group a name') || s.includes('only the person who created'))
    return String(err?.message ?? e);
  return 'Something went wrong — please try again.';
}

const LINK_CHOICES = [0, 1, 2, 3, 5];

/** sheet for creating a group or adding people to one */
type GroupSheet = { mode: 'create' } | { mode: 'add'; groupToken: string; name: string };

export function ContactsScreen({
  contacts, busy, error, onLookup, onPin, onUnpin, onOpenContact, onMessage, onVerify, onSetNickname,
  onCreateGroup, myGroups, onAddGroupPeople, prefillAdd,
}: ContactsScreenProps) {
  const { node: promptNode, ask } = useThemedPrompt();
  // b199 Veil QR: in-app scanner overlay
  const [scanOpen, setScanOpen] = useState(false);
  const [lookupInput, setLookupInput] = useState('');
  const [lookupBusy, setLookupBusy] = useState(false);
  const [lookupErr, setLookupErr] = useState<string | null>(null);
  const [card, setCard] = useState<LookupResult | null>(null);
  const [sheetFor, setSheetFor] = useState<ContactRow | null>(null);
  const [unpinArm, setUnpinArm] = useState<string | null>(null);
  // groups
  const [groupSheet, setGroupSheet] = useState<GroupSheet | null>(null);
  const [groupName, setGroupName] = useState('');
  const [picked, setPicked] = useState<Set<string>>(new Set());
  const [linkCount, setLinkCount] = useState(0);
  const [showLinks, setShowLinks] = useState(false);
  const [groupBusy, setGroupBusy] = useState(false);
  const [groupErr, setGroupErr] = useState<string | null>(null);
  const [groupDone, setGroupDone] = useState<GroupInviteResult | null>(null);

  const nameOf = (c: ContactRow) => c.nickname || c.veilId;

  // b199: "which chat?" — shown when a contact has no contact chat yet
  const [chooseFor, setChooseFor] = useState<{ contact: ContactRow; anon: ContactChatChoice[] } | null>(null);
  const [openBusy, setOpenBusy] = useState(false);
  const openContact = async (c: ContactRow) => {
    if (openBusy) return;
    setOpenBusy(true);
    try {
      const anon = await onOpenContact(c.veilId);
      if (anon) setChooseFor({ contact: c, anon });
    } catch (e) {
      setLookupErr(friendlyError(e, 'open-contact'));
    } finally { setOpenBusy(false); }
  };
  const choose = async (choice: { open?: string; start?: boolean }) => {
    if (!chooseFor) return;
    const v = chooseFor.contact.veilId;
    setChooseFor(null);
    try { await onOpenContact(v, choice); } catch (e) { setLookupErr(friendlyError(e, 'open-contact')); }
  };

  /** web parity: two-tap remove — first tap arms the button for 6 s. */
  const doUnpin = async (veilId: string) => {
    if (unpinArm === veilId) {
      setUnpinArm(null);
      setSheetFor(null);
      try { await onUnpin(veilId); } catch { /* surfaced by parent */ }
      return;
    }
    setUnpinArm(veilId);
    setTimeout(() => setUnpinArm((a) => (a === veilId ? null : a)), 6000);
  };

  const doLookup = async (id?: string) => {
    setLookupBusy(true); setLookupErr(null);
    try {
      const r = await onLookup((id ?? lookupInput).trim());
      if (r) setCard(r); else setLookupErr('No Vardum identity matches that ID.');
    } catch (e) {
      setLookupErr(friendlyError(e, 'lookup'));
    } finally { setLookupBusy(false); }
  };

  // b199 Veil QR: an opened add link runs the same lookup → safety-code
  // confirm as typing the ID. Nothing is pinned until the user confirms.
  React.useEffect(() => {
    if (!prefillAdd?.veilId) return;
    setLookupInput(prefillAdd.veilId);
    void doLookup(prefillAdd.veilId);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [prefillAdd?.nonce]);

  const openGroupSheet = (g: GroupSheet) => {
    setGroupSheet(g); setGroupName(''); setPicked(new Set()); setLinkCount(0); setShowLinks(false); setGroupErr(null); setGroupDone(null);
  };
  const togglePick = (veilId: string) => setPicked((cur) => {
    const next = new Set(cur);
    if (next.has(veilId)) next.delete(veilId); else next.add(veilId);
    return next;
  });
  const submitGroup = async () => {
    if (!groupSheet) return;
    setGroupBusy(true); setGroupErr(null);
    try {
      const r = groupSheet.mode === 'create'
        ? await onCreateGroup(groupName, [...picked], linkCount)
        : await onAddGroupPeople(groupSheet.groupToken, [...picked], linkCount);
      setGroupDone(r);
    } catch (e) {
      setGroupErr(friendlyError(e, 'group'));
    } finally { setGroupBusy(false); }
  };

  const renameContact = async (c: ContactRow) => {
    const t = (await ask({
      title: 'Name this contact',
      message: 'Stored on this phone only. Never sent, never synced, never on the server.',
      input: 'text', defaultValue: c.nickname ?? '', placeholder: 'Jo', submitLabel: 'Save',
    })) as string | null;
    if (t === null) return;
    onSetNickname(c.veilId, t.trim());
    setSheetFor(null);
  };

  return (
    <View style={styles.fill}>
      <ScrollView style={styles.fill} contentContainerStyle={styles.wrap} keyboardShouldPersistTaps="handled">
        <Text style={styles.h1}>Contacts</Text>

        {/* ---- Add a contact (b119: easy to find; now one compact row) ---- */}
        <View style={styles.addRow}>
          <TextInput
            style={styles.addInput}
            autoCapitalize="none"
            autoCorrect={false}
            placeholder="Paste a Vardum ID"
            placeholderTextColor="#5E6464"
            value={lookupInput}
            editable={!lookupBusy}
            onChangeText={(t) => { setLookupInput(t); setLookupErr(null); }}
          />
          <TouchableOpacity
            style={[styles.addBtn, lookupInput.length < 8 && styles.btnDisabled]}
            disabled={lookupInput.length < 8 || lookupBusy}
            onPress={() => { void doLookup(); }}
          >
            {lookupBusy ? <ActivityIndicator color="#0B0B0F" /> : <Text style={styles.addBtnText}>Add</Text>}
          </TouchableOpacity>
          {/* b199 Veil QR: scan someone's QR in the app (same lookup + confirm) */}
          <TouchableOpacity style={styles.scanBtn} onPress={() => setScanOpen(true)} disabled={lookupBusy} accessibilityLabel="Scan a Vardum QR">
            <Ionicons name="qr-code-outline" size={20} color="#FFFFFF" />
          </TouchableOpacity>
        </View>
        {lookupErr ? <Text style={styles.err}>{lookupErr}</Text> : null}
        {error ? <Text style={styles.err}>{error}</Text> : null}

        {/* ---- Your contacts ---- */}
        <Text style={styles.groupTitle}>Your contacts{contacts.length > 0 ? ` (${contacts.length})` : ''}</Text>
        {contacts.length === 0 ? (
          <View style={styles.group}>
            <Text style={styles.empty}>No contacts yet. Ask someone for their Vardum ID and add it above. Once added, you can message them in one tap.</Text>
          </View>
        ) : (
          <View style={styles.group}>
            {contacts.map((c, i) => (
              <View key={c.veilId} style={[styles.row, i === contacts.length - 1 && styles.rowLast]}>
                <TouchableOpacity style={styles.rowMain} onPress={() => { void openContact(c); }} disabled={busy || openBusy} activeOpacity={0.7}>
                  <View style={[styles.avatar, c.verified && styles.avatarV]}>
                    <Text style={styles.avatarText}>{nameOf(c).slice(0, 2).toUpperCase()}</Text>
                  </View>
                  <View style={styles.rowBody}>
                    <Text style={[styles.name, !c.nickname && styles.nameId]} numberOfLines={1}>{nameOf(c)}</Text>
                    <Text style={c.verified ? styles.verified : styles.unverified}>{c.verified ? 'Verified' : 'Not verified yet'}</Text>
                  </View>
                </TouchableOpacity>
                <TouchableOpacity style={styles.more} onPress={() => setSheetFor(c)} accessibilityLabel={`More for ${nameOf(c)}`}>
                  <Text style={styles.moreTxt}>⋯</Text>
                </TouchableOpacity>
              </View>
            ))}
          </View>
        )}
        <Text style={styles.note}>Tap a contact to message them. Names you give contacts stay on this phone.</Text>

        {/* ---- Groups ---- */}
        <Text style={styles.groupTitle}>Groups</Text>
        <View style={styles.group}>
          <TouchableOpacity style={[styles.row, myGroups.length === 0 && styles.rowLast]} onPress={() => openGroupSheet({ mode: 'create' })}>
            <Text style={styles.accentRow}>Create a group</Text>
            <Text style={styles.chev}>›</Text>
          </TouchableOpacity>
          {myGroups.map((g, i) => (
            <TouchableOpacity key={g.groupToken} style={[styles.row, i === myGroups.length - 1 && styles.rowLast]} onPress={() => openGroupSheet({ mode: 'add', groupToken: g.groupToken, name: g.name })}>
              <View style={styles.rowBody}>
                <Text style={styles.name} numberOfLines={1}>{g.name}</Text>
                <Text style={styles.sub}>Add people</Text>
              </View>
              <Text style={styles.chev}>›</Text>
            </TouchableOpacity>
          ))}
        </View>
        <Text style={styles.note}>Up to 100 members. Invites go privately inside your encrypted chat with each person, and only work for them.</Text>
      </ScrollView>

      {/* ---- contact sheet (⋯) ---- */}
      {sheetFor ? (
        <View style={styles.backdrop}>
          <TouchableOpacity style={StyleSheet.absoluteFill} activeOpacity={1} onPress={() => setSheetFor(null)} />
          <View style={styles.sheet}>
            <View style={styles.sheetHead}>
              <View style={[styles.avatar, sheetFor.verified && styles.avatarV]}>
                <Text style={styles.avatarText}>{nameOf(sheetFor).slice(0, 2).toUpperCase()}</Text>
              </View>
              <View style={styles.rowBody}>
                <Text style={styles.name} numberOfLines={1}>{nameOf(sheetFor)}</Text>
                <Text style={styles.idTxt} numberOfLines={1} selectable>{sheetFor.veilId}</Text>
              </View>
            </View>
            <TouchableOpacity style={styles.primary} onPress={() => { const c = sheetFor; setSheetFor(null); void openContact(c); }} disabled={busy || openBusy}>
              <Text style={styles.primaryTxt}>Message</Text>
            </TouchableOpacity>
            <Text style={styles.label}>Safety code</Text>
            <Text style={styles.code} selectable>{sheetFor.fingerprint}</Text>
            {sheetFor.verified ? (
              <Text style={styles.verified}>✓ You've compared this code</Text>
            ) : (
              <>
                <Text style={styles.hint}>Compare this with {nameOf(sheetFor)} in person or on a call. If it matches, nobody is in the middle.</Text>
                <TouchableOpacity style={styles.secondary} onPress={async () => { await onVerify(sheetFor.veilId); setSheetFor({ ...sheetFor, verified: true }); }} disabled={busy}>
                  <Text style={styles.secondaryTxt}>I've compared it</Text>
                </TouchableOpacity>
              </>
            )}
            <TouchableOpacity style={styles.secondary} onPress={() => { void renameContact(sheetFor); }}>
              <Text style={styles.secondaryTxt}>{sheetFor.nickname ? 'Rename' : 'Give a name'}</Text>
            </TouchableOpacity>
            <TouchableOpacity style={styles.secondary} onPress={() => { const v = sheetFor.veilId; setSheetFor(null); onMessage(v); }} disabled={busy}>
              <Text style={styles.secondaryTxt}>Start a fresh chat</Text>
              <Text style={styles.secondarySub}>New keys; your current chat with them ends</Text>
            </TouchableOpacity>
            <TouchableOpacity style={[styles.secondary, unpinArm === sheetFor.veilId && styles.dangerArmed]} onPress={() => { void doUnpin(sheetFor.veilId); }} disabled={busy}>
              <Text style={styles.dangerTxt}>{unpinArm === sheetFor.veilId ? 'Tap again to remove' : 'Remove contact'}</Text>
            </TouchableOpacity>
            <TouchableOpacity style={styles.close} onPress={() => setSheetFor(null)}>
              <Text style={styles.closeTxt}>Close</Text>
            </TouchableOpacity>
          </View>
        </View>
      ) : null}

      {/* ---- b199 "which chat?" — no contact chat yet; never start one silently ---- */}
      {chooseFor ? (
        <View style={styles.backdrop}>
          <TouchableOpacity style={StyleSheet.absoluteFill} activeOpacity={1} onPress={() => setChooseFor(null)} />
          <View style={[styles.sheet, styles.sheetTall]}>
            <ScrollView bounces={false}>
              <Text style={styles.sheetTitle}>No chat with {nameOf(chooseFor.contact)} yet</Text>
              {chooseFor.anon.length ? (
                <>
                  <Text style={styles.hint}>
                    You have {chooseFor.anon.length === 1 ? 'a chat' : `${chooseFor.anon.length} chats`} started from an invite link. Those chats aren't linked to a contact, so Vardum can't tell who they're with. If one is with {nameOf(chooseFor.contact)}, open it instead of starting another.
                  </Text>
                  <View style={styles.pickList}>
                    {chooseFor.anon.map((a) => (
                      <TouchableOpacity key={a.token} style={styles.pickRow} onPress={() => { void choose({ open: a.token }); }}>
                        <View style={styles.rowBody}>
                          <Text style={styles.pickName} numberOfLines={1}>{a.title}</Text>
                          {a.subtitle ? <Text style={styles.sub} numberOfLines={1}>{a.subtitle}</Text> : null}
                        </View>
                        <Text style={styles.chev}>›</Text>
                      </TouchableOpacity>
                    ))}
                  </View>
                </>
              ) : (
                <Text style={styles.hint}>Start a private chat with {nameOf(chooseFor.contact)}? It uses the keys you pinned for them.</Text>
              )}
              <TouchableOpacity style={styles.primary} onPress={() => { void choose({ start: true }); }} disabled={busy}>
                <Text style={styles.primaryTxt}>Start a new chat with {nameOf(chooseFor.contact)}</Text>
              </TouchableOpacity>
              <TouchableOpacity style={styles.close} onPress={() => setChooseFor(null)}>
                <Text style={styles.closeTxt}>Cancel</Text>
              </TouchableOpacity>
            </ScrollView>
          </View>
        </View>
      ) : null}

      {/* ---- group sheet: create / add people ---- */}
      {groupSheet ? (
        <View style={styles.backdrop}>
          <TouchableOpacity style={StyleSheet.absoluteFill} activeOpacity={1} onPress={() => { if (!groupBusy) setGroupSheet(null); }} />
          <View style={[styles.sheet, styles.sheetTall]}>
            {groupDone ? (
              <ScrollView bounces={false}>
                <Text style={styles.sheetTitle}>{groupDone.groupName} {groupSheet.mode === 'create' ? 'is ready' : 'updated'}</Text>
                {groupDone.invited.length ? (
                  <Text style={styles.hint}>
                    Invites sent to {groupDone.invited.map((v) => nameOf(contacts.find((c) => c.veilId === v) ?? { veilId: v, nickname: null, verified: false, fingerprint: '' })).join(', ')}. They'll see a Join button in your chat with them.
                  </Text>
                ) : null}
                {groupDone.queued.length ? (
                  <Text style={styles.hint}>
                    {groupDone.queued.map((v) => nameOf(contacts.find((c) => c.veilId === v) ?? { veilId: v, nickname: null, verified: false, fingerprint: '' })).join(', ')} {groupDone.queued.length === 1 ? 'needs' : 'need'} to accept a chat with you, and you both need to confirm its safety code, first. Their invite will be sent automatically as soon as that’s done. Keep Vardum open for a moment, or it sends next time you open the app.
                  </Text>
                ) : null}
                {groupDone.failed.length ? (
                  <Text style={styles.err}>
                    Couldn't reach {groupDone.failed.map((v) => nameOf(contacts.find((c) => c.veilId === v) ?? { veilId: v, nickname: null, verified: false, fingerprint: '' })).join(', ')}. Try adding them again in a moment.
                  </Text>
                ) : null}
                {groupDone.inviteLinks.length ? (
                  <>
                    <Text style={styles.label}>Invite links</Text>
                    <Text style={styles.hint}>Give each link to one person. Anyone holding a link can join, so share them only in person or over a channel you trust.</Text>
                    {groupDone.inviteLinks.map((lnk, i) => (
                      <View key={i} style={styles.linkRow}>
                        <Text style={styles.linkTxt} numberOfLines={1}>{lnk}</Text>
                        <TouchableOpacity style={styles.shareBtn} onPress={() => Share.share({ message: lnk }).catch(() => {})}>
                          <Text style={styles.shareBtnTxt}>Share</Text>
                        </TouchableOpacity>
                      </View>
                    ))}
                  </>
                ) : null}
                <TouchableOpacity style={styles.primary} onPress={() => setGroupSheet(null)}>
                  <Text style={styles.primaryTxt}>Done</Text>
                </TouchableOpacity>
              </ScrollView>
            ) : (
              <ScrollView bounces={false} keyboardShouldPersistTaps="handled">
                <Text style={styles.sheetTitle}>{groupSheet.mode === 'create' ? 'Create a group' : `Add people to ${groupSheet.name}`}</Text>
                {groupSheet.mode === 'create' ? (
                  <TextInput
                    style={styles.input}
                    autoCapitalize="words"
                    autoCorrect={false}
                    placeholder="Group name"
                    placeholderTextColor="#5E6464"
                    value={groupName}
                    maxLength={40}
                    editable={!groupBusy}
                    onChangeText={(t) => { setGroupName(t); setGroupErr(null); }}
                  />
                ) : null}
                <Text style={styles.label}>Choose contacts</Text>
                {contacts.length === 0 ? (
                  <Text style={styles.hint}>Add contacts first, or use an invite link below.</Text>
                ) : (
                  <View style={styles.pickList}>
                    {contacts.map((c) => {
                      const on = picked.has(c.veilId);
                      return (
                        <TouchableOpacity key={c.veilId} style={styles.pickRow} onPress={() => togglePick(c.veilId)} disabled={groupBusy}>
                          <View style={[styles.check, on && styles.checkOn]}>{on ? <Text style={styles.checkTick}>✓</Text> : null}</View>
                          <Text style={styles.pickName} numberOfLines={1}>{nameOf(c)}</Text>
                          <Text style={c.verified ? styles.verified : styles.unverified}>{c.verified ? 'Verified' : 'Not verified'}</Text>
                        </TouchableOpacity>
                      );
                    })}
                  </View>
                )}
                {showLinks ? (
                  <>
                    <Text style={styles.label}>Invite links for people who aren't contacts</Text>
                    <View style={styles.countRow}>
                      {LINK_CHOICES.map((n) => (
                        <TouchableOpacity key={n} style={[styles.countBtn, linkCount === n && styles.countOn]} onPress={() => setLinkCount(n)} disabled={groupBusy}>
                          <Text style={[styles.countTxt, linkCount === n && styles.countTxtOn]}>{n === 0 ? 'None' : n}</Text>
                        </TouchableOpacity>
                      ))}
                    </View>
                  </>
                ) : (
                  <TouchableOpacity onPress={() => setShowLinks(true)}>
                    <Text style={styles.linkToggle}>Invite with a link instead</Text>
                  </TouchableOpacity>
                )}
                {groupErr ? <Text style={styles.err}>{groupErr}</Text> : null}
                <TouchableOpacity
                  style={[styles.primary, (groupBusy || (groupSheet.mode === 'create' && !groupName.trim()) || (picked.size + linkCount === 0)) && styles.btnDisabled]}
                  disabled={groupBusy || (groupSheet.mode === 'create' && !groupName.trim()) || picked.size + linkCount === 0}
                  onPress={() => { void submitGroup(); }}
                >
                  {groupBusy ? <ActivityIndicator color="#0B0B0F" /> : (
                    <Text style={styles.primaryTxt}>
                      {groupSheet.mode === 'create' ? 'Create and send invites' : 'Send invites'}
                      {picked.size ? ` (${picked.size})` : ''}
                    </Text>
                  )}
                </TouchableOpacity>
                <TouchableOpacity style={styles.close} onPress={() => setGroupSheet(null)} disabled={groupBusy}>
                  <Text style={styles.closeTxt}>Cancel</Text>
                </TouchableOpacity>
              </ScrollView>
            )}
          </View>
        </View>
      ) : null}

      {/* ---- add-contact safety-code confirm ---- */}
      {card ? (
        <View style={styles.backdrop}>
          <TouchableOpacity style={StyleSheet.absoluteFill} activeOpacity={1} onPress={() => setCard(null)} />
          <View style={styles.sheet}>
            <Text style={styles.sheetTitle}>Add this contact?</Text>
            <Text style={styles.hint}>Compare this safety code with them over a channel you trust. Adding them means this key is their identity from now on.</Text>
            <Text style={styles.code} selectable>{card.fingerprint}</Text>
            <TouchableOpacity
              style={styles.primary}
              onPress={async () => {
                if (!card) return;
                await onPin(card);
                setCard(null); setLookupInput('');
              }}
            >
              <Text style={styles.primaryTxt}>Add contact</Text>
            </TouchableOpacity>
            <TouchableOpacity style={styles.close} onPress={() => setCard(null)}>
              <Text style={styles.closeTxt}>Cancel</Text>
            </TouchableOpacity>
          </View>
        </View>
      ) : null}
      {promptNode}
      {scanOpen ? (
        <QrScanner
          onClose={() => setScanOpen(false)}
          onFound={(id) => { setScanOpen(false); setLookupInput(id); void doLookup(id); }}
        />
      ) : null}
    </View>
  );
}

const styles = StyleSheet.create({
  fill: { flex: 1 },
  wrap: { padding: 16, paddingBottom: 40 },
  h1: { color: '#FFFFFF', fontSize: 22, fontWeight: '700', marginBottom: 12, marginLeft: 4 },
  addRow: { flexDirection: 'row', backgroundColor: '#15151B', borderWidth: 1, borderColor: '#24242D', borderRadius: 12, padding: 8 },
  addInput: { flex: 1, color: '#FFFFFF', backgroundColor: '#0B0B0F', borderWidth: 1, borderColor: '#24242D', borderRadius: 9, paddingHorizontal: 12, paddingVertical: 9, fontSize: 14 },
  addBtn: { marginLeft: 8, backgroundColor: '#FFFFFF', borderRadius: 9, paddingHorizontal: 18, alignItems: 'center', justifyContent: 'center' },
  addBtnText: { color: '#0B0B0F', fontWeight: '800', fontSize: 14 },
  scanBtn: { marginLeft: 8, width: 44, borderRadius: 9, borderWidth: 1, borderColor: '#3A3A44', alignItems: 'center', justifyContent: 'center', backgroundColor: 'rgba(255,255,255,0.06)' },
  btnDisabled: { opacity: 0.35 },
  groupTitle: { color: '#FFFFFF', fontSize: 11, fontWeight: '800', letterSpacing: 0.8, textTransform: 'uppercase', marginTop: 20, marginBottom: 6, marginLeft: 6 },
  group: { backgroundColor: '#15151B', borderWidth: 1, borderColor: '#24242D', borderRadius: 12, overflow: 'hidden' },
  note: { color: '#8E9696', fontSize: 11, lineHeight: 16, marginTop: 6, marginHorizontal: 6 },
  empty: { color: '#8E9696', fontSize: 13, lineHeight: 19, padding: 14 },
  row: { flexDirection: 'row', alignItems: 'center', paddingHorizontal: 12, paddingVertical: 10, borderBottomWidth: 1, borderBottomColor: '#24242D', minHeight: 56 },
  rowLast: { borderBottomWidth: 0 },
  rowMain: { flex: 1, flexDirection: 'row', alignItems: 'center' },
  rowBody: { flex: 1, minWidth: 0 },
  avatar: { width: 38, height: 38, borderRadius: 19, backgroundColor: '#24242D', alignItems: 'center', justifyContent: 'center', marginRight: 12 },
  avatarV: { backgroundColor: '#24242D' },
  avatarText: { color: '#FFFFFF', fontSize: 13, fontWeight: '700' },
  name: { color: '#FFFFFF', fontSize: 15, fontWeight: '600' },
  nameId: { fontFamily: 'monospace', fontSize: 13 },
  sub: { color: '#8E9696', fontSize: 12, marginTop: 2 },
  verified: { color: '#FFFFFF', fontSize: 12, marginTop: 2 },
  unverified: { color: '#d69a5c', fontSize: 12, marginTop: 2 },
  more: { paddingHorizontal: 10, paddingVertical: 8 },
  moreTxt: { color: '#8E9696', fontSize: 20, fontWeight: '700' },
  accentRow: { flex: 1, color: '#FFFFFF', fontSize: 15, fontWeight: '600' },
  chev: { color: '#4A4A54', fontSize: 20, marginLeft: 8 },
  err: { color: '#ff8f8f', fontSize: 12, marginTop: 8, marginHorizontal: 6 },
  // overlay sheets (same pattern as ThemedPrompt — no RN Modal, b25 freeze)
  backdrop: { ...StyleSheet.absoluteFillObject, backgroundColor: 'rgba(11,11,15,0.86)', justifyContent: 'center', alignItems: 'center', padding: 20, zIndex: 80 },
  sheet: { width: '100%', maxWidth: 440, backgroundColor: '#15151B', borderRadius: 16, borderWidth: 1, borderColor: '#24242D', padding: 18 },
  sheetTall: { maxHeight: '90%' },
  sheetHead: { flexDirection: 'row', alignItems: 'center', marginBottom: 6 },
  sheetTitle: { color: '#FFFFFF', fontSize: 17, fontWeight: '800', marginBottom: 8 },
  idTxt: { color: '#8E9696', fontSize: 11, fontFamily: 'monospace', marginTop: 2 },
  label: { color: '#FFFFFF', fontSize: 11, fontWeight: '800', letterSpacing: 0.6, textTransform: 'uppercase', marginTop: 14, marginBottom: 6 },
  hint: { color: '#d69a5c', fontSize: 12, lineHeight: 17, marginBottom: 8 },
  code: { color: '#FFFFFF', fontSize: 14, letterSpacing: 1, fontFamily: 'monospace', backgroundColor: '#0B0B0F', borderRadius: 10, borderWidth: 1, borderColor: '#3A3A44', padding: 12, marginBottom: 8 },
  primary: { backgroundColor: '#FFFFFF', borderRadius: 11, paddingVertical: 12, alignItems: 'center', marginTop: 12 },
  primaryTxt: { color: '#0B0B0F', fontWeight: '800', fontSize: 14 },
  secondary: { borderWidth: 1, borderColor: '#24242D', borderRadius: 11, paddingVertical: 11, paddingHorizontal: 12, alignItems: 'center', marginTop: 8 },
  secondaryTxt: { color: '#C9CFCE', fontSize: 14, fontWeight: '600' },
  secondarySub: { color: '#8E9696', fontSize: 11, marginTop: 2 },
  dangerTxt: { color: '#e8836f', fontSize: 14, fontWeight: '600' },
  dangerArmed: { borderColor: '#5c2a24' },
  close: { paddingVertical: 12, alignItems: 'center', marginTop: 4 },
  closeTxt: { color: '#8E9696', fontSize: 13, fontWeight: '600' },
  input: { color: '#FFFFFF', backgroundColor: '#0B0B0F', borderWidth: 1, borderColor: '#24242D', borderRadius: 10, paddingHorizontal: 12, paddingVertical: 10, fontSize: 15, marginBottom: 4 },
  pickList: { borderWidth: 1, borderColor: '#24242D', borderRadius: 10, overflow: 'hidden' },
  pickRow: { flexDirection: 'row', alignItems: 'center', paddingHorizontal: 12, paddingVertical: 11, borderBottomWidth: 1, borderBottomColor: '#24242D' },
  pickName: { flex: 1, color: '#FFFFFF', fontSize: 14, marginRight: 8 },
  check: { width: 22, height: 22, borderRadius: 6, borderWidth: 1, borderColor: '#3A3A44', alignItems: 'center', justifyContent: 'center', marginRight: 12 },
  checkOn: { borderColor: '#FFFFFF', backgroundColor: 'rgba(255,255,255,0.14)' },
  checkTick: { color: '#FFFFFF', fontSize: 13, fontWeight: '800' },
  linkToggle: { color: '#FFFFFF', fontSize: 13, marginTop: 14, textDecorationLine: 'underline' },
  countRow: { flexDirection: 'row', flexWrap: 'wrap', gap: 8 },
  countBtn: { borderWidth: 1, borderColor: '#3A3A44', borderRadius: 8, paddingHorizontal: 14, paddingVertical: 8 },
  countOn: { borderColor: '#FFFFFF', backgroundColor: 'rgba(255,255,255,0.12)' },
  countTxt: { color: '#8E9696', fontSize: 13, fontWeight: '600' },
  countTxtOn: { color: '#FFFFFF' },
  linkRow: { flexDirection: 'row', alignItems: 'center', borderWidth: 1, borderColor: '#24242D', borderRadius: 9, paddingLeft: 10, paddingVertical: 4, paddingRight: 4, marginBottom: 6 },
  linkTxt: { flex: 1, color: '#8E9696', fontSize: 11, marginRight: 8 },
  shareBtn: { backgroundColor: '#FFFFFF', borderRadius: 8, paddingHorizontal: 14, paddingVertical: 7 },
  shareBtnTxt: { color: '#0B0B0F', fontWeight: '800', fontSize: 12 },
});
