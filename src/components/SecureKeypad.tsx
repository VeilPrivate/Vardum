/**
 * SecureKeypad — Vardum's own on-screen keyboard for secret fields.
 *
 * Owner (Oct 18, device testing): "I don't want any information from outside
 * coming in." Every textContentType we tried on the phone's own keyboard still
 * let iOS offer something — "Use Strong Password", then email addresses, then
 * one-time codes. A system keyboard also means a third-party keyboard (if one
 * is installed) sees every character of the password. So secret fields no
 * longer use a native text box at all:
 *
 *  - SecureInput draws the field itself (dots, or plain words for the recovery
 *    phrase). It is ordinary Text, so there is nothing for iOS/Android AutoFill,
 *    QuickType, keyboard learning, copy or paste to attach to.
 *  - SecureKeypad is the keyboard: lower/upper case, digits, common symbols,
 *    space, backspace, done. No autocapitalisation (passphrases are typed
 *    exactly), no suggestions, no key preview bubble.
 *  - SecureKeypadHost docks the keypad at the bottom of a screen, where the
 *    phone keyboard would be, and binds it to whichever SecureInput is active.
 *    A SecureInput without a host shows the keypad right under itself.
 *
 * The typed value lives only in React state (the caller's useState, exactly as
 * it did with TextInput) — never in a native text view, the pasteboard or the OS.
 */
import React, { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react';
import { View, Text, Pressable, StyleSheet, Keyboard, type StyleProp, type ViewStyle, type TextStyle } from 'react-native';
import { Ionicons } from '@expo/vector-icons';

/** 'password': full keyboard, masked. 'phrase': lowercase letters + space only (24-word recovery phrase). */
export type KeypadVariant = 'password' | 'phrase';
type Layer = 'letters' | 'numbers' | 'symbols';
type Shift = 'off' | 'once' | 'lock';

const LETTERS = [
  ['q', 'w', 'e', 'r', 't', 'y', 'u', 'i', 'o', 'p'],
  ['a', 's', 'd', 'f', 'g', 'h', 'j', 'k', 'l'],
  ['z', 'x', 'c', 'v', 'b', 'n', 'm'],
];
const NUMBERS = [
  ['1', '2', '3', '4', '5', '6', '7', '8', '9', '0'],
  ['-', '/', ':', ';', '(', ')', '$', '&', '@', '"'],
  ['.', ',', '?', '!', "'"],
];
const SYMBOLS = [
  ['[', ']', '{', '}', '#', '%', '^', '*', '+', '='],
  ['_', '\\', '|', '~', '<', '>', '€', '£', '¥', '`'],
  ['.', ',', '?', '!', "'"],
];

interface Binding {
  value: string;
  onChange: (v: string) => void;
  onDone?: () => void;
  stayOpen?: boolean;
  maxLength: number;
  variant: KeypadVariant;
  disabled?: boolean;
  doneLabel?: string;
  initialLayer?: Layer;
}

interface HostApi {
  activeId: string | null;
  open: (id: string, binding: React.MutableRefObject<Binding>) => void;
  close: (id: string) => void;
  refresh: () => void;
}

const HostCtx = createContext<HostApi | null>(null);

/** Array.from counts a symbol like € (one code point) as one character */
const chars = (v: string) => Array.from(v);

/* ------------------------------- keypad -------------------------------- */

export function SecureKeypad({ binding, onClose }: { binding: React.MutableRefObject<Binding>; onClose: () => void }) {
  const b = binding.current;
  const [layer, setLayer] = useState<Layer>(b.initialLayer ?? 'letters');
  const [shift, setShift] = useState<Shift>('off');
  const repeat = useRef<ReturnType<typeof setInterval> | null>(null);
  const stopRepeat = () => { if (repeat.current) { clearInterval(repeat.current); repeat.current = null; } };
  useEffect(() => stopRepeat, []);

  // every key reads binding.current at press time, so the keypad never holds
  // (or needs a redraw for) a copy of the value
  const type = (ch: string) => {
    const cur = binding.current;
    if (cur.disabled || chars(cur.value).length >= cur.maxLength) return;
    cur.onChange(cur.value + ch);
  };
  const backspace = () => {
    const cur = binding.current;
    if (cur.disabled || cur.value.length === 0) { stopRepeat(); return; }
    cur.onChange(chars(cur.value).slice(0, -1).join(''));
  };
  const done = () => {
    const cur = binding.current;
    if (cur.disabled) return;
    cur.onDone?.();
    if (!cur.stayOpen) onClose();
  };
  const letter = (ch: string) => {
    type(shift === 'off' ? ch : ch.toUpperCase());
    if (shift === 'once') setShift('off');
  };

  const phrase = b.variant === 'phrase';
  const rows = layer === 'letters' ? LETTERS : layer === 'numbers' ? NUMBERS : SYMBOLS;

  return (
    <View style={[s.pad, b.disabled && s.padOff]} accessibilityLabel="Vardum keyboard">
      {rows.map((row, ri) => (
        <View key={ri} style={s.row}>
          {ri === 2 && !phrase ? (
            layer === 'letters' ? (
              <Key wide special on={shift !== 'off'} label={shift === 'lock' ? '⇪' : '⇧'}
                a11y={shift === 'lock' ? 'Caps lock on' : shift === 'once' ? 'Shift on' : 'Shift'}
                onPress={() => setShift((v) => (v === 'off' ? 'once' : v === 'once' ? 'lock' : 'off'))} />
            ) : (
              <Key wide special label={layer === 'numbers' ? '#+=' : '123'} a11y={layer === 'numbers' ? 'More symbols' : 'Numbers'}
                onPress={() => setLayer(layer === 'numbers' ? 'symbols' : 'numbers')} />
            )
          ) : null}
          {ri === 1 && layer === 'letters' ? <View style={s.half} /> : null}
          {row.map((ch) => (
            <Key key={ch} label={layer === 'letters' && shift !== 'off' ? ch.toUpperCase() : ch}
              onPress={() => (layer === 'letters' ? letter(ch) : type(ch))} />
          ))}
          {ri === 1 && layer === 'letters' ? <View style={s.half} /> : null}
          {ri === 2 ? (
            <Key wide special a11y="Delete" icon="backspace-outline" onPress={backspace}
              onLongPress={() => { stopRepeat(); repeat.current = setInterval(backspace, 90); }} onPressOut={stopRepeat} />
          ) : null}
        </View>
      ))}
      <View style={[s.row, s.rowLast]}>
        {!phrase ? (
          <Key wide special label={layer === 'letters' ? '123' : 'ABC'} a11y={layer === 'letters' ? 'Numbers and symbols' : 'Letters'}
            onPress={() => { setLayer(layer === 'letters' ? 'numbers' : 'letters'); setShift('off'); }} />
        ) : null}
        <Key space label="space" a11y="Space" onPress={() => type(' ')} />
        <Key done label={b.doneLabel ?? 'Done'} onPress={done} />
      </View>
    </View>
  );
}

function Key({ label, icon, a11y, onPress, onLongPress, onPressOut, wide, special, space, done, on }: {
  label?: string;
  icon?: React.ComponentProps<typeof Ionicons>['name'];
  a11y?: string;
  onPress: () => void;
  onLongPress?: () => void;
  onPressOut?: () => void;
  wide?: boolean; special?: boolean; space?: boolean; done?: boolean; on?: boolean;
}) {
  return (
    <Pressable
      onPress={onPress}
      onLongPress={onLongPress}
      onPressOut={onPressOut}
      delayLongPress={350}
      accessibilityRole="keyboardkey"
      accessibilityLabel={a11y ?? label}
      style={({ pressed }) => [
        s.key, wide && s.keyWide, space && s.keySpace,
        special && s.keySpecial, done && s.keyDone, on && s.keyOn,
        pressed && (done ? s.keyDonePressed : s.keyPressed),
      ]}
    >
      {icon ? <Ionicons name={icon} size={22} color="#FFFFFF" /> : (
        <Text style={[s.keyTxt, (wide || space || done) && s.keyTxtSmall, done && s.keyTxtDone, on && s.keyTxtOn]} allowFontScaling={false}>{label}</Text>
      )}
    </Pressable>
  );
}

/* -------------------------------- host --------------------------------- */

/**
 * Wrap a screen (or the part of it above a tab bar) in this. Children fill the
 * space above; the keypad sits underneath while a SecureInput is active, so a
 * ScrollView above shrinks exactly as it did for the phone keyboard.
 */
export function SecureKeypadHost({ children, style }: { children: React.ReactNode; style?: StyleProp<ViewStyle> }) {
  const [active, setActive] = useState<{ id: string; binding: React.MutableRefObject<Binding>; n: number } | null>(null);
  const open = useCallback((id: string, binding: React.MutableRefObject<Binding>) => {
    Keyboard.dismiss(); // a plain text field elsewhere on the screen may have the phone keyboard up
    setActive((cur) => (cur && cur.id === id ? cur : { id, binding, n: 0 }));
  }, []);
  const close = useCallback((id: string) => setActive((cur) => (cur && cur.id === id ? null : cur)), []);
  const refresh = useCallback(() => setActive((cur) => (cur ? { ...cur, n: cur.n + 1 } : cur)), []);
  // tapping a plain text field on the same screen (e.g. the email box) brings
  // up the phone keyboard — never show both, so the Vardum keypad steps aside
  useEffect(() => {
    const sub = Keyboard.addListener('keyboardDidShow', () => setActive(null));
    return () => sub.remove();
  }, []);
  const activeId = active?.id ?? null;
  const api = useMemo<HostApi>(() => ({ activeId, open, close, refresh }), [activeId, open, close, refresh]);
  return (
    <HostCtx.Provider value={api}>
      <View style={[s.host, style]}>
        <View style={s.host}>{children}</View>
        {active ? <SecureKeypad key={active.id} binding={active.binding} onClose={() => close(active.id)} /> : null}
      </View>
    </HostCtx.Provider>
  );
}

/* -------------------------------- field -------------------------------- */

let nextId = 0;

export interface SecureInputProps {
  value: string;
  onChangeText: (v: string) => void;
  placeholder?: string;
  /** dots instead of characters — default true for 'password', false for 'phrase' */
  masked?: boolean;
  variant?: KeypadVariant;
  maxLength?: number;
  /** open the keypad as soon as the field appears */
  autoFocus?: boolean;
  editable?: boolean;
  /** the keypad's Done key; the keypad closes afterwards unless stayOpen */
  onSubmit?: () => void;
  stayOpen?: boolean;
  doneLabel?: string;
  /** start on the digits layer (e.g. a numeric prompt) */
  numeric?: boolean;
  multiline?: boolean;
  style?: StyleProp<ViewStyle>;
  focusedStyle?: StyleProp<ViewStyle>;
  textStyle?: StyleProp<TextStyle>;
  placeholderTextColor?: string;
  /** drawn before the text, e.g. a lock icon */
  left?: React.ReactNode;
  accessibilityLabel?: string;
}

export function SecureInput({
  value, onChangeText, placeholder, variant = 'password', masked = variant === 'password',
  maxLength = 1024, autoFocus, editable = true, onSubmit, stayOpen, doneLabel, numeric, multiline,
  style, focusedStyle, textStyle, placeholderTextColor = '#5E6464', left, accessibilityLabel,
}: SecureInputProps) {
  const host = useContext(HostCtx);
  const id = useRef(`sk${++nextId}`).current;
  const binding = useRef<Binding>(null as unknown as Binding);
  binding.current = {
    value,
    onChange: (v) => {
      const next = chars(variant === 'phrase' ? v.toLowerCase() : v).slice(0, maxLength).join('');
      onChangeText(next);
    },
    onDone: onSubmit, stayOpen, maxLength, variant, disabled: !editable, doneLabel,
    initialLayer: numeric ? 'numbers' : 'letters',
  };
  const [localOpen, setLocalOpen] = useState(false);
  const focused = host ? host.activeId === id : localOpen;
  // opens even while not editable (e.g. the lock screen during a lockout): the
  // keypad shows dimmed and every key checks `disabled` before typing
  const focus = () => { if (host) host.open(id, binding); else setLocalOpen(true); };

  useEffect(() => { if (autoFocus) focus(); }, []); // eslint-disable-line react-hooks/exhaustive-deps
  const closeRef = useRef(host?.close);
  closeRef.current = host?.close;
  useEffect(() => () => closeRef.current?.(id), [id]);
  // the keypad reads the value at key-press time; it only needs a redraw when
  // its own look changes (dimmed while verifying, the Done label)
  useEffect(() => { if (focused && host) host.refresh(); }, [editable, doneLabel]); // eslint-disable-line react-hooks/exhaustive-deps

  const n = chars(value).length;
  return (
    <View>
      <Pressable
        onPress={focus}
        accessibilityRole="button"
        accessibilityLabel={accessibilityLabel ?? placeholder ?? 'Secret field'}
        accessibilityValue={{ text: masked ? `${n} characters` : value }}
        accessibilityState={{ disabled: !editable }}
        accessibilityHint="Opens the Vardum keyboard"
        style={[s.field, multiline ? s.fieldMulti : null, style, focused && focusedStyle]}
      >
        {left}
        <Text
          style={[s.fieldTxt, textStyle, !value && { color: placeholderTextColor }, masked && value ? s.fieldDots : null]}
          numberOfLines={multiline ? undefined : 1}
          ellipsizeMode="head"
          selectable={false}
        >
          {value ? (masked ? '•'.repeat(n) : value) : (placeholder ?? '')}
          {focused ? <Text style={s.caret}>|</Text> : null}
        </Text>
      </Pressable>
      {!host && localOpen ? <SecureKeypad binding={binding} onClose={() => setLocalOpen(false)} /> : null}
    </View>
  );
}

const s = StyleSheet.create({
  host: { flex: 1 },
  pad: { backgroundColor: '#111116', borderTopWidth: 1, borderTopColor: '#24242D', paddingHorizontal: 3, paddingTop: 8, paddingBottom: 6 },
  padOff: { opacity: 0.45 },
  row: { flexDirection: 'row', justifyContent: 'center', marginBottom: 8 },
  rowLast: { marginBottom: 2 },
  half: { flex: 0.5 },
  key: { flex: 1, height: 44, marginHorizontal: 3, borderRadius: 7, backgroundColor: '#2A2A33', alignItems: 'center', justifyContent: 'center' },
  keyWide: { flex: 1.5 },
  keySpace: { flex: 5 },
  keySpecial: { backgroundColor: '#1C1C23' },
  keyOn: { backgroundColor: '#FFFFFF' },
  keyDone: { flex: 2.2, backgroundColor: '#FFFFFF' },
  keyPressed: { backgroundColor: '#4A4A56' },
  keyDonePressed: { backgroundColor: '#C9CFCF' },
  keyTxt: { color: '#FFFFFF', fontSize: 20 },
  keyTxtSmall: { fontSize: 15, fontWeight: '600' },
  keyTxtDone: { color: '#0B0B0F', fontWeight: '800' },
  keyTxtOn: { color: '#0B0B0F' },
  field: { flexDirection: 'row', alignItems: 'center', minHeight: 44 },
  fieldMulti: { alignItems: 'flex-start' },
  fieldTxt: { flex: 1, color: '#FFFFFF', fontSize: 15 },
  fieldDots: { letterSpacing: 2 },
  caret: { color: '#20D9C2', fontWeight: '300' },
});
