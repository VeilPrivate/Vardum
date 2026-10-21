/**
 * Expo shell — the VEIL device context.
 *
 * Everything crypto/storage/relay-shaped comes from the tested pure packages;
 * this file only wires platform pieces and holds app state. No crypto here.
 */
import {
  KeychainStorage, PinStore, IdentityVault, SessionStore, VeilRelay, Base44Auth, SettingsStore, AppLockStore, NotesStore,
} from '../vendor/device/src/index';
import { createRnSecureStore, type RnSecureStoreOptions } from './secure-store.rn';
import * as FileSystem from 'expo-file-system';
import { toB64 } from '../vendor/crypto-core/src/index';

// b198 RELAY FLIP (founder-approved): self-hosted relay behind Caddy TLS.
// Base44 remains the production/TestFlight relay until the staged cutover completes.
export const VEIL_BASE_URL = 'https://relay.tryveil.app';
// b199 (Oct 16): the public website, for Settings' privacy policy, terms and
// Security Centre links. They pointed at the relay, which has no web pages.
export const VEIL_SITE_URL = 'https://tryveil.app';
export let VEIL_APP_ID = '6a9dae3b8bc7a581e4ab310a';
export const setVeilAppId = (id: string) => { VEIL_APP_ID = id; };

export interface VeilApp {
  storage: KeychainStorage;
  auth: Base44Auth;
  pins: PinStore;
  settings: SettingsStore;
  vault: IdentityVault;
  sessions: SessionStore;
  appLock: AppLockStore;
  notes: NotesStore;
  relay: VeilRelay;
}

export async function createVeilApp(secureStoreOpts: RnSecureStoreOptions = {}): Promise<VeilApp> {
  const storage = new KeychainStorage(createRnSecureStore(secureStoreOpts));
  const auth = new Base44Auth({ baseUrl: VEIL_BASE_URL, appId: VEIL_APP_ID }, storage);
  // the relay authorizes every gate call with the account session token.
  // bytesToTempFile routes bytes-based uploads (Vault containers, Device
  // Transfer bundles) through a real cache file — RN's FormData cannot
  // construct a Blob from raw bytes (VEIL-P1, Sept 19), but it CAN send a
  // {uri,name,type} part, the same path media sends already use.
  const relay = new VeilRelay({
    baseUrl: VEIL_BASE_URL,
    appId: VEIL_APP_ID,
    getToken: () => auth.getToken(),
    bytesToTempFile: async (bytes: Uint8Array, name: string) => {
      const uri = `${FileSystem.cacheDirectory}veil-upload-${Date.now()}-${name}`;
      await FileSystem.writeAsStringAsync(uri, toB64(bytes), { encoding: FileSystem.EncodingType.Base64 });
      return { uri, cleanup: () => { FileSystem.deleteAsync(uri, { idempotent: true }).catch(() => undefined); } };
    },
  });
  return {
    storage,
    auth,
    pins: new PinStore((k) => storage.get(k), (k, v) => storage.set(k, v)),
    settings: new SettingsStore((k) => storage.get(k), (k, v) => storage.set(k, v)),
    vault: new IdentityVault(storage),
    sessions: new SessionStore(storage),
    appLock: new AppLockStore(storage),
    notes: new NotesStore((k) => storage.get(k), (k, v) => storage.set(k, v)),
    relay,
  };
}
