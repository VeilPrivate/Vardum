/**
 * Platform wording (20 Oct 2026, GrapheneOS test on a Pixel 8 Pro): the
 * Android build showed iPhone-only copy ("check Vardum in iPhone Settings",
 * "Free during TestFlight", Face ID). One place for the words that differ.
 */
import { Platform } from 'react-native';

export const IS_ANDROID = Platform.OS === 'android';

/** where the user fixes a declined permission */
export const SETTINGS_APP = IS_ANDROID ? 'Android Settings → Apps → Vardum' : 'iPhone Settings';

/** the biometric the phone asks for */
export const BIOMETRIC = IS_ANDROID ? 'your fingerprint or face unlock' : 'Face ID or Touch ID';
export const BIOMETRIC_SHORT = IS_ANDROID ? 'Biometric' : 'Face ID';

/** the hardware that seals keys */
export const SECURE_CHIP = IS_ANDROID ? 'the phone’s security chip (Android Keystore)' : 'the Secure Enclave';

/** where the beta comes from */
export const BETA_SOURCE = IS_ANDROID ? 'the beta download page' : 'TestFlight';

/** "A permission was declined …" message, same on every screen */
export const PERMISSION_DECLINED = `A permission was declined — check Vardum in ${SETTINGS_APP}, then try again.`;
