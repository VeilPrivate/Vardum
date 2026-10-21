/**
 * @veil/crypto-core — protocol constants. These MUST NOT drift: any change is
 * a protocol bump.
 */

/** Batch C: veil-ratchet-6 is the ONLY supported 1:1 protocol. Hard cut —
 *  older sessions (ratchet-3/-4: P-256, optional PQ; ratchet-5: no responder-IK
 *  term, shared signing key, dials outside the transcript) are refused on load
 *  and ended by the app's one-time migration. */
export const RATCHET_PROTOCOL_LATEST = 'veil-ratchet-6' as const;
export const RATCHET_VERSION = RATCHET_PROTOCOL_LATEST;
export const RATCHET_PROTOCOL_SUPPORTED = [RATCHET_PROTOCOL_LATEST] as const;

export const RATCHET_ENGINE_LABEL =
  'Double Ratchet — hybrid X25519 + ML-KEM-768 (FIPS 203), signed PQ prekey, PQ mandatory, per-step PQ re-key, signed ratchet keys · HKDF-SHA256 · AES-GCM-256 · padded buckets · cover traffic' as const;

/** Padded plaintext buckets (bytes). Anything larger throws in the web app. */
export const PADDED_BUCKETS: readonly number[] = [1024, 4096];
/** Padded frame header: 1 byte cover flag + 2 bytes big-endian length. */
export const PAD_FRAME_HEADER_BYTES = 3;

/** BIP39 (standard English wordlist, 2048 words). */
export const BIP39_SALT = 'mnemonic' as const;
export const BIP39_ITERATIONS = 2048;
export const BIP39_WORDS = 24;

/** HKDF info strings (extracted from bundle). */
export const HKDF_INFO_IDENTITY_ED25519 = 'veil-identity-ed25519' as const;

/** 64-byte root/chain derivation (KDF_RK): info = `vardum-ratchet-6/rk` -> {rk, ck}. */
export const ROOT_KEY_INFO = 'vardum-ratchet-6/rk' as const;
/** Handshake root: HKDF(shared, salt=`vardum-ratchet-6:<token>`, info=`rk0`, 32). */
export const RK0_SALT_PREFIX = 'vardum-ratchet-6:' as const;
export const RK0_INFO = 'rk0' as const;
/** Invite link secret (`k=` fragment, never sent to the relay):
 *  HKDF(k, salt=`vardum-pp-6:<token>`, info=`pp`, 32). */
export const PP_SALT_PREFIX = 'vardum-pp-6:' as const;
export const PP_INFO = 'pp' as const;
/** One-tap contact relay write credentials. */
export const CONTACT_WRITE_INFO = 'vardum-contact-write-6' as const;
/** Session fingerprint transcript label (see kdf.ts transcriptFingerprint). */
export const FINGERPRINT_LABEL = 'vardum-fp-6' as const;
/** Signed ML-KEM prekey: Ed25519(IK, utf8(PQ_PREKEY_SIG_LABEL) || pq_pub bytes). */
export const PQ_PREKEY_SIG_LABEL = 'vardum-pq-prekey-v1:' as const;
/** ML-KEM-768 public key / ciphertext sizes (FIPS 203). */
export const MLKEM768_PUB_BYTES = 1184;
export const MLKEM768_CT_BYTES = 1088;

/** Session-scoped Ed25519 ratchet-key signatures (prior finding H-1). The
 *  signing keypair is derived from the session's handshake root with this
 *  info string, one pair per direction (Batch C, B9), and every header's
 *  ratchet pub + PQ step pub is signed. Always on. */
export const RATCHET_SIG_INFO = 'vardum-ratchet-sig-6' as const;
