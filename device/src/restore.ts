/**
 * @veil/device — identity restore (phrase login).
 *
 * The web-verified flow (Sept 8, re-verified Sept 13), exact order:
 *   1. restoreIdentity(phrase) — keys re-derived locally, veil_id reproduced
 *   2. identityRegister — publish FRESH SPK/pq prekeys (public material only)
 *   3. identityChallenge — relay issues a nonce
 *   4. ikSign(nonce) — Ed25519 signature with the identity key
 *   5. identityBind — binds the veil_id to the logged-in account
 *   6. keyvault saved to the secure store
 *
 * The phrase and every private key stay on-device; the relay sees public keys
 * and a nonce signature only. A phrase belonging to a DIFFERENT identity than
 * expected is rejected before anything touches the network.
 */

import { restoreIdentity, ikSign, signPqPrekey, bindChallengeMessage, toB64, type VeilIdentityMaterial } from '../../crypto-core/src/index';
import type { VeilRelay, IdentityVault, KeyvaultIdentity } from './index';

export interface RestoreDeps {
  relay: VeilRelay;
  vault: IdentityVault;
}

/**
 * Provision any identity material (freshly created or phrase-restored):
 * publish fresh prekeys (public-only), challenge -> sign -> bind, keyvault save.
 * The phrase and every private key stay on-device.
 */
export async function provisionIdentity(
  deps: RestoreDeps,
  material: VeilIdentityMaterial,
): Promise<KeyvaultIdentity> {
  // 1. publish fresh prekeys (public material only — never the phrase)
  await deps.relay.identityRegister({
    veil_id: material.veilId,
    IK_pub: material.ikPubB64,
    SPK_pub: material.spkPubB64,
    SPK_sig: material.spkSigB64,
    pq_pub: material.pq.pub,
    pq_sig: material.pqSigB64,
  });

  // 2. challenge -> sign the nonce with the identity key -> bind
  const nonce = await deps.relay.identityChallenge(material.veilId);
  // b54 (T-1): never sign relay-chosen bytes raw — domain-separated bind message
  const signature = await ikSign(material.ikSeedB64, toB64(bindChallengeMessage(nonce, material.veilId)));
  await deps.relay.identityBind(material.veilId, nonce, signature);

  // 3. keyvault to secure storage
  const identity: KeyvaultIdentity = {
    veilId: material.veilId,
    ikSeedB64: material.ikSeedB64,
    ikPubB64: material.ikPubB64,
    spkPubB64: material.spkPubB64,
    spkPrivB64: material.spkPrivB64,
    spkSigB64: material.spkSigB64,
    pqPubB64: material.pq.pub,
    pqPrivB64: material.pq.priv,
    pqSigB64: material.pqSigB64,
    createdAt: new Date().toISOString(),
  };
  await deps.vault.save(identity);
  return identity;
}

export async function restoreFromPhrase(
  deps: RestoreDeps,
  phrase: string,
  expectedVeilId?: string,
): Promise<KeyvaultIdentity> {
  // keys re-derived locally; wrong-identity phrase rejected before network
  const material = await restoreIdentity(phrase, expectedVeilId, true);
  return provisionIdentity(deps, material);
}

/**
 * b54 (Batch A): a keyvault created before b54 has no pq_sig. Sign the
 * EXISTING prekeys with the identity key, republish them unchanged with the
 * signature, and save it to the keyvault. Idempotent; runs at every launch
 * until it has succeeded once. Peers on b54 refuse an unsigned PQ prekey.
 */
export async function ensurePqPrekeySigned(deps: RestoreDeps, identity: KeyvaultIdentity): Promise<KeyvaultIdentity> {
  if (identity.pqSigB64) return identity;
  const pqSigB64 = await signPqPrekey(identity.ikSeedB64, identity.pqPubB64);
  await deps.relay.identityRegister({
    veil_id: identity.veilId,
    IK_pub: identity.ikPubB64,
    SPK_pub: identity.spkPubB64,
    SPK_sig: identity.spkSigB64,
    pq_pub: identity.pqPubB64,
    pq_sig: pqSigB64,
  });
  const updated = { ...identity, pqSigB64 };
  await deps.vault.save(updated);
  return updated;
}
