# Vardum

**Private messaging that stays private, even if someone has your phone.**

Vardum (formerly VEIL) is an end-to-end encrypted messenger for iPhone and Android, made by Vardum Technology Pty Ltd in Queensland, Australia. This repository holds the crypto core, the protocol layer, the relay server and the app code under AGPL-3.0, so anyone can check our claims against the code.

> Renamed from VEIL in October 2026. Internal identifiers (`veil_*` keys, `veil-*` crypto labels, the `VeilCrypto` module, the `tryveil.app` relay and link addresses) keep their old names on purpose: changing them would break existing installs, keys and links.

Website: https://tryvardum.app

## What it does

- **End-to-end encryption.** Hybrid X25519 + ML-KEM-768 key exchange, double ratchet, forward secrecy per message. The relay stores ciphertext it cannot open.
- **Deleted means deleted.** Burn after read (5 min to 24 h after opening), an expiry for unopened copies, and a wipe either person can trigger. Relay copies are hard-deleted, not hidden.
- **Nothing-at-Rest.** Identity keys live in memory only. A locked phone fetches nothing and keeps much less on it to extract (not a guarantee against extraction tools or a compromised phone). Recovery is the 24-word phrase.
- **Duress and decoy codes, off until you set them.** A decoy code opens a harmless dashboard. A duress code wipes local keys and asks the relay to delete your records, then shows the same decoy.
- **No phone. No email. No name.** Your identity is 24 random words made on your phone. Your Vardum ID is random, and nothing you sign up with points back to you.
- **Calls across networks.** Voice and video calls go through a call server Vardum runs itself, so neither phone learns the other's IP address. Connection details travel inside the encrypted call offer to cut setup time.
- **Groups up to 100.** Post-quantum sender keys, rotation each epoch, signed membership, evictions that stick.
- **Encrypted media, vaults and notes.** Per-file keys, a hidden vault volume, a 25 MB cap.
- **Android without Google.** On GrapheneOS and other phones without Google services, alerts arrive through UnifiedPush (for example the ntfy app), encrypted to the phone and carrying no sender or content. Vardum is not affiliated with or endorsed by GrapheneOS.

## Honest limits

- The cryptography is self-reviewed. An independent cryptographic audit is planned for early 2027; until it's published, nothing here has been independently checked.
- Calling across networks is new and has had limited testing. The call server sees both phones' IP addresses while a call runs, and when and for how long. If it can't be reached, calls work on the same network only.
- The relay sees network metadata such as timing, sizes and the IP address of each request. Push services (Apple, Google, Expo, UnifiedPush servers) see the push address and when alerts are sent.
- Android is a small-group beta, by request.

Every claim is listed with its status and limits in the [claims register](https://tryvardum.app/claims/). The [privacy policy](https://tryvardum.app/privacy/) says what is kept and for how long.

## Try it

- **iPhone:** free public beta on TestFlight: https://testflight.apple.com/join/Aqay7XH2
- **Android:** small-group beta. Ask to join at https://tryvardum.app/android/, which also lists the signing fingerprint to check before installing.

## What's in this repository

| Directory | What it is |
|---|---|
| `crypto-core/` | The encryption: the ratchet, the hybrid X25519 + ML-KEM-768 key agreement, the identity system |
| `device/` | The protocol layer: sessions, groups, contacts, media, vaults, notes, calls, the relay client |
| `relay/` | The self-hosted relay server: the API, the session gate, the group gate, the sweeper, call credentials |
| `modules/veil-crypto/` | The native crypto module: hardware-accelerated PBKDF2 and AES on iOS, native PBKDF2 on Android |
| `modules/vardum-unifiedpush/` | The Android UnifiedPush module for alerts without Google services |
| `src/` | The React Native app: the screens, calls, notifications and privacy controls |
| `app.json` | The Expo configuration |

This is a source copy for review. In the app's own repository `crypto-core/` and `device/` live under `vendor/`, which is why app imports read `../vendor/...`. One value is left out: the founding-tester forum's group token in `device/src/lounge.ts`, because it is part of that forum's private invite link.

## Building

Requires Node.js 18+. For iOS, Xcode and an Apple developer account; for Android, the Android SDK (API 36).

```bash
npm install
npx expo start                                          # development
npx eas build --platform ios --profile production       # iOS release build
npx expo run:android --variant release                  # Android release build
```

## The relay

The relay is a Deno application. Deploy:

```bash
cd relay
deno run -A --unstable-kv main.ts
```

Settings come from environment variables (for example `TURN_SECRET` and `TURN_HOSTS` for calls); none are stored in this repository. The relay stores ciphertext it cannot decrypt. It does see network metadata; see Honest limits above.

## Reporting a security issue

Please read the [responsible disclosure policy](https://tryvardum.app/disclosure/) first. Support: support@tryvardum.app.

## License

Copyright © 2026 Matt Franks

This program is free software: you can redistribute it and/or modify it under the terms of the GNU Affero General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.
