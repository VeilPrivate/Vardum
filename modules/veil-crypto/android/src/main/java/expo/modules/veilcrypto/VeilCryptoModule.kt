package expo.modules.veilcrypto

import android.app.Activity
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.security.keystore.UserNotAuthenticatedException
import android.util.Base64
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import java.security.KeyStore
import java.security.SecureRandom
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import expo.modules.kotlin.Promise
import expo.modules.kotlin.exception.CodedException
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition

/**
 * Vardum native crypto for Android — the Kotlin counterpart of the iOS
 * VeilCryptoModule (Swift). The JS-facing contract is byte-compatible:
 *
 *  - pbkdf2Sha256(password, saltHex, iterations, dkLen) -> hex
 *      PBKDF2-SHA256, byte-identical to the web/iOS contract (210k iterations).
 *  - aesGcmEncrypt(keyHex, ivHex, plaintextBase64, aadHex) -> base64(ct || tag)
 *  - aesGcmDecrypt(keyHex, ivHex, combinedBase64, aadHex) -> base64(pt)
 *      Combined layout is ciphertext||tag(16) — identical to CryptoKit's
 *      sealed-box layout and noble's combined output. A GCM tag mismatch MUST
 *      surface with the message "authentication failure (GCM tag mismatch)"
 *      — noble-subtle.ts matches on exactly that (and "code 20") to fail fast
 *      on wrong passphrases instead of retrying in JS.
 *  - randomBytesBase64(n) -> base64 (SecureRandom; up to 64 MB)
 *  - seIsAvailable / seWrapKey / seUnwrapKey / seResetKey
 *      "Security chip" key mode. iOS seals the master key via ECDH against a
 *      Secure Enclave P-256 key. The Android equivalent is a Keystore AES-GCM
 *      key (StrongBox where available) with setUserAuthenticationRequired +
 *      invalidated-by-biometric-enrollment, unlocked by a BiometricPrompt
 *      CryptoObject at key use. The sealed blob format is device-local and
 *      never crosses platforms — only the JS-facing {eph, salt, ct} shape and
 *      the "biometrics prompt at unwrap" behaviour are the contract here.
 *  - onScreenCapture event {kind: "screenshot"}
 *      Android 14+ (API 34) system screenshot callback. (iOS also reports
 *      "recording"; Android has no equivalent API — the JS side treats the
 *      event shape gracefully.) Blocking screenshots is done JS-side with
 *      expo-screen-capture / FLAG_SECURE — that power is Android-only.
 */
class VeilCryptoModule : Module() {
  private val mainHandler = Handler(Looper.getMainLooper())

  private var captureCallback: Activity.ScreenCaptureCallback? = null

  override fun definition() = ModuleDefinition {
    Name("VeilCrypto")

    Events("onScreenCapture")

    // ---------- Screen-capture watch (Android 14+) ----------
    // Mirrors the iOS side's post-hoc screenshot notice. Android cannot
    // detect screenshots before API 34; the watch simply stays silent there
    // (screen-watch.ts handles an absent watch fine).
    OnActivityEntersForeground {
      val activity = appContext.currentActivity
      if (Build.VERSION.SDK_INT >= 34 && activity != null && captureCallback == null) {
        val cb = Activity.ScreenCaptureCallback {
          sendEvent("onScreenCapture", mapOf("kind" to "screenshot"))
        }
        try {
          // Needs android.permission.DETECT_SCREEN_CAPTURE (module manifest).
          activity.registerScreenCaptureCallback(mainExecutor(), cb)
          captureCallback = cb
        } catch (e: SecurityException) {
          // permission missing — stay silent, same as pre-34 devices
        }
      }
    }
    OnActivityEntersBackground {
      val activity = appContext.currentActivity
      val cb = captureCallback
      if (Build.VERSION.SDK_INT >= 34 && activity != null && cb != null) {
        try { activity.unregisterScreenCaptureCallback(cb) } catch (e: Exception) { }
      }
      captureCallback = null
    }

    // ---------- Secure chip availability ----------
    // b199 (Android handover TODO, owner OK Oct 17): the phone's ringer mode,
    // so the call ringtone obeys silent/vibrate the way iOS obeys the mute
    // switch. Android-only; JS calls it only when present (older builds and
    // iOS fall back to today's behaviour).
    Function("ringerMode") {
      val ctx = appContext.reactContext?.applicationContext ?: return@Function "normal"
      val am = ctx.getSystemService(android.content.Context.AUDIO_SERVICE) as? android.media.AudioManager
        ?: return@Function "normal"
      when (am.ringerMode) {
        android.media.AudioManager.RINGER_MODE_SILENT -> "silent"
        android.media.AudioManager.RINGER_MODE_VIBRATE -> "vibrate"
        else -> "normal"
      }
    }

    // Call quality (owner test 20 Oct 2026: "you can hear yourself"): Android
    // only applies its call echo cancellation and earpiece routing in
    // MODE_IN_COMMUNICATION. JS turns it on for a call and back to
    // MODE_NORMAL at teardown. A connected headset wins over the earpiece.
    Function("setCallAudioMode") { active: Boolean ->
      val ctx = appContext.reactContext?.applicationContext ?: return@Function false
      val am = ctx.getSystemService(android.content.Context.AUDIO_SERVICE) as? android.media.AudioManager
        ?: return@Function false
      try {
        if (active) {
          am.mode = android.media.AudioManager.MODE_IN_COMMUNICATION
          if (android.os.Build.VERSION.SDK_INT >= 31) {
            val devices = am.availableCommunicationDevices
            val headset = devices.firstOrNull {
              it.type == android.media.AudioDeviceInfo.TYPE_WIRED_HEADSET ||
                it.type == android.media.AudioDeviceInfo.TYPE_WIRED_HEADPHONES ||
                it.type == android.media.AudioDeviceInfo.TYPE_USB_HEADSET ||
                it.type == android.media.AudioDeviceInfo.TYPE_BLUETOOTH_SCO ||
                it.type == android.media.AudioDeviceInfo.TYPE_BLE_HEADSET
            }
            val target = headset ?: devices.firstOrNull { it.type == android.media.AudioDeviceInfo.TYPE_BUILTIN_EARPIECE }
            if (target != null) am.setCommunicationDevice(target)
          } else {
            @Suppress("DEPRECATION")
            am.isSpeakerphoneOn = false
          }
        } else {
          if (android.os.Build.VERSION.SDK_INT >= 31) am.clearCommunicationDevice()
          am.mode = android.media.AudioManager.MODE_NORMAL
        }
        true
      } catch (e: Exception) {
        false
      }
    }

    Function("seIsAvailable") {
      val ctx = appContext.reactContext?.applicationContext ?: return@Function false
      val can = BiometricManager.from(ctx)
        .canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)
      can == BiometricManager.BIOMETRIC_SUCCESS
    }

    // ---------- PBKDF2-SHA256 (native C; javax.crypto fallback) ----------
    AsyncFunction("pbkdf2Sha256") { password: String, saltHex: String, iterations: Int, dkLen: Int, promise: Promise ->
      try {
        val salt = hexToBytes(saltHex)
        if (salt.isEmpty()) throw CodedException("ERR_INVALID_SALT", "invalid salt hex", null)
        // RV-27: same bounds as the JS entry point (vendor/device/src/kdf.ts
        // pbkdf2Sha256Bytes); a 1-iteration request is refused here too.
        if (iterations < PBKDF2_MIN_ITERATIONS || iterations > PBKDF2_MAX_ITERATIONS || dkLen < 16 || dkLen > 64) {
          throw CodedException("ERR_INVALID_PARAMS", "pbkdf2Sha256: unsupported iterations or dkLen", null)
        }
        // b199: native C, ~20x faster on budget phones, same bytes (Pbkdf2Sha256.kt).
        val derived = Pbkdf2Sha256.derive(password, salt, iterations, dkLen)
        try {
          promise.resolve(bytesToHex(derived))
        } finally {
          derived.fill(0) // RV-29 (the hex String itself can't be wiped)
        }
      } catch (e: CodedException) {
        promise.reject(e)
      } catch (e: Exception) {
        promise.reject("ERR_PBKDF2", "pbkdf2Sha256 failed: ${e.message}", e)
      }
    }

    // ---------- AES-256-GCM ----------
    AsyncFunction("aesGcmEncrypt") { keyHex: String, ivHex: String, plaintextBase64: String, aadHex: String, promise: Promise ->
      try {
        val key = hexToBytes(keyHex)
        if (key.size != 32) throw CodedException("ERR_BAD_KEY", "aesGcmEncrypt: key must be 32 bytes", null)
        val iv = hexToBytes(ivHex)
        if (iv.size != 12) throw CodedException("ERR_BAD_IV", "aesGcmEncrypt: iv must be 12 bytes", null)
        val pt = b64ToBytes(plaintextBase64)
          ?: throw CodedException("ERR_BAD_INPUT", "aesGcmEncrypt: invalid base64 plaintext", null)
        val aad = hexToBytes(aadHex)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
        if (aad.isNotEmpty()) cipher.updateAAD(aad)
        // javax.crypto GCM doFinal output is ciphertext||tag(16) — the same
        // combined layout CryptoKit and noble produce.
        val out = cipher.doFinal(pt)
        key.fill(0); pt.fill(0) // RV-29
        promise.resolve(bytesToB64(out))
      } catch (e: CodedException) {
        promise.reject(e)
      } catch (e: Exception) {
        promise.reject("ERR_AES", "aesGcmEncrypt failed: ${e.message}", e)
      }
    }

    AsyncFunction("aesGcmDecrypt") { keyHex: String, ivHex: String, combinedBase64: String, aadHex: String, promise: Promise ->
      try {
        val key = hexToBytes(keyHex)
        if (key.size != 32) throw CodedException("ERR_BAD_KEY", "aesGcmDecrypt: key must be 32 bytes", null)
        val iv = hexToBytes(ivHex)
        if (iv.size != 12) throw CodedException("ERR_BAD_IV", "aesGcmDecrypt: iv must be 12 bytes", null)
        val combined = b64ToBytes(combinedBase64)
          ?: throw CodedException("ERR_BAD_INPUT", "aesGcmDecrypt: invalid base64 ciphertext", null)
        if (combined.size < 16) {
          throw CodedException("ERR_BAD_INPUT", "aesGcmDecrypt: ciphertext shorter than a bare GCM tag", null)
        }
        val aad = hexToBytes(aadHex)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
        if (aad.isNotEmpty()) cipher.updateAAD(aad)
        val pt: ByteArray
        try {
          // javax.crypto expects the tag appended to the ciphertext — the
          // combined layout, exactly as the Swift module receives it.
          pt = cipher.doFinal(combined)
        } catch (e: javax.crypto.AEADBadTagException) {
          // MUST match noble-subtle.ts's detection: it looks for
          // "code 20" or "authentication failure" in the message.
          throw CodedException("ERR_GCM_AUTH", "authentication failure (GCM tag mismatch)", null)
        }
        key.fill(0) // RV-29
        try { promise.resolve(bytesToB64(pt)) } finally { pt.fill(0) }
      } catch (e: CodedException) {
        promise.reject(e)
      } catch (e: Exception) {
        promise.reject("ERR_AES", "aesGcmDecrypt failed: ${e.message}", e)
      }
    }

    // ---------- SecureRandom ----------
    AsyncFunction("randomBytesBase64") { byteLength: Int, promise: Promise ->
      try {
        if (byteLength <= 0 || byteLength > 64 * 1024 * 1024) {
          throw CodedException("ERR_BAD_LENGTH", "randomBytesBase64: length out of range", null)
        }
        val bytes = ByteArray(byteLength)
        SecureRandom().nextBytes(bytes)
        promise.resolve(bytesToB64(bytes))
      } catch (e: CodedException) {
        promise.reject(e)
      } catch (e: Exception) {
        promise.reject("ERR_RANDOM", "randomBytesBase64 failed: ${e.message}", e)
      }
    }

    // ---------- "Security chip" seal (Android Keystore + BiometricPrompt) ----------
    AsyncFunction("seWrapKey") { masterKeyB64: String, promise: Promise ->
      try {
        val master = b64ToBytes(masterKeyB64)
          ?: throw CodedException("ERR_SE_INPUT", "seWrapKey: master key is not valid base64", null)
        if (master.isEmpty()) {
          throw CodedException("ERR_SE_INPUT", "seWrapKey: master key is not valid base64", null)
        }
        val out = try {
          runAuthed({ loadSeCipher(Cipher.ENCRYPT_MODE, null) }) { it.doFinal(master) }
        } finally {
          master.fill(0) // RV-29
        }
        // Device-local blob format: [version:1][iv:12][ct||tag]
        val blob = ByteArray(1 + 12 + out.output.size)
        blob[0] = SE_BLOB_VERSION
        System.arraycopy(out.ivBytes, 0, blob, 1, 12)
        System.arraycopy(out.output, 0, blob, 13, out.output.size)
        val rng = SecureRandom()
        val eph = ByteArray(32); rng.nextBytes(eph)
        val salt = ByteArray(32); rng.nextBytes(salt)
        val hw = seKeyHardware()
        android.util.Log.i("veil-se", "wrap key hw=$hw")
        promise.resolve(
          mapOf(
            "eph" to bytesToB64(eph),
            "salt" to bytesToB64(salt),
            "ct" to bytesToB64(blob),
            // D-20 (RV-57): where the wrap key really lives. Extra field;
            // callers that only read eph/salt/ct are unaffected.
            "hw" to hw,
          )
        )
      } catch (e: SeAuthCancelled) {
        promise.reject("ERR_SE_CANCELLED", "seWrapKey: biometric prompt cancelled (${e.message})", e)
      } catch (e: SeAuthTimeout) {
        promise.reject("ERR_SE_TIMEOUT", "seWrapKey: biometric prompt timed out", e)
      } catch (e: CodedException) {
        promise.reject(e)
      } catch (e: Exception) {
        promise.reject("ERR_SE", "seWrapKey failed: ${e.message}", e)
      }
    }

    AsyncFunction("seUnwrapKey") { ephB64: String, saltB64: String, ctB64: String, promise: Promise ->
      try {
        val blob = b64ToBytes(ctB64)
          ?: throw CodedException("ERR_SE_INPUT", "seUnwrapKey: malformed sealed blob", null)
        if (blob.size < 1 + 12 + 16 || blob[0] != SE_BLOB_VERSION) {
          throw CodedException("ERR_SE_INPUT", "seUnwrapKey: malformed sealed blob", null)
        }
        val iv = blob.copyOfRange(1, 13)
        val ct = blob.copyOfRange(13, blob.size)
        val master = runAuthed({ loadSeCipher(Cipher.DECRYPT_MODE, GCMParameterSpec(128, iv)) }) { it.doFinal(ct) }
        try { promise.resolve(bytesToB64(master.output)) } finally { master.output.fill(0) } // RV-29
      } catch (e: SeAuthCancelled) {
        promise.reject("ERR_SE_CANCELLED", "seUnwrapKey: biometric prompt cancelled (${e.message})", e)
      } catch (e: SeAuthTimeout) {
        promise.reject("ERR_SE_TIMEOUT", "seUnwrapKey: biometric prompt timed out", e)
      } catch (e: CodedException) {
        promise.reject(e)
      } catch (e: Exception) {
        promise.reject("ERR_SE", "seUnwrapKey failed: ${e.message}", e)
      }
    }

    AsyncFunction("seResetKey") { promise: Promise ->
      try {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        if (ks.containsAlias(SE_KEY_ALIAS)) ks.deleteEntry(SE_KEY_ALIAS)
        // Same rule as iOS D-19: reset must really replace the key.
        if (KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }.containsAlias(SE_KEY_ALIAS)) {
          throw CodedException("ERR_SE", "seResetKey: old Keystore key still present after delete", null)
        }
        ensureSeKey()
        promise.resolve(true)
      } catch (e: Exception) {
        promise.reject("ERR_SE", "seResetKey failed: ${e.message}", e)
      }
    }

    // D-20 (RV-57): report where the wrap key lives without using it (no
    // prompt). New, optional: JS that doesn't call it is unaffected. Creates
    // the key if missing, like seWrapKey would.
    AsyncFunction("seKeyInfo") { promise: Promise ->
      try {
        val hw = seKeyHardware()
        promise.resolve(mapOf("hw" to hw, "insideSecureHardware" to (hw == "strongbox" || hw == "tee")))
      } catch (e: Exception) {
        promise.reject("ERR_SE", "seKeyInfo failed: ${e.message}", e)
      }
    }
  }

  // ================= internals =================

  companion object {
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val SE_KEY_ALIAS = "veil-se-wrap-key"
    private const val SE_BLOB_VERSION: Byte = 1
    /** Must match PBKDF2_MIN_ITERATIONS / PBKDF2_MAX_ITERATIONS in vendor/device/src/kdf.ts. */
    private const val PBKDF2_MIN_ITERATIONS = 100_000
    private const val PBKDF2_MAX_ITERATIONS = 1_000_000
    /** D-20: how long a key operation waits for the biometric prompt. */
    private const val SE_PROMPT_TIMEOUT_S = 120L
  }

  /** Thrown locally when the biometric prompt ends with an error (cancel, lockout…), to route the reject. */
  private class SeAuthCancelled(val code: Int, why: String) : Exception("biometric prompt ended ($code: $why)")

  /** Thrown locally when the biometric prompt got no answer in time. */
  private class SeAuthTimeout : Exception()

  private class AuthedResult(val output: ByteArray, val ivBytes: ByteArray)

  private fun mainExecutor(): Executor {
    val activity = appContext.currentActivity
    return if (activity != null && Build.VERSION.SDK_INT >= 28) {
      activity.mainExecutor
    } else {
      Executor { r -> mainHandler.post(r) }
    }
  }

  private fun currentFragmentActivity(): FragmentActivity? =
    appContext.currentActivity as? FragmentActivity

  /**
   * Load the persisted Keystore wrap key or create it: AES-256-GCM,
   * StrongBox where available, biometry-gated per use, invalidated when the
   * biometric set changes (matches iOS's .biometryCurrentSet semantics).
   */
  private fun ensureSeKey() {
    val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
    if (ks.containsAlias(SE_KEY_ALIAS)) return

    val builder = KeyGenParameterSpec.Builder(
      SE_KEY_ALIAS,
      KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
    )
      .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
      .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
      .setKeySize(256)
      .setUserAuthenticationRequired(true)
      .setInvalidatedByBiometricEnrollment(true)

    if (Build.VERSION.SDK_INT >= 30) {
      builder.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
    } else {
      // -1 = authentication required for every use (CryptoObject flow)
      builder.setUserAuthenticationValidityDurationSeconds(-1)
    }

    val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)

    if (Build.VERSION.SDK_INT >= 28) {
      try {
        builder.setIsStrongBoxBacked(true)
        generator.init(builder.build())
        generator.generateKey()
        return
      } catch (e: StrongBoxUnavailableException) {
        // no StrongBox hardware — fall through to the normal Keystore
      } catch (e: java.security.ProviderException) {
        // some OEM keystore providers wrap StrongBox errors in ProviderException
      }
      // IMPORTANT: clear the StrongBox flag before the fallback build — the
      // builder is mutable and keeps whatever was last set.
      builder.setIsStrongBoxBacked(false)
    }
    generator.init(builder.build())
    generator.generateKey()
  }

  /** The wrap key from the Keystore (created on first use). */
  private fun loadSeSecretKey(): javax.crypto.SecretKey {
    ensureSeKey()
    val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
    val entry = ks.getEntry(SE_KEY_ALIAS, null) as? KeyStore.SecretKeyEntry
      ?: throw CodedException("ERR_SE_KEY", "Keystore wrap key unavailable (re-enrolled biometrics?)", null)
    return entry.secretKey
  }

  /**
   * A FRESH cipher on the auth-gated wrap key, initialised but not yet used.
   * For a per-use biometric key, init succeeds without auth; the operation
   * is authorised only through the BiometricPrompt CryptoObject that wraps
   * this exact cipher. A cipher is never reused after a failed operation.
   * (D-20: the old code swallowed UserNotAuthenticatedException here and
   * returned an UNinitialised cipher.)
   */
  private fun loadSeCipher(mode: Int, spec: GCMParameterSpec?): Cipher {
    val key = loadSeSecretKey()
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    try {
      if (spec != null) cipher.init(mode, key, spec) else cipher.init(mode, key)
    } catch (e: KeyPermanentlyInvalidatedException) {
      throw CodedException("ERR_SE_KEY", "Keystore wrap key was invalidated (biometrics changed); reset needed", e)
    }
    return cipher
  }

  /**
   * "strongbox" / "tee" / "software" / "unknown": where the wrap key really
   * lives, from KeyInfo (RV-57: StrongBox falls back to TEE or software
   * silently; "security chip" must not be claimed over a software key).
   */
  private fun seKeyHardware(): String = try {
    val key = loadSeSecretKey()
    val factory = javax.crypto.SecretKeyFactory.getInstance(key.algorithm, ANDROID_KEYSTORE)
    val info = factory.getKeySpec(key, KeyInfo::class.java) as KeyInfo
    if (Build.VERSION.SDK_INT >= 31) {
      when (info.securityLevel) {
        KeyProperties.SECURITY_LEVEL_STRONGBOX -> "strongbox"
        KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> "tee"
        KeyProperties.SECURITY_LEVEL_SOFTWARE -> "software"
        KeyProperties.SECURITY_LEVEL_UNKNOWN_SECURE -> "tee"
        else -> "unknown"
      }
    } else {
      @Suppress("DEPRECATION")
      if (info.isInsideSecureHardware) "tee" else "software"
    }
  } catch (e: Exception) {
    "unknown"
  }

  /**
   * D-20 (RV-17): run a cipher operation on the per-use, biometric-only wrap
   * key. The old code tried the operation WITHOUT auth and showed the prompt
   * only on UserNotAuthenticatedException, but a per-use Keystore key fails
   * at doFinal with IllegalBlockSizeException instead, so the prompt never
   * appeared; it also reused the failed cipher and waited forever.
   *
   * Now every call: fresh cipher -> BiometricPrompt.authenticate(CryptoObject)
   * built and shown on the main thread -> the operation runs on the cipher
   * the prompt hands back. The wait is bounded (SE_PROMPT_TIMEOUT_S) and the
   * prompt is cancelled on timeout. If the authorised operation itself fails
   * for a key-store reason, one more attempt is made with a NEW cipher and a
   * new prompt. Throws SeAuthCancelled / SeAuthTimeout for those outcomes.
   */
  private fun runAuthed(newCipher: () -> Cipher, op: (Cipher) -> ByteArray): AuthedResult {
    if (Looper.myLooper() == Looper.getMainLooper()) {
      // waiting on the main thread would deadlock the prompt's own callbacks
      throw CodedException("ERR_SE", "biometric key operation called on the main thread", null)
    }
    var lastFailure: Exception? = null
    for (attempt in 1..2) {
      try {
        return promptOnce(newCipher(), op)
      } catch (e: javax.crypto.IllegalBlockSizeException) {
        lastFailure = e // key-store refusal after auth: retry with a fresh cipher
      } catch (e: UserNotAuthenticatedException) {
        lastFailure = e
      } catch (e: java.security.ProviderException) {
        lastFailure = e
      }
    }
    throw CodedException("ERR_SE", "biometric key operation failed: ${lastFailure?.message}", lastFailure)
  }

  private fun promptOnce(cipher: Cipher, op: (Cipher) -> ByteArray): AuthedResult {
    val activity = currentFragmentActivity()
      ?: throw CodedException("ERR_SE_UNAVAILABLE", "no biometric-capable activity is in the foreground", null)

    val latch = CountDownLatch(1)
    val finished = AtomicBoolean(false)
    var result: AuthedResult? = null
    var failure: Exception? = null
    var prompt: BiometricPrompt? = null

    fun finish(r: AuthedResult?, f: Exception?) {
      if (!finished.compareAndSet(false, true)) return // late callback after a timeout
      result = r
      failure = f
      latch.countDown()
    }

    val info = BiometricPrompt.PromptInfo.Builder()
      .setTitle("Vardum")
      .setSubtitle("Unlock your identity key")
      .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
      .setNegativeButtonText("Cancel")
      .setConfirmationRequired(false)
      .build()

    mainHandler.post {
      try {
        // androidx expects BiometricPrompt to be constructed on the main thread.
        val executor: Executor = if (Build.VERSION.SDK_INT >= 28) activity.mainExecutor else Executor { r -> mainHandler.post(r) }
        val p = BiometricPrompt(
          activity,
          executor,
          object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(authResult: BiometricPrompt.AuthenticationResult) {
              if (finished.get()) return
              // Use the cipher the prompt authorised, never a stale one.
              val authed = authResult.cryptoObject?.cipher ?: cipher
              try {
                finish(AuthedResult(op(authed), authed.iv), null)
              } catch (e: javax.crypto.AEADBadTagException) {
                finish(null, CodedException("ERR_GCM_AUTH", "authentication failure (GCM tag mismatch)", null))
              } catch (e: Exception) {
                finish(null, e)
              }
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
              finish(null, SeAuthCancelled(errorCode, errString.toString()))
            }

            override fun onAuthenticationFailed() {
              // single failed attempt (unrecognised finger) — the prompt stays up
            }
          },
        )
        prompt = p
        p.authenticate(info, BiometricPrompt.CryptoObject(cipher))
      } catch (e: Exception) {
        finish(null, e)
      }
    }

    if (!latch.await(SE_PROMPT_TIMEOUT_S, TimeUnit.SECONDS)) {
      if (finished.compareAndSet(false, true)) {
        mainHandler.post { try { prompt?.cancelAuthentication() } catch (e: Exception) { } }
        throw SeAuthTimeout()
      }
      // a callback won the race just now; its result is set
      latch.await()
    }

    failure?.let { throw it }
    return result ?: throw CodedException("ERR_SE", "se operation failed without a result", null)
  }

  // ---------- hex / base64 helpers (mirror the Swift helpers) ----------

  private fun hexToBytes(hex: String): ByteArray {
    val chars = hex.toCharArray()
    if (chars.size % 2 != 0) return ByteArray(0)
    val out = ByteArray(chars.size / 2)
    for (i in out.indices) {
      val hi = hexDigit(chars[i * 2]) ?: return ByteArray(0)
      val lo = hexDigit(chars[i * 2 + 1]) ?: return ByteArray(0)
      out[i] = ((hi shl 4) or lo).toByte()
    }
    return out
  }

  private fun hexDigit(c: Char): Int? = when (c) {
    in '0'..'9' -> c - '0'
    in 'a'..'f' -> c - 'a' + 10
    in 'A'..'F' -> c - 'A' + 10
    else -> null
  }

  private fun bytesToHex(bytes: ByteArray): String {
    val sb = StringBuilder(bytes.size * 2)
    for (b in bytes) {
      val v = b.toInt() and 0xff
      sb.append("0123456789abcdef"[v ushr 4])
      sb.append("0123456789abcdef"[v and 0x0f])
    }
    return sb.toString()
  }

  private fun b64ToBytes(b64: String): ByteArray? = try {
    Base64.decode(b64, Base64.NO_WRAP)
  } catch (e: IllegalArgumentException) {
    null
  }

  private fun bytesToB64(bytes: ByteArray): String = Base64.encodeToString(bytes, Base64.NO_WRAP)
}
