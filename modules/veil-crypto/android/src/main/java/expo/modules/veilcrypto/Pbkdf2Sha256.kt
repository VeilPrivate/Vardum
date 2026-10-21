package expo.modules.veilcrypto

import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.nio.charset.CodingErrorAction
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

/**
 * PBKDF2-HMAC-SHA256 for VeilCryptoModule.pbkdf2Sha256.
 *
 * Fast path: one native call into src/main/cpp/pbkdf2_sha256.c (libveilkdf).
 * Fallback (library missing — should not happen in a shipped APK): the
 * original javax.crypto SecretKeyFactory "PBKDF2WithHmacSHA256" path.
 * Both produce the same bytes; Pbkdf2Sha256Test checks that against RFC 7914
 * vectors, @noble/hashes outputs and SecretKeyFactory itself.
 *
 * Password encoding: the platform factory (BouncyCastle on Android) turns the
 * char[] into UTF-8; WebCrypto/noble use UTF-8 too. We encode the same way, and
 * refuse malformed UTF-16 (a lone surrogate) instead of guessing — the old path
 * threw on those as well, so the JS caller sees the same rejection.
 */
internal object Pbkdf2Sha256 {
  /** True when libveilkdf loaded; tests use it to report which path ran. */
  val nativeAvailable: Boolean = try {
    System.loadLibrary("veilkdf")
    true
  } catch (e: Throwable) {
    false
  }

  @JvmStatic
  private external fun nativeDerive(password: ByteArray, salt: ByteArray, iterations: Int, out: ByteArray): Int

  fun derive(password: String, salt: ByteArray, iterations: Int, dkLen: Int): ByteArray {
    require(iterations > 0 && dkLen > 0) { "invalid iterations or dkLen" }
    // BouncyCastle's factory refuses an empty password; keep that contract.
    require(password.isNotEmpty()) { "password empty" }
    if (!nativeAvailable) return deriveJca(password, salt, iterations, dkLen)
    val pw = passwordUtf8(password)
    try {
      val out = ByteArray(dkLen)
      val rc = nativeDerive(pw, salt, iterations, out)
      check(rc == 0) { "native pbkdf2 failed ($rc)" }
      return out
    } finally {
      pw.fill(0)
    }
  }

  /** The pre-b199 implementation, kept as the fallback and the test reference. */
  fun deriveJca(password: String, salt: ByteArray, iterations: Int, dkLen: Int): ByteArray {
    val spec = PBEKeySpec(password.toCharArray(), salt, iterations, dkLen * 8)
    try {
      return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
    } finally {
      spec.clearPassword()
    }
  }

  /** Strict UTF-8 (throws CharacterCodingException on malformed UTF-16). */
  fun passwordUtf8(password: String): ByteArray {
    val enc = Charsets.UTF_8.newEncoder()
      .onMalformedInput(CodingErrorAction.REPORT)
      .onUnmappableCharacter(CodingErrorAction.REPORT)
    val buf: ByteBuffer = enc.encode(CharBuffer.wrap(password))
    val out = ByteArray(buf.remaining())
    buf.get(out)
    if (buf.hasArray()) buf.array().fill(0)
    return out
  }
}
