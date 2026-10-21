package expo.modules.veilcrypto

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.nio.charset.CharacterCodingException
import java.util.Random

/**
 * PBKDF2-HMAC-SHA256 must stay byte-identical to the old SecretKeyFactory
 * path, WebCrypto and @noble/hashes — vault slots and the app passcode hash
 * were written with them.
 *
 * Expected hex below: RFC 7914 section 11 vectors, plus outputs of
 * @noble/hashes pbkdf2(sha256, TextEncoder().encode(pw), salt, {c, dkLen}),
 * each also confirmed equal to Node/OpenSSL crypto.pbkdf2Sync.
 *
 * On a plain JVM run the native library is absent, so derive() exercises the
 * fallback. To test the C code itself, build a host libveilkdf (see
 * src/test/host-native/build-host-lib.sh) and run with
 *   -PveilkdfLibDir=<dir with veilkdf.dll/.so>
 * which also sets veilkdf.requireNative so the run fails if it did not load.
 */
class Pbkdf2Sha256Test {
  private class Vector(val password: String, val saltHex: String, val iterations: Int, val dkLen: Int, val expectedHex: String)

  private val vectors = listOf(
    // RFC 7914 section 11
    Vector("passwd", "73616c74", 1, 64,
      "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"),
    Vector("Password", "4e61436c", 80000, 64,
      "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d"),
    // non-ASCII (2-, 3- and 4-byte UTF-8) — @noble/hashes
    Vector("pässwörd 漢字 🔑", "000102030405060708090a0b0c0d0e0f", 1000, 32,
      "8be4f9aa596ce7fd84a0bce0a7bed2438ba2d7a186bd71217e251b565f768f66"),
    // password longer than the SHA-256 block (key gets hashed), dkLen spanning 3 blocks
    Vector("x".repeat(65) + "é", "ffeeddccbbaa99887766554433221100", 3, 80,
      "09659e00f0341eb180f7e0ff025605e2d15c8aa921c12cf0a430de9cf23e48a1b9fbbcb06db2619ad19ffca1a737fbe9f9877f130578cc30abee39974ab092568283f0c97940d953a721decb8e56ce70"),
    // the app's real parameters: app-lock passcode (210k, 32) and vault slot (600k, 32)
    Vector("482916", "9f8e7d6c5b4a39281706f5e4d3c2b1a0", 210000, 32,
      "03e2c2f47012aa1b74f22de74dd0b50c238d739ed8148dfbd6e15efa668ce095"),
    Vector("correct horse battery staple é🔑",
      "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90", 600000, 32,
      "47d585be460f6d0c3efb63b4d3a352351cae769d8b3340fe133461e2c83a56a2"),
  )

  @Test
  fun reportsWhichPathRan() {
    println("Pbkdf2Sha256.nativeAvailable = ${Pbkdf2Sha256.nativeAvailable}")
    if (System.getProperty("veilkdf.requireNative") == "true") {
      assertTrue("libveilkdf did not load", Pbkdf2Sha256.nativeAvailable)
    }
  }

  @Test
  fun knownVectors() {
    for (v in vectors) {
      val salt = hex(v.saltHex)
      val t0 = System.nanoTime()
      val got = toHex(Pbkdf2Sha256.derive(v.password, salt, v.iterations, v.dkLen))
      val ms = (System.nanoTime() - t0) / 1_000_000
      assertEquals("derive c=${v.iterations}", v.expectedHex, got)
      assertEquals("jca c=${v.iterations}", v.expectedHex, toHex(Pbkdf2Sha256.deriveJca(v.password, salt, v.iterations, v.dkLen)))
      println("c=${v.iterations} dkLen=${v.dkLen}: ${ms} ms (native=${Pbkdf2Sha256.nativeAvailable})")
    }
  }

  @Test
  fun randomInputsMatchSecretKeyFactory() {
    val rnd = Random(20261017)
    val alphabet = listOf("a", "Z", "0", " ", "!", "é", "ß", "€", "漢", "🔑", "\u0000")
    repeat(300) { n ->
      val len = 1 + rnd.nextInt(if (n % 30 == 0) 120 else 20)
      val pw = buildString { repeat(len) { append(alphabet[rnd.nextInt(alphabet.size)]) } }
      val salt = ByteArray(1 + rnd.nextInt(80)).also { rnd.nextBytes(it) }
      val c = 1 + rnd.nextInt(200)
      val dk = 1 + rnd.nextInt(130)
      assertEquals(
        "case $n",
        toHex(Pbkdf2Sha256.deriveJca(pw, salt, c, dk)),
        toHex(Pbkdf2Sha256.derive(pw, salt, c, dk)),
      )
    }
  }

  @Test
  fun passwordEncodingIsUtf8AndStrict() {
    assertEquals("70c3a4f09f9491", toHex(Pbkdf2Sha256.passwordUtf8("pä🔑")))
    try {
      Pbkdf2Sha256.passwordUtf8("bad\uD83D")
      fail("lone surrogate must be rejected")
    } catch (e: CharacterCodingException) {
      // expected
    }
  }

  @Test(expected = IllegalArgumentException::class)
  fun emptyPasswordIsRejectedLikeTheOldPath() {
    Pbkdf2Sha256.derive("", hex("00"), 1, 32)
  }

  private fun hex(s: String) = ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
  private fun toHex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }
}
