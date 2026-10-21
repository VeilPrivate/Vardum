package app.tryvardum.unifiedpush

import android.content.Context
import android.content.SharedPreferences

/**
 * Persists the current UnifiedPush endpoint so it survives the app being
 * killed (the distributor can deliver a new endpoint while no JS is running).
 * Holds only the endpoint URL and its public Web Push keys — no secrets; the
 * private decryption keys stay inside the connector's own key store.
 */
object VardumPushStore {
  private const val PREFS = "vardum_unifiedpush"
  private const val K_URL = "url"
  private const val K_PUB = "pubKey"
  private const val K_AUTH = "auth"
  private const val K_ERR = "lastError"

  /** Set by the JS module while it is alive, so a new endpoint reaches JS at once. */
  @Volatile
  var listener: (() -> Unit)? = null

  private fun prefs(c: Context): SharedPreferences =
    c.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

  fun saveEndpoint(c: Context, url: String, pubKey: String?, auth: String?) {
    prefs(c).edit()
      .putString(K_URL, url)
      .putString(K_PUB, pubKey ?: "")
      .putString(K_AUTH, auth ?: "")
      .remove(K_ERR)
      .apply()
    runCatching { listener?.invoke() }
  }

  fun endpoint(c: Context): Map<String, String>? {
    val p = prefs(c)
    val url = p.getString(K_URL, null) ?: return null
    return mapOf(
      "url" to url,
      "pubKey" to (p.getString(K_PUB, "") ?: ""),
      "auth" to (p.getString(K_AUTH, "") ?: ""),
    )
  }

  fun saveError(c: Context, reason: String) {
    prefs(c).edit().putString(K_ERR, reason).apply()
  }

  fun lastError(c: Context): String? = prefs(c).getString(K_ERR, null)

  fun clear(c: Context) {
    prefs(c).edit().clear().apply()
    runCatching { listener?.invoke() }
  }
}
