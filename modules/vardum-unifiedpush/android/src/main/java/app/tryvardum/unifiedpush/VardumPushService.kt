package app.tryvardum.unifiedpush

import android.util.Log
import org.json.JSONObject
import org.unifiedpush.android.connector.FailedReason
import org.unifiedpush.android.connector.PushService
import org.unifiedpush.android.connector.data.PushEndpoint
import org.unifiedpush.android.connector.data.PushMessage

/**
 * Receives UnifiedPush events from the distributor (ntfy). Runs without the
 * JS engine, so a ping shows even when Vardum is closed.
 *
 * Contentless by design: whatever the payload says, the banner is only ever
 * "Notification" (messages) or "Incoming call". The only thing read from the
 * (Web Push–encrypted) payload is kind == "call".
 */
class VardumPushService : PushService() {
  private val tag = "VardumPush"
  private companion object { const val CALL_FRESH_MS = 60_000L }

  override fun onNewEndpoint(endpoint: PushEndpoint, instance: String) {
    Log.i(tag, "new endpoint received (instance=$instance)")
    VardumPushStore.saveEndpoint(
      applicationContext,
      endpoint.url,
      endpoint.pubKeySet?.pubKey,
      endpoint.pubKeySet?.auth,
    )
  }

  override fun onMessage(message: PushMessage, instance: String) {
    // Batch H (round-6 review R6-3-03): only a push encrypted to this phone's keys
    // (sent by the relay) shows a banner. On ntfy.sh anyone who knows the topic
    // can publish to it; such a push is dropped silently.
    if (!message.decrypted) {
      Log.i(tag, "push not encrypted to this phone — ignored")
      return
    }
    // Batch H (round-6 review R6-3-07): every push now has the same TTL, so a call
    // push can arrive late. Show "Incoming call" only while the send time is fresh.
    val isCall = message.decrypted && runCatching {
      val o = JSONObject(String(message.content, Charsets.UTF_8).trim())
      val t = o.optLong("t", 0L)
      o.optString("kind") == "call" && (t == 0L || System.currentTimeMillis() - t < CALL_FRESH_MS)
    }.getOrDefault(false)
    Log.i(tag, "ping received (call=$isCall, decrypted=${message.decrypted})")
    VardumNotifier.show(applicationContext, isCall)
  }

  override fun onRegistrationFailed(reason: FailedReason, instance: String) {
    Log.w(tag, "registration failed: ${reason.name}")
    VardumPushStore.saveError(applicationContext, reason.name)
  }

  override fun onUnregistered(instance: String) {
    Log.i(tag, "unregistered by distributor")
    VardumPushStore.clear(applicationContext)
  }
}
