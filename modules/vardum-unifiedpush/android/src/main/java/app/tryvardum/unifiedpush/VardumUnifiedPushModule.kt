package app.tryvardum.unifiedpush

import android.content.Context
import android.os.Bundle
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import org.unifiedpush.android.connector.INSTANCE_DEFAULT
import org.unifiedpush.android.connector.UnifiedPush

/**
 * JS bridge for Google-free push (UnifiedPush). JS side: src/unifiedpush.ts.
 *
 * Flow: JS picks a distributor (ntfy) -> register() -> the distributor hands
 * VardumPushService a push endpoint URL + Web Push keys -> stored here ->
 * JS reads it and files it with the relay as this device's push target.
 * Pings are then shown natively by VardumNotifier, app open or not.
 */
class VardumUnifiedPushModule : Module() {
  private val ctx: Context
    get() = appContext.reactContext ?: throw IllegalStateException("Vardum push: React context not ready")

  override fun definition() = ModuleDefinition {
    Name("VardumUnifiedPush")

    Events("onEndpoint")

    OnCreate {
      VardumPushStore.listener = {
        val c = appContext.reactContext
        if (c != null) {
          val ep = VardumPushStore.endpoint(c)
          val b = Bundle()
          b.putString("url", ep?.get("url"))
          b.putString("pubKey", ep?.get("pubKey"))
          b.putString("auth", ep?.get("auth"))
          sendEvent("onEndpoint", b)
        }
      }
    }

    OnDestroy {
      VardumPushStore.listener = null
    }

    Function("getDistributors") {
      UnifiedPush.getDistributors(ctx)
    }

    Function("getSavedDistributor") {
      UnifiedPush.getSavedDistributor(ctx)
    }

    Function("getAckDistributor") {
      UnifiedPush.getAckDistributor(ctx)
    }

    Function("saveDistributor") { pkg: String ->
      UnifiedPush.saveDistributor(ctx, pkg)
    }

    Function("register") { vapid: String? ->
      UnifiedPush.register(ctx, INSTANCE_DEFAULT, "Vardum", vapid)
    }

    Function("unregister") {
      UnifiedPush.unregister(ctx, INSTANCE_DEFAULT)
      VardumPushStore.clear(ctx)
    }

    Function("getEndpoint") {
      VardumPushStore.endpoint(ctx)
    }

    Function("getLastError") {
      VardumPushStore.lastError(ctx)
    }
  }
}
