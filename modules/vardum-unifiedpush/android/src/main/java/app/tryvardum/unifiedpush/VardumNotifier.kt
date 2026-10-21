package app.tryvardum.unifiedpush

import android.Manifest
import android.annotation.SuppressLint
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.BitmapFactory
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat

/**
 * Shows the contentless Vardum banner natively.
 *
 * Uses the SAME channel ids the JS side creates in src/notifications.ts
 * ('default' = Messages, HIGH; 'calls' = Calls, MAX), so the user's channel
 * settings apply to both paths. If JS has never run on this install, the
 * channels are created here with the same importance.
 */
object VardumNotifier {
  private const val CH_MESSAGES = "default"
  private const val CH_CALLS = "calls"
  private const val ID_MESSAGE = 7001
  private const val ID_CALL = 7002
  private const val TEAL = 0xFF20D9C2.toInt()

  @SuppressLint("MissingPermission") // checked explicitly below
  fun show(c: Context, call: Boolean) {
    if (Build.VERSION.SDK_INT >= 33 &&
      ContextCompat.checkSelfPermission(c, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
    ) return

    ensureChannels(c)

    val launch = c.packageManager.getLaunchIntentForPackage(c.packageName)?.apply {
      addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP)
    }
    val tap = launch?.let {
      PendingIntent.getActivity(
        c,
        if (call) ID_CALL else ID_MESSAGE,
        it,
        PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
      )
    }

    val n = NotificationCompat.Builder(c, if (call) CH_CALLS else CH_MESSAGES)
      .setSmallIcon(R.drawable.vardum_notify)
      .setLargeIcon(BitmapFactory.decodeResource(c.resources, R.drawable.vardum_notify_large))
      .setColor(TEAL)
      .setContentTitle("Vardum")
      .setContentText(if (call) "Incoming call" else "Notification")
      .setPriority(if (call) NotificationCompat.PRIORITY_MAX else NotificationCompat.PRIORITY_HIGH)
      .setCategory(if (call) NotificationCompat.CATEGORY_CALL else NotificationCompat.CATEGORY_MESSAGE)
      .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
      .setAutoCancel(true)
      .apply { if (tap != null) setContentIntent(tap) }
      .build()

    NotificationManagerCompat.from(c).notify(if (call) ID_CALL else ID_MESSAGE, n)
  }

  private fun ensureChannels(c: Context) {
    if (Build.VERSION.SDK_INT < 26) return
    val nm = c.getSystemService(NotificationManager::class.java) ?: return
    if (nm.getNotificationChannel(CH_MESSAGES) == null) {
      nm.createNotificationChannel(
        NotificationChannel(CH_MESSAGES, "Messages", NotificationManager.IMPORTANCE_HIGH).apply {
          lockscreenVisibility = android.app.Notification.VISIBILITY_PUBLIC
          vibrationPattern = longArrayOf(0, 250, 250, 250)
          enableVibration(true)
        },
      )
    }
    if (nm.getNotificationChannel(CH_CALLS) == null) {
      nm.createNotificationChannel(
        NotificationChannel(CH_CALLS, "Calls", NotificationManager.IMPORTANCE_MAX).apply {
          lockscreenVisibility = android.app.Notification.VISIBILITY_PUBLIC
          vibrationPattern = longArrayOf(0, 600, 800, 600, 800)
          enableVibration(true)
        },
      )
    }
  }
}
