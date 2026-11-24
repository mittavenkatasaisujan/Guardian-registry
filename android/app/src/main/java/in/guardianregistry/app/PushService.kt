package `in`.guardianregistry.app

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import com.google.firebase.FirebaseApp
import com.google.firebase.FirebaseOptions
import com.google.firebase.messaging.FirebaseMessaging
import com.google.firebase.messaging.FirebaseMessagingService
import com.google.firebase.messaging.RemoteMessage
import org.json.JSONObject
import java.util.concurrent.Executors

/**
 * Push alerts (FCM). Push goes to the app, not the phone number, so it keeps working
 * during a SIM-swap window when SMS to the number is withheld.
 *
 * Firebase is set up from build properties (grFcm*), so no google-services.json is needed;
 * with them empty the app builds and runs without push.
 */
class PushService : FirebaseMessagingService() {

    override fun onNewToken(token: String) {
        Store(this).pushToken = token
        register(this)
    }

    override fun onMessageReceived(message: RemoteMessage) {
        val n = message.notification ?: return
        show(this, n.title ?: getString(R.string.app_name), n.body ?: "")
    }

    companion object {
        private const val CHANNEL = "alerts"
        private val io = Executors.newSingleThreadExecutor()

        fun configured(): Boolean = BuildConfig.FCM_PROJECT_ID.isNotEmpty() && BuildConfig.FCM_APP_ID.isNotEmpty()

        fun init(context: Context) {
            if (!configured() || FirebaseApp.getApps(context).isNotEmpty()) return
            FirebaseApp.initializeApp(
                context,
                FirebaseOptions.Builder()
                    .setProjectId(BuildConfig.FCM_PROJECT_ID)
                    .setApplicationId(BuildConfig.FCM_APP_ID)
                    .setApiKey(BuildConfig.FCM_API_KEY)
                    .setGcmSenderId(BuildConfig.FCM_SENDER_ID)
                    .build()
            )
        }

        /** Fetch the current token and tell the registry (after sign-in). */
        fun refresh(context: Context) {
            if (!configured()) return
            init(context)
            FirebaseMessaging.getInstance().token.addOnSuccessListener { t ->
                Store(context).pushToken = t
                register(context)
            }
        }

        private fun register(context: Context) {
            val store = Store(context)
            val session = store.token ?: return
            val push = store.pushToken ?: return
            io.execute {
                try {
                    Api(store.apiBase, session).post(
                        "/v1/me/alerts/push", JSONObject().put("token", push).put("platform", "android")
                    )
                } catch (e: Exception) {
                    // retried on the next sign-in / token refresh
                }
            }
        }

        fun show(context: Context, title: String, body: String) {
            val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            nm.createNotificationChannel(
                NotificationChannel(CHANNEL, context.getString(R.string.alerts_channel), NotificationManager.IMPORTANCE_HIGH)
            )
            if (Build.VERSION.SDK_INT >= 33 &&
                context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
            ) return
            val open = PendingIntent.getActivity(
                context, 0, Intent(context, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE
            )
            val notification = android.app.Notification.Builder(context, CHANNEL)
                .setSmallIcon(R.drawable.ic_shield)
                .setContentTitle(title)
                .setContentText(body)
                .setStyle(android.app.Notification.BigTextStyle().bigText(body))
                .setContentIntent(open)
                .setAutoCancel(true)
                .build()
            nm.notify((System.currentTimeMillis() % Int.MAX_VALUE).toInt(), notification)
        }
    }
}
