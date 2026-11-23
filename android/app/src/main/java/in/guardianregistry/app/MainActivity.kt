package `in`.guardianregistry.app

import android.Manifest
import android.app.Activity
import android.app.AlertDialog
import android.graphics.Color
import android.graphics.Typeface
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.InputType
import android.view.Gravity
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.Executors

/**
 * One screen, rebuilt from data: sign in, then "Payments waiting" for guardians, your own
 * protection (pause payments), alerts, and lost-phone. Views are built in code to keep
 * the app dependency-free. Labels are string resources (English, and Hindi in values-hi);
 * names, payees and alerts come from the server and are shown as plain text.
 */
class MainActivity : Activity() {
    private val io = Executors.newSingleThreadExecutor()
    private val main = Handler(Looper.getMainLooper())
    private lateinit var store: Store
    private lateinit var key: DeviceKey
    private lateinit var root: LinearLayout

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        store = Store(this)
        key = DeviceKey(this)
        PushService.init(this)
        root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), dp(24), dp(16), dp(24))
        }
        setContentView(ScrollView(this).apply { addView(root) })
        if (Build.VERSION.SDK_INT >= 33) requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 1)
    }

    override fun onResume() {
        super.onResume()
        if (store.token == null) showSignIn() else loadHome()
    }

    private fun api() = Api(BuildConfig.API_BASE, store.token)

    /** Run [work] off the main thread, then [done] on it. Shows API errors as a toast. */
    private fun <T> bg(work: () -> T, done: (T) -> Unit) {
        io.execute {
            try {
                val out = work()
                main.post { done(out) }
            } catch (e: ApiError) {
                main.post {
                    if (e.status == 401) signedOut(getString(R.string.signed_out_reason, e.message ?: "")) else toast(e.message ?: getString(R.string.error))
                }
            } catch (e: Exception) {
                main.post { toast(getString(R.string.cant_reach)) }
            }
        }
    }

    // ---------------------------------------------------------------- sign-in
    private fun showSignIn(message: String? = null) {
        root.removeAllViews()
        title(getString(R.string.app_name))
        para(getString(R.string.intro))
        message?.let { para(it, Color.parseColor("#9A3412")) }
        val mobile = input(getString(R.string.mobile_number), InputType.TYPE_CLASS_PHONE, store.mobile)
        button(getString(R.string.send_code)) {
            val m = mobile.text.toString().trim()
            bg({ Api(BuildConfig.API_BASE, null).post("/v1/auth/otp", JSONObject().put("mobile", m).put("language", Wire.language())) as JSONObject }) {
                store.mobile = m
                showCode(m, it.optString("dev_code").ifBlank { null })
            }
        }
    }

    private fun showCode(mobile: String, devCode: String?) {
        root.removeAllViews()
        title(getString(R.string.enter_code))
        para(getString(R.string.code_sent, mobile))
        val code = input(getString(R.string.code), InputType.TYPE_CLASS_NUMBER, devCode)
        val name = input(getString(R.string.your_name_first), InputType.TYPE_CLASS_TEXT, null)
        button(getString(R.string.sign_in)) {
            val c = code.text.toString().trim()
            val n = name.text.toString().trim()
            bg({ signIn(mobile, c, n) }) { out ->
                store.token = out.getString("token")
                PushService.refresh(this)
                if (out.optBoolean("restricted")) {
                    toast(getString(R.string.signed_in_limits, out.optJSONArray("restriction_reasons")?.join(", ") ?: ""))
                }
                loadHome()
            }
        }
        button(getString(R.string.back), secondary = true) { showSignIn() }
    }

    /** OTP + device key proof. The key is created (and attested) on first use. */
    private fun signIn(mobile: String, code: String, name: String): JSONObject {
        val anon = Api(BuildConfig.API_BASE, null)
        val challenge = (anon.post("/v1/auth/challenge") as JSONObject).getString("challenge")
        val attestation = if (!key.exists) key.create(challenge) else null
        val body = Wire.verifyBody(mobile, code, name, store.deviceId, key.publicKey(), challenge,
            key.sign(challenge), attestation)
        return try {
            anon.post("/v1/auth/verify", body) as JSONObject
        } catch (e: ApiError) {
            if (e.status == 401 && e.message?.contains("revoked") == true) key.delete()  // reinstall-equivalent
            throw e
        }
    }

    private fun signedOut(message: String) {
        store.token = null
        showSignIn(message)
    }

    // ---------------------------------------------------------------- home
    private fun loadHome() {
        bg({
            val a = api()
            Home(a.obj("/v1/me"), a.obj("/v1/me/rules"), a.obj("/v1/guardian/inbox"), a.arr("/v1/guardian/wards"),
                a.arr("/v1/me/notifications?limit=20"))
        }) { showHome(it) }
    }

    private data class Home(val me: JSONObject, val rules: JSONObject, val inbox: JSONObject, val wards: JSONArray, val alerts: JSONArray)

    private fun showHome(h: Home) {
        root.removeAllViews()
        title(getString(R.string.hello, h.me.optString("display_name")))
        val names = HashMap<String, String>()
        for (i in 0 until h.wards.length()) {
            val w = h.wards.getJSONObject(i)
            names[w.optString("principal_id")] = w.optString("principal_name")
        }

        val invites = h.inbox.optJSONArray("invitations") ?: JSONArray()
        for (i in 0 until invites.length()) {
            val g = invites.getJSONObject(i)
            card(getString(R.string.asked_guardian, g.optString("principal_name")))
            row(
                getString(R.string.accept) to { act("/v1/guardian/invitations/${g.getString("id")}/accept", getString(R.string.you_protect_them)) },
                getString(R.string.decline) to { act("/v1/guardian/invitations/${g.getString("id")}/decline", getString(R.string.declined)) },
            )
        }

        heading(getString(R.string.payments_waiting))
        val held = h.inbox.optJSONArray("held_payments") ?: JSONArray()
        if (held.length() == 0) para(getString(R.string.nothing_waiting), Color.GRAY)
        for (i in 0 until held.length()) {
            val p = held.getJSONObject(i)
            val who = names[p.optString("principal_id")]?.let { getString(R.string.from_person, it) } ?: ""
            card(getString(R.string.amount_to, Wire.rupees(p.optLong("amount")), p.optString("payee"), who))
            val id = p.getString("check_id")
            if (p.optString("status") == "pending_approval") {
                row(
                    getString(R.string.approve) to { confirm(getString(R.string.approve_q)) { act("/v1/guardian/payments/$id/approve", getString(R.string.approved)) } },
                    getString(R.string.deny) to { act("/v1/guardian/payments/$id/deny", getString(R.string.denied)) },
                )
            } else {
                row(getString(R.string.stop_payment) to { act("/v1/guardian/payments/$id/cancel", getString(R.string.cancelled)) })
            }
        }

        heading(getString(R.string.my_protection))
        val paused = h.rules.optBoolean("kill_switch")
        if (paused) {
            para(getString(R.string.all_paused), Color.parseColor("#9A3412"))
            button(getString(R.string.resume), secondary = true) { act("/v1/me/kill-switch/off", getString(R.string.resume_requested)) }
        } else {
            button(getString(R.string.pause_all)) {
                confirm(getString(R.string.pause_q)) {
                    act("/v1/me/kill-switch/on", getString(R.string.paused))
                }
            }
        }

        heading(getString(R.string.alerts))
        if (h.alerts.length() == 0) para(getString(R.string.no_alerts), Color.GRAY)
        for (i in 0 until minOf(h.alerts.length(), 10)) {
            val n = h.alerts.getJSONObject(i)
            card(n.optString("title") + "\n" + n.optString("body"))
        }

        heading(getString(R.string.security))
        button(getString(R.string.lost_phone), secondary = true) {
            confirm(getString(R.string.lost_q)) {
                bg({ api().post("/v1/me/security/lost-phone") }) { signedOut(getString(R.string.lost_done)) }
            }
        }
        button(getString(R.string.sign_out), secondary = true) {
            bg({ api().post("/v1/auth/logout", JSONObject().put("everywhere", false)) }) { signedOut(getString(R.string.signed_out)) }
        }
        button(getString(R.string.refresh), secondary = true) { loadHome() }
    }

    private fun act(path: String, done: String) {
        bg({ api().post(path) }) {
            toast(done)
            loadHome()
        }
    }

    // ---------------------------------------------------------------- tiny view kit
    private fun dp(v: Int) = (v * resources.displayMetrics.density).toInt()

    private fun title(text: String) = root.addView(TextView(this).apply {
        this.text = text; textSize = 24f; typeface = Typeface.DEFAULT_BOLD; setPadding(0, 0, 0, dp(12))
    })

    private fun heading(text: String) = root.addView(TextView(this).apply {
        this.text = text; textSize = 18f; typeface = Typeface.DEFAULT_BOLD; setPadding(0, dp(20), 0, dp(6))
    })

    private fun para(text: String, color: Int = Color.DKGRAY) = root.addView(TextView(this).apply {
        this.text = text; textSize = 15f; setTextColor(color); setPadding(0, dp(4), 0, dp(8))
    })

    private fun card(text: String) = root.addView(TextView(this).apply {
        this.text = text; textSize = 16f; setTextColor(Color.BLACK)
        setBackgroundColor(Color.parseColor("#F1F5F9")); setPadding(dp(12), dp(12), dp(12), dp(12))
        layoutParams = LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(8) }
    })

    private fun input(hint: String, type: Int, value: String?): EditText = EditText(this).apply {
        this.hint = hint; inputType = type; setText(value ?: ""); textSize = 18f
        root.addView(this)
    }

    private fun button(text: String, secondary: Boolean = false, onClick: () -> Unit) {
        root.addView(makeButton(text, secondary, onClick).apply {
            layoutParams = LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(8) }
        })
    }

    private fun row(vararg buttons: Pair<String, () -> Unit>) {
        val r = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; gravity = Gravity.END }
        buttons.forEachIndexed { i, (label, onClick) ->
            r.addView(makeButton(label, i > 0, onClick).apply {
                layoutParams = LinearLayout.LayoutParams(0, -2, 1f).apply { marginStart = if (i > 0) dp(8) else 0 }
            })
        }
        root.addView(r)
    }

    private fun makeButton(text: String, secondary: Boolean, onClick: () -> Unit) = Button(this).apply {
        this.text = text; isAllCaps = false; textSize = 16f
        if (!secondary) { setBackgroundColor(Color.parseColor("#1F5FBF")); setTextColor(Color.WHITE) }
        setOnClickListener(View.OnClickListener { onClick() })
    }

    private fun confirm(question: String, yes: () -> Unit) {
        AlertDialog.Builder(this).setMessage(question)
            .setPositiveButton(getString(R.string.yes)) { _, _ -> yes() }
            .setNegativeButton(getString(R.string.no), null).show()
    }

    private fun toast(text: String) = Toast.makeText(this, text, Toast.LENGTH_LONG).show()
}
