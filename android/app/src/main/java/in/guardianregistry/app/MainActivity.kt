package `in`.guardianregistry.app

import android.Manifest
import android.app.Activity
import android.app.AlertDialog
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.os.Build
import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.InputType
import android.view.Gravity
import android.view.View
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.Spinner
import android.widget.TextView
import android.widget.Toast
import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.Executors

/**
 * The same four screens as the web app: My protection, I protect, Alerts and Devices, with a
 * tab bar, badges, the restricted-sign-in banner, and a refresh every 15 seconds (not while
 * typing). Views are built in code to keep the app dependency-free. Labels are string
 * resources (English, Hindi in values-hi, other languages generated from the catalog);
 * names, payees and alerts come from the server and are shown as plain text.
 */
private const val SAVE_DATA = 41   // request code: save my data to a file

class MainActivity : Activity() {
    private val io = Executors.newSingleThreadExecutor()
    private val main = Handler(Looper.getMainLooper())
    private lateinit var store: Store
    private lateinit var key: DeviceKey
    private lateinit var tabs: LinearLayout
    private lateinit var banner: TextView
    private lateinit var scroll: ScrollView
    private lateinit var root: LinearLayout
    private var tab = "me"
    private var dialogOpen = false
    private var resumed = false
    private val tabButtons = HashMap<String, Button>()
    private var insetTop = 0

    /** Something typed into a form and not saved yet: the 15-second refresh waits. */
    private var formDirty = false
    private var noticeOpen = false
    private var shownTab: String? = null   // the tab whose data is on screen (null: still loading)

    /** This sign-in is restricted (new device, or after a SIM change): the registry refuses
     *  approvals and other high-trust actions, so those buttons become a note instead. */
    private var restricted = false
    private var outer: View? = null

    /** Tabs on (signed in) or off (sign-in screens); the status-bar space goes to whichever is on top. */
    private fun showTabs(on: Boolean) {
        tabs.visibility = if (on) View.VISIBLE else View.GONE
        tabs.setPadding(dp(4), (if (on) insetTop else 0) + dp(4), dp(4), dp(6))
        outer?.let { it.setPadding(it.paddingLeft, if (on) 0 else insetTop, it.paddingRight, it.paddingBottom) }
    }

    private val refresher = object : Runnable {
        override fun run() {
            // never redraw over something the person is typing or has typed and not saved yet
            if (resumed && store.token != null && !dialogOpen && !formDirty && currentFocus !is EditText) render(quiet = true)
            main.postDelayed(this, REFRESH_MS)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        store = Store(this)
        key = DeviceKey(this)
        PushService.init(this)
        tab = savedInstanceState?.getString("tab") ?: "me"
        tabs = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            isBaselineAligned = false
            setBackgroundColor(BRAND)
            setPadding(dp(4), dp(4), dp(4), dp(6))
        }
        for ((id, label) in listOf("me" to R.string.tab_me, "guardian" to R.string.tab_guardian,
                                   "alerts" to R.string.alerts, "devices" to R.string.tab_devices)) {
            val b = Button(this).apply {
                text = getString(label); isAllCaps = false; textSize = 13f; setTextColor(Color.WHITE)
                // every tab two lines tall, so one- and two-line labels sit level
                minLines = 2; maxLines = 2; ellipsize = android.text.TextUtils.TruncateAt.END; gravity = Gravity.CENTER
                background = null; minHeight = dp(48); minimumHeight = dp(48); setPadding(dp(4), dp(4), dp(4), dp(4))
                stateListAnimator = null
                setOnClickListener { switchTo(id) }
            }
            tabButtons[id] = b
            tabs.addView(b, LinearLayout.LayoutParams(0, -2, 1f).apply { marginStart = dp(2); marginEnd = dp(2) })
        }
        banner = TextView(this).apply {
            textSize = 14f; setTextColor(Color.parseColor("#7C2D12")); setBackgroundColor(Color.parseColor("#FFEDD5"))
            setPadding(dp(16), dp(10), dp(16), dp(10)); visibility = View.GONE
        }
        root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), dp(16), dp(16), dp(32))
        }
        scroll = ScrollView(this).apply { addView(root); setBackgroundColor(PAGE) }
        setContentView(LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(PAGE)
            // Android 15 draws apps edge to edge: the blue tab bar extends under the status bar,
            // and the page keeps clear of the navigation bar and the keyboard.
            setOnApplyWindowInsetsListener { v, insets ->
                if (Build.VERSION.SDK_INT >= 30) {
                    val bars = insets.getInsets(android.view.WindowInsets.Type.systemBars() or android.view.WindowInsets.Type.ime())
                    insetTop = bars.top
                    v.setPadding(bars.left, 0, bars.right, bars.bottom)
                } else {
                    @Suppress("DEPRECATION")
                    insetTop = insets.systemWindowInsetTop
                    @Suppress("DEPRECATION")
                    v.setPadding(insets.systemWindowInsetLeft, 0, insets.systemWindowInsetRight, insets.systemWindowInsetBottom)
                }
                outer = v
                showTabs(tabs.visibility == View.VISIBLE)
                insets
            }
            addView(tabs, LinearLayout.LayoutParams(-1, -2))
            addView(banner, LinearLayout.LayoutParams(-1, -2))
            addView(scroll, LinearLayout.LayoutParams(-1, 0, 1f))
        })
        if (Build.VERSION.SDK_INT >= 33) requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 1)
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putString("tab", tab)
    }

    @Deprecated("Activity result API; this app has no AndroidX")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        val uri = data?.data
        if (requestCode != SAVE_DATA || resultCode != RESULT_OK || uri == null) return
        bg({
            val json = api().obj("/v1/me/data-export").toString(2)
            contentResolver.openOutputStream(uri, "wt")!!.use { it.write(json.toByteArray(Charsets.UTF_8)) }
        }) { toast(getString(R.string.data_saved)) }
    }

    override fun onResume() {
        super.onResume()
        resumed = true
        if (store.token == null) showSignIn() else render()
        main.removeCallbacks(refresher)
        main.postDelayed(refresher, REFRESH_MS)
    }

    override fun onPause() {
        super.onPause()
        resumed = false
        main.removeCallbacks(refresher)
    }

    private fun api() = Api(store.apiBase, store.token)

    /** Run [work] off the main thread, then [done] on it. Shows API errors as a toast. */
    private fun <T> bg(work: () -> T, quiet: Boolean = false, failed: (() -> Unit)? = null,
                       unreachable: (() -> Unit)? = null, done: (T) -> Unit) {
        io.execute {
            try {
                val out = work()
                main.post { done(out) }
            } catch (e: ApiError) {
                main.post {
                    failed?.invoke()
                    if (e.status == 401) signedOut(getString(R.string.signed_out_reason, e.message ?: ""))
                    else if (!quiet) toast(e.message ?: getString(R.string.error))
                }
            } catch (e: Exception) {
                main.post {
                    failed?.invoke()
                    unreachable?.invoke()
                    if (!quiet && unreachable == null) toast(getString(R.string.cant_reach))
                }
            }
        }
    }

    // ---------------------------------------------------------------- sign-in
    private fun showSignIn(message: String? = null) {
        showTabs(false)
        banner.visibility = View.GONE
        root.removeAllViews()
        title(getString(R.string.app_name))
        para(getString(R.string.intro))
        message?.let { para(it, WARN_TEXT) }
        val c = card()
        val mobile = input(c, getString(R.string.mobile_number), InputType.TYPE_CLASS_PHONE, store.mobile)
        // Debug builds only: point the app at a test server (e.g. the registry on your PC over Wi-Fi).
        val server = if (BuildConfig.DEBUG) input(c, "Server address (testing)", InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI, store.apiBase) else null
        button(c, getString(R.string.send_code)) { b ->
            val m = mobile.text.toString().trim()
            server?.let { store.apiBase = it.text.toString().trim().trimEnd('/') }
            busy(b)
            bg({ Api(store.apiBase, null).post("/v1/auth/otp", JSONObject().put("mobile", m).put("language", Wire.language())) as JSONObject },
               failed = { idle(b) }) {
                store.mobile = m
                showCode(m, it.str("dev_code").ifBlank { null })
            }
        }
    }

    private fun showCode(mobile: String, devCode: String?) {
        root.removeAllViews()
        title(getString(R.string.enter_code))
        para(getString(R.string.code_sent, mobile))
        val c = card()
        devCode?.let { pill(c, getString(R.string.dev_code, it), WARN_BG, WARN_TEXT) }
        val code = input(c, getString(R.string.code), InputType.TYPE_CLASS_NUMBER, devCode)
        val name = input(c, getString(R.string.your_name_first), InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_CAP_WORDS, null)
        val adult = CheckBox(this).apply {
            text = getString(R.string.adult_first); textSize = 16f; setTextColor(INK); minHeight = dp(44)
            c.addView(this, LinearLayout.LayoutParams(-1, -2))
        }
        para(c, getString(R.string.adults_only), MUTED, 13f)
        button(c, getString(R.string.sign_in)) { b ->
            val cd = code.text.toString().trim()
            val n = name.text.toString().trim()
            val isAdult = adult.isChecked
            busy(b)
            bg({ signIn(mobile, cd, n, isAdult) }, failed = { idle(b) }) { out ->
                store.token = out.getString("token")
                PushService.refresh(this)
                when {
                    out.optBoolean("new_user") -> toast(getString(R.string.welcome))
                    out.optBoolean("restricted") ->
                        toast(getString(R.string.signed_in_limits, out.optJSONArray("restriction_reasons")?.let { r ->
                            (0 until r.length()).joinToString("; ") { Wire.readableTimes(r.optString(it)) } } ?: ""))
                }
                tab = "me"
                render()
            }
        }
        button(c, getString(R.string.back), style = Style.SECONDARY) { showSignIn() }
    }

    /** OTP + device key proof. The key is created (and attested) on first use. */
    private fun signIn(mobile: String, code: String, name: String, adult: Boolean): JSONObject {
        val anon = Api(store.apiBase, null)
        val challenge = (anon.post("/v1/auth/challenge") as JSONObject).getString("challenge")
        val attestation = if (!key.exists) key.create(challenge) else null
        val body = Wire.verifyBody(mobile, code, name, store.deviceId, key.publicKey(), challenge,
            key.sign(challenge), attestation, adult)
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

    // ---------------------------------------------------------------- tabs
    private fun switchTo(id: String) {
        if (id == tab) { render(); return }
        tab = id
        shownTab = null
        root.removeAllViews()
        para(getString(R.string.loading), MUTED)
        scroll.scrollTo(0, 0)
        render()
    }

    /** Load the current tab's data, then draw it (keeping the scroll position on a refresh). */
    private fun render(quiet: Boolean = false) {
        showTabs(true)
        for ((id, b) in tabButtons) {
            val on = id == tab
            b.typeface = if (on) Typeface.DEFAULT_BOLD else Typeface.DEFAULT
            b.alpha = if (on) 1f else 0.85f
            b.background = if (on) rounded(Color.argb(56, 255, 255, 255), radius = 10) else null
        }
        val which = tab
        // nothing on screen yet and the server can't be reached: say so, with a way out
        bg({ load(which) }, quiet = quiet, unreachable = {
            if (which == tab && store.token != null && shownTab != which) offlineView() else if (!quiet) toast(getString(R.string.cant_reach))
        }) { data ->
            if (which != tab || store.token == null) return@bg
            shownTab = which
            val y = scroll.scrollY
            restricted = data.security?.optJSONObject("this_session")?.optBoolean("restricted") == true
            root.removeAllViews()
            formDirty = false
            when (which) {
                "guardian" -> guardianView(data)
                "alerts" -> alertsView(data)
                "devices" -> devicesView(data)
                else -> meView(data)
            }
            setBanner(data.security)
            setBadges(data.inbox, data.unread)
            scroll.post { scroll.scrollTo(0, y) }
        }
    }

    /** The server can't be reached and there is nothing to show: name the address, offer a retry
     *  and a way back to the sign-in screen (where test builds can change the address). */
    private fun offlineView() {
        root.removeAllViews()
        val c = card(WARN)
        heading(c, getString(R.string.offline_title))
        para(c, getString(R.string.offline_explain, store.apiBase), MUTED)
        button(c, getString(R.string.try_again)) { _ ->
            root.removeAllViews()
            para(getString(R.string.loading), MUTED)
            render()
        }
        if (BuildConfig.DEBUG) {
            button(c, getString(R.string.change_server), style = Style.SECONDARY) { _ ->
                store.token = null   // a session belongs to one server: sign in again at the new address
                showSignIn()
            }
        }
        button(c, getString(R.string.sign_out_phone), style = Style.SECONDARY) { _ ->
            confirm(getString(R.string.sign_out_phone_q)) { store.token = null; showSignIn() }
        }
    }

    private class Data(
        val inbox: JSONObject, val unread: Int, val security: JSONObject? = null,
        val me: JSONObject? = null, val rules: JSONObject? = null, val guardians: JSONArray? = null,
        val changes: JSONArray? = null, val payments: JSONArray? = null, val presets: JSONObject? = null,
        val wards: JSONArray? = null, val alerts: JSONArray? = null, val devices: JSONArray? = null,
        val myKeyId: String? = null, val nominee: JSONObject? = null,
        val notice: JSONObject? = null, val consents: JSONObject? = null, val erasure: JSONObject? = null,
        val complaints: JSONArray? = null,
    )

    private fun load(which: String): Data {
        val a = api()
        val inbox = a.obj("/v1/guardian/inbox")
        val unread = a.arr("/v1/me/notifications?unread_only=true&limit=100").length()
        return when (which) {
            "guardian" -> Data(inbox, unread, security = a.obj("/v1/me/security"), wards = a.arr("/v1/guardian/wards"))
            "alerts" -> Data(inbox, unread, security = a.obj("/v1/me/security"), alerts = a.arr("/v1/me/notifications?limit=50"))
            "devices" -> Data(inbox, unread, security = a.obj("/v1/me/security"), devices = a.arr("/v1/me/devices"),
                              myKeyId = if (key.exists) Wire.keyId(key.publicKey()) else null)
            else -> Data(inbox, unread, security = a.obj("/v1/me/security"), me = a.obj("/v1/me"),
                          rules = a.obj("/v1/me/rules"), guardians = a.arr("/v1/me/guardians"),
                          changes = a.arr("/v1/me/changes"), payments = a.arr("/v1/me/payments?limit=10"),
                          presets = a.obj("/v1/presets"), nominee = a.obj("/v1/me/nominee").optJSONObject("nominee"),
                          notice = a.obj("/v1/privacy/notice"), consents = a.obj("/v1/me/consents"),
                          erasure = a.obj("/v1/me/erasure").optJSONObject("erasure"),
                          complaints = a.arr("/v1/me/grievances"))
        }
    }

    private fun setBanner(security: JSONObject?) {
        val session = security?.optJSONObject("this_session") ?: return
        if (session.optBoolean("restricted")) {
            val reasons = session.optJSONArray("reasons")?.let { r -> (0 until r.length()).joinToString("; ") { Wire.readableTimes(r.optString(it)) } } ?: ""
            banner.text = getString(R.string.restricted_banner, reasons)
            banner.visibility = View.VISIBLE
        } else {
            banner.visibility = View.GONE
        }
    }

    private fun setBadges(inbox: JSONObject, unread: Int) {
        val n = listOf("held_payments", "pending_changes", "invitations", "recoveries").sumOf { inbox.optJSONArray(it)?.length() ?: 0 }
        tabButtons["guardian"]?.text = getString(R.string.tab_guardian) + if (n > 0) " ($n)" else ""
        tabButtons["alerts"]?.text = getString(R.string.alerts) + if (unread > 0) " ($unread)" else ""
    }

    // ---------------------------------------------------------------- My protection
    private fun meView(d: Data) {
        val me = d.me!!
        val rules = d.rules!!
        val security = d.security!!
        title(getString(R.string.hello, me.str("display_name")))
        para(getString(R.string.identity, identityText(me.str("identity_level"))), MUTED, 13f)

        // DPDP: the notice, and a clear "I agree", before the protection is relied on
        val notice = d.notice!!
        val agreed = d.consents?.optBoolean("accepted_current") == true
        if (!agreed) {
            val pc = card(WARN)
            heading(pc, getString(R.string.privacy_notice))
            para(pc, getString(R.string.privacy_please))
            noticeToggle(pc, notice)
            button(pc, getString(R.string.privacy_agree)) { b ->
                act(b, { api().post("/v1/me/consents", JSONObject().put("notice_version", notice.str("version"))) }) {
                    getString(R.string.privacy_thanks)
                }
            }
        }

        val paused = rules.optBoolean("kill_switch")
        val status = card(if (paused) BAD else OK)
        bigStatus(status, if (paused) getString(R.string.payments_paused) else getString(R.string.payments_on), if (paused) BAD else OK)
        para(status, if (paused) getString(R.string.paused_explain) else getString(R.string.on_explain), MUTED)
        if (paused && restricted) {
            restrictedNote(status)
        } else if (paused) {
            button(status, getString(R.string.switch_back_on), style = Style.SECONDARY) { b ->
                act(b, { api().post("/v1/me/kill-switch/off") as JSONObject }) {
                    if (it.optBoolean("applied")) getString(R.string.back_on) else getString(R.string.held_24h)
                }
            }
        } else {
            button(status, getString(R.string.pause_all_payments), style = Style.DANGER) { b ->
                act(b, { api().post("/v1/me/kill-switch/on") }) { getString(R.string.all_paused_toast) }
            }
        }

        if (security.optBoolean("sim_swap_window_open")) {
            val c = card(WARN)
            heading(c, getString(R.string.sim_title))
            para(c, getString(R.string.sim_until, Wire.time(security.str("window_ends_at"))))
            para(c, getString(R.string.sim_explain), MUTED)
            if (restricted) restrictedNote(c) else button(c, getString(R.string.sim_confirm)) { b ->
                act(b, { api().post("/v1/me/security/confirm-sim-change") }) { getString(R.string.sim_confirmed) }
            }
        }

        val pending = d.changes!!.objects().filter { it.str("status") == "pending" }
        if (pending.isNotEmpty()) {
            val c = card(WARN)
            heading(c, getString(R.string.changes_waiting))
            for (ch in pending) {
                item(c)
                para(c, changeLabel(ch.str("kind")), bold = true)
                para(c, getString(R.string.takes_effect, Wire.time(ch.str("effective_at"))), MUTED, 13f)
            }
        }

        val r = card()
        heading(r, getString(R.string.my_rules))
        val rows = listOf(
            R.string.rule_per_txn to money(rules, "per_txn_limit"),
            R.string.rule_daily to money(rules, "daily_limit"),
            R.string.rule_approval to money(rules, "approval_threshold"),
            R.string.rule_new_payee to money(rules, "new_payee_delay_threshold"),
            R.string.rule_cooling to getString(R.string.minutes, rules.optInt("cooling_off_minutes").toString()),
            R.string.rule_timeout to getString(R.string.minutes, rules.optInt("approval_timeout_minutes").toString()),
            R.string.rule_channels to (rules.optJSONArray("blocked_channels")?.let { a ->
                if (a.length() == 0) null else (0 until a.length()).joinToString(", ") { a.optString(it).uppercase() }
            } ?: getString(R.string.none)),
            R.string.rule_verified to yesNo(rules.optBoolean("require_verified_guardian")),
            R.string.rule_sim to yesNo(rules.optBoolean("sim_swap_hold")),
            R.string.rule_scam to yesNo(rules.optBoolean("scam_signals")),
            R.string.rule_payee to money(rules, "per_payee_daily_limit"),
            R.string.rule_channel_limits to (rules.optJSONObject("channel_daily_limits")?.let { m ->
                m.keys().asSequence().toList().sorted().joinToString(" · ") { "${it.uppercase()} ${Wire.rupees(m.optLong(it))}" }
                    .ifEmpty { null }
            } ?: getString(R.string.none)),
            R.string.rule_scope to getString(if (rules.str("approval_scope") == "rbi") R.string.scope_rbi else R.string.scope_all),
            R.string.rule_wait to rules.optInt("new_guardian_wait_hours").let {
                if (it > 0) getString(R.string.hours, it.toString()) else getString(R.string.right_away)
            },
            R.string.quiet_hours to (rules.optJSONObject("quiet_hours")?.let { quietText(it) } ?: getString(R.string.none)),
        )
        for ((label, value) in rows) keyValue(r, getString(label), value)
        para(r, getString(R.string.preset_label), bold = true).apply { setPadding(0, dp(14), 0, dp(4)) }
        val presets = d.presets!!
        val names = presets.keys().asSequence().toList()
        val spinner = Spinner(this).apply {
            // long preset names wrap instead of being cut off, closed and open
            adapter = object : ArrayAdapter<String>(this@MainActivity, android.R.layout.simple_spinner_dropdown_item,
                names.map { presets.optJSONObject(it)?.str("label") ?: it }) {
                private fun wrap(v: View): View = v.apply {
                    (this as? TextView)?.apply { isSingleLine = false; maxLines = 3; ellipsize = null; textSize = 15f; setTextColor(INK) }
                }
                override fun getView(position: Int, convertView: View?, parent: android.view.ViewGroup): View =
                    wrap(super.getView(position, convertView, parent))
                override fun getDropDownView(position: Int, convertView: View?, parent: android.view.ViewGroup): View =
                    wrap(super.getDropDownView(position, convertView, parent))
            }
            contentDescription = getString(R.string.preset_label)
        }
        r.addView(spinner, LinearLayout.LayoutParams(-1, -2))
        button(r, getString(R.string.apply), style = Style.SECONDARY) { b ->
            val name = names.getOrNull(spinner.selectedItemPosition) ?: return@button
            act(b, { api().post("/v1/me/rules/preset/" + java.net.URLEncoder.encode(name, "UTF-8")) as JSONObject }) {
                if (it.optBoolean("held")) getString(R.string.preset_held) else getString(R.string.applied)
            }
        }
        para(r, getString(R.string.rules_note), MUTED, 13f)

        // the person's own limits (RBI's draft calls these customer-induced controls)
        val lc = card()
        heading(lc, getString(R.string.change_limits))
        para(lc, getString(R.string.limits_note), MUTED, 13f)
        val limitFields = listOf(
            Triple("per_txn_limit", R.string.lim_txn, rules), Triple("daily_limit", R.string.lim_day, rules),
            Triple("per_payee_daily_limit", R.string.lim_payee, rules), Triple("approval_threshold", R.string.lim_approve, rules),
        ).map { (key, label, rs) ->
            para(lc, getString(label), bold = true).apply { setPadding(0, dp(10), 0, 0) }
            key to input(lc, getString(R.string.no_limit), InputType.TYPE_CLASS_NUMBER,
                if (rs.isNull(key) || !rs.has(key)) null else (rs.optLong(key) / 100).toString())
                .apply { contentDescription = getString(label) }   // screen readers name each box
        }
        button(lc, getString(R.string.save_limits), style = Style.SECONDARY) { b ->
            val body = JSONObject()
            for ((key, field) in limitFields) {
                val text = field.text.toString().replace(",", "").replace("₹", "").trim()
                if (text.isEmpty()) {
                    body.put(key, JSONObject.NULL)
                } else {
                    val rupees = text.toLongOrNull()
                    if (rupees == null || rupees <= 0) { toast(getString(R.string.amount_invalid)); field.requestFocus(); return@button }
                    body.put(key, rupees * 100)
                }
            }
            act(b, { api().put("/v1/me/rules", body) as JSONObject }) {   // PUT: same as PATCH on the server
                if (it.isNull("held")) getString(R.string.saved) else getString(R.string.preset_held)
            }
        }

        // quiet hours: chosen channels off every day between two hours (RBI's draft time-window control)
        val qc = card()
        heading(qc, getString(R.string.quiet_hours))
        para(qc, getString(R.string.quiet_note), MUTED, 13f)
        val quiet = rules.optJSONObject("quiet_hours")
        val quietOn = quiet?.optJSONArray("channels")?.let { a -> (0 until a.length()).map { a.getString(it) } } ?: emptyList()
        para(qc, getString(R.string.quiet_channels), bold = true).apply { setPadding(0, dp(10), 0, 0) }
        val boxes = CHANNEL_KEYS.map { c ->
            c to CheckBox(this).apply {
                text = channelName(c); textSize = 16f; setTextColor(INK); minHeight = dp(44)
                isChecked = c in quietOn
                setOnCheckedChangeListener { _, _ -> formDirty = true }
                qc.addView(this, LinearLayout.LayoutParams(-1, -2))
            }
        }
        fun hourSpinner(label: Int, value: Int): Spinner {
            para(qc, getString(label), bold = true).apply { setPadding(0, dp(10), 0, 0) }
            return Spinner(this).apply {
                adapter = ArrayAdapter(this@MainActivity, android.R.layout.simple_spinner_dropdown_item, (0..23).map { hourText(it) })
                setSelection(value)
                contentDescription = getString(label)
                onItemSelectedListener = object : android.widget.AdapterView.OnItemSelectedListener {
                    override fun onItemSelected(p: android.widget.AdapterView<*>?, v: View?, pos: Int, id: Long) {
                        if (pos != value) formDirty = true   // the first call is the initial selection
                    }
                    override fun onNothingSelected(p: android.widget.AdapterView<*>?) {}
                }
                qc.addView(this, LinearLayout.LayoutParams(-1, dp(52)))
            }
        }
        val from = hourSpinner(R.string.quiet_from, quiet?.optInt("start", 22) ?: 22)
        val to = hourSpinner(R.string.quiet_to, quiet?.optInt("end", 6) ?: 6)
        button(qc, getString(R.string.save_quiet), style = Style.SECONDARY) { b ->
            val chosen = boxes.filter { it.second.isChecked }.map { it.first }
            if (chosen.isEmpty() || from.selectedItemPosition == to.selectedItemPosition) {
                toast(getString(R.string.quiet_invalid)); return@button
            }
            val body = JSONObject().put("quiet_hours", JSONObject()
                .put("channels", org.json.JSONArray(chosen)).put("start", from.selectedItemPosition).put("end", to.selectedItemPosition))
            act(b, { api().put("/v1/me/rules", body) as JSONObject }) {
                if (it.isNull("held")) getString(R.string.saved) else getString(R.string.preset_held)
            }
        }
        if (quiet != null) {
            button(qc, getString(R.string.quiet_off), style = Style.SECONDARY) { b ->
                act(b, { api().put("/v1/me/rules", JSONObject().put("quiet_hours", JSONObject.NULL)) as JSONObject }) {
                    if (it.isNull("held")) getString(R.string.saved) else getString(R.string.held_24h)
                }
            }
        }

        val g = card()
        heading(g, getString(R.string.my_guardians))
        val guardians = d.guardians!!.objects()
        if (guardians.isEmpty()) para(g, getString(R.string.no_guardians), MUTED)
        for (x in guardians) {
            item(g)
            val st = x.str("status")
            rowWithPill(g, x.str("guardian_name"), identityText(x.str("guardian_identity_level")), statusWord(st),
                when (st) { "active" -> OK; "invited" -> WARN; else -> MUTED })
        }
        para(g, getString(R.string.invite_label), bold = true).apply { setPadding(0, dp(14), 0, dp(4)) }
        if (restricted) {
            restrictedNote(g)
        } else {
            val gm = input(g, getString(R.string.mobile_number), InputType.TYPE_CLASS_PHONE, null)
            button(g, getString(R.string.invite)) { b ->
                val m = gm.text.toString().trim()
                if (m.isEmpty()) { gm.requestFocus(); return@button }
                act(b, { api().post("/v1/me/guardians", JSONObject().put("mobile", m)) }) { getString(R.string.invite_sent) }
            }
        }

        val p = card()
        heading(p, getString(R.string.recent_payments))
        val payments = d.payments!!.objects()
        if (payments.isEmpty()) para(p, getString(R.string.no_payments), MUTED)
        for (x in payments) paymentItem(p, x, null)

        // DPDP Act: correct your name (s.12), nominate someone (s.14)
        val yd = card()
        heading(yd, getString(R.string.your_details))
        para(yd, getString(R.string.your_name), bold = true)
        val nameField = input(yd, getString(R.string.your_name), InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_CAP_WORDS,
            me.str("display_name"))
        button(yd, getString(R.string.save_name), style = Style.SECONDARY) { b ->
            val n = nameField.text.toString().trim()
            if (n.isEmpty()) { nameField.requestFocus(); return@button }
            act(b, { api().put("/v1/me/name", JSONObject().put("display_name", n)) }) { getString(R.string.name_saved) }
        }
        para(yd, getString(R.string.nominee), bold = true).apply { textSize = 16f; setPadding(0, dp(16), 0, dp(2)) }
        para(yd, getString(R.string.nominee_explain), MUTED, 13f)
        val nom = d.nominee
        if (nom != null) {
            rowWithPill(yd, nom.str("name"), nom.str("relation") + " · " + nom.str("mobile"), null, MUTED)
            if (restricted) restrictedNote(yd) else button(yd, getString(R.string.remove_nominee), style = Style.SECONDARY) { b ->
                act(b, { api().delete("/v1/me/nominee") }) { getString(R.string.nominee_removed) }
            }
        } else {
            para(yd, getString(R.string.no_nominee), MUTED)
            if (restricted) {
                restrictedNote(yd)
            } else {
                val nn = input(yd, getString(R.string.nominee_name), InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_CAP_WORDS, null)
                val nr = input(yd, getString(R.string.nominee_relation), InputType.TYPE_CLASS_TEXT, null)
                val nm = input(yd, getString(R.string.nominee_mobile), InputType.TYPE_CLASS_PHONE, null)
                button(yd, getString(R.string.save_nominee), style = Style.SECONDARY) { b ->
                    val body = JSONObject().put("name", nn.text.toString().trim()).put("relation", nr.text.toString().trim())
                        .put("mobile", nm.text.toString().trim())
                    if (body.getString("name").isEmpty() || body.getString("relation").isEmpty() || body.getString("mobile").isEmpty()) {
                        toast(getString(R.string.nominee_fill)); return@button
                    }
                    act(b, { api().put("/v1/me/nominee", body) }) { getString(R.string.nominee_saved) }
                }
            }
        }

        if (agreed) {
            val pc = card()
            heading(pc, getString(R.string.privacy_notice))
            noticeToggle(pc, notice)
        }

        // DPDP rights: a copy of everything held, and deleting the account (held 7 days)
        val erasure = d.erasure
        val dc = card(if (erasure != null) BAD else null)
        heading(dc, getString(R.string.your_data))
        para(dc, getString(R.string.data_explain), MUTED, 13f)
        if (restricted) restrictedNote(dc) else button(dc, getString(R.string.download_data), style = Style.SECONDARY) {
            // the person picks where to save; the file is written in onActivityResult
            startActivityForResult(Intent(Intent.ACTION_CREATE_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE)
                .setType("application/json").putExtra(Intent.EXTRA_TITLE, "guardian-registry-my-data.json"), SAVE_DATA)
        }
        para(dc, getString(R.string.delete_account), bold = true).apply { textSize = 16f; setPadding(0, dp(16), 0, dp(2)) }
        if (erasure != null) {
            para(dc, getString(R.string.deletion_on, Wire.time(erasure.str("erase_at"))), bold = true)
            para(dc, getString(R.string.deletion_warning), MUTED, 13f)
            button(dc, getString(R.string.cancel_deletion)) { b ->
                act(b, { api().delete("/v1/me/erasure") }) { getString(R.string.deletion_cancelled) }
            }
        } else {
            para(dc, getString(R.string.deletion_explain), MUTED, 13f)
            if (restricted) restrictedNote(dc) else button(dc, getString(R.string.delete_account), style = Style.DANGER) { b ->
                confirm(getString(R.string.deletion_confirm)) {
                    act(b, { api().post("/v1/me/erasure") }) { getString(R.string.deletion_requested) }
                }
            }
        }

        // DPDP Act s.13: complain to the grievance officer; the answer comes back here
        val gc = card()
        heading(gc, getString(R.string.complaints))
        para(gc, getString(R.string.complaints_explain), MUTED, 13f)
        val complaint = input(gc, getString(R.string.your_complaint),
            InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE or InputType.TYPE_TEXT_FLAG_CAP_SENTENCES, null)
            .apply { minLines = 3; gravity = android.view.Gravity.TOP or android.view.Gravity.START; contentDescription = getString(R.string.your_complaint) }
        button(gc, getString(R.string.send_complaint), style = Style.SECONDARY) { b ->
            act(b, { api().post("/v1/me/grievances", JSONObject().put("text", complaint.text.toString().trim())) }) {
                getString(R.string.complaint_sent)
            }
        }
        for (g in d.complaints?.objects() ?: emptyList()) {
            item(gc)
            val answered = g.str("status") == "answered"
            rowWithPill(gc, Wire.time(g.str("created_at")), null, getString(if (answered) R.string.answered else R.string.waiting),
                if (answered) OK else WARN)
            para(gc, g.str("text"), INK, 15f)
            if (answered) para(gc, getString(R.string.our_answer, g.str("answer")), OK, 15f)
            else para(gc, getString(R.string.answer_due, Wire.time(g.str("due_at"))), MUTED, 13f)
        }

        val l = card()
        heading(l, getString(R.string.lost_title))
        para(l, getString(R.string.lost_explain), MUTED)
        button(l, getString(R.string.report_lost), style = Style.DANGER) { b ->
            confirm(getString(R.string.lost_confirm)) {
                busy(b)
                bg({ api().post("/v1/me/security/lost-phone") }, failed = { idle(b) }) { signedOut(getString(R.string.lost_done)) }
            }
        }
    }

    // ---------------------------------------------------------------- I protect
    private fun guardianView(d: Data) {
        val inbox = d.inbox
        val wards = d.wards!!.objects()
        val names = wards.associate { it.str("principal_id") to it.str("principal_name") }
        title(getString(R.string.people_i_protect))

        val invites = inbox.optJSONArray("invitations").objects()
        if (invites.isNotEmpty()) {
            val c = card(WARN)
            heading(c, getString(R.string.guardian_requests))
            for (inv in invites) {
                item(c)
                val who = inv.str("principal_name")
                para(c, getString(R.string.asked_guardian, who))
                val id = inv.getString("id")
                val accept = action(getString(R.string.accept), Style.OK) { b -> act(b, { api().post("/v1/guardian/invitations/$id/accept") }) { getString(R.string.you_protect_name, who) } }
                val decline = action(getString(R.string.decline), Style.SECONDARY) { b -> act(b, { api().post("/v1/guardian/invitations/$id/decline") }) { getString(R.string.declined) } }
                if (restricted) { restrictedNote(c); row(c, decline) } else row(c, accept, decline)
            }
        }

        val held = inbox.optJSONArray("held_payments").objects()
        val w = card(if (held.isNotEmpty()) WARN else null)
        heading(w, getString(R.string.payments_waiting))
        if (held.isEmpty()) para(w, getString(R.string.nothing_waiting), MUTED)
        for (p in held) {
            paymentItem(w, p, names[p.str("principal_id")]?.let { getString(R.string.from_name, it) })
            p.str("narration").ifBlank { null }?.let { para(w, getString(R.string.note_text, it), INK, 15f).apply { setTypeface(typeface, Typeface.ITALIC) } }
            p.str("approval_expires_at").ifBlank { null }?.let { para(w, getString(R.string.answer_by, Wire.time(it)), MUTED, 13f) }
            p.str("release_at").ifBlank { null }?.let { para(w, getString(R.string.goes_through, Wire.time(it)), MUTED, 13f) }
            para(w, getString(R.string.not_sure), MUTED, 13f)
            val id = p.getString("check_id")
            if (p.str("status") == "pending_approval") {
                val approve = action(getString(R.string.approve), Style.OK) { b ->
                    confirm(getString(R.string.approve_q)) { act(b, { api().post("/v1/guardian/payments/$id/approve") }) { getString(R.string.approved) } }
                }
                val deny = action(getString(R.string.deny), Style.DANGER) { b -> act(b, { api().post("/v1/guardian/payments/$id/deny") }) { getString(R.string.denied) } }
                if (restricted) { restrictedNote(w); row(w, deny) } else row(w, approve, deny)
            } else {
                button(w, getString(R.string.stop_payment), style = Style.DANGER) { b ->
                    act(b, { api().post("/v1/guardian/payments/$id/cancel") }) { getString(R.string.cancelled) }
                }
            }
        }

        val changes = inbox.optJSONArray("pending_changes").objects()
        if (changes.isNotEmpty()) {
            val c = card(WARN)
            heading(c, getString(R.string.changes_waiting_g))
            for (ch in changes) {
                item(c)
                para(c, getString(R.string.wants_to, names[ch.str("principal_id")] ?: getString(R.string.someone), changeLabel(ch.str("kind"))))
                para(c, getString(R.string.happens_unless, Wire.time(ch.str("effective_at"))), MUTED, 13f)
                val id = ch.getString("id")
                val stop = action(getString(R.string.stop_it), Style.DANGER) { b -> act(b, { api().post("/v1/guardian/changes/$id/veto") }) { getString(R.string.stopped) } }
                val approveNow = action(getString(R.string.approve_now), Style.SECONDARY) { b -> act(b, { api().post("/v1/guardian/changes/$id/approve") }) { getString(R.string.approved) } }
                if (restricted) { restrictedNote(c); row(c, stop) } else row(c, stop, approveNow)
            }
        }

        val recoveries = inbox.optJSONArray("recoveries").objects()
        if (recoveries.isNotEmpty()) {
            val c = card(BAD)
            heading(c, getString(R.string.recoveries))
            for (rc in recoveries) {
                item(c)
                para(c, getString(R.string.recovery_wants, rc.str("person_name"), rc.str("new_number")))
                para(c, getString(R.string.recovery_warn), MUTED, 13f)
                val opens = rc.str("vouching_opens_at")
                val pendingNow = rc.str("status") == "pending"
                if (pendingNow && Wire.isFuture(opens)) para(c, getString(R.string.recovery_from, Wire.time(opens)), MUTED, 13f)
                val id = rc.getString("recovery_id")
                val deny = action(getString(R.string.deny), Style.DANGER) { b -> act(b, { api().post("/v1/guardian/recoveries/$id/deny") }) { getString(R.string.stopped) } }
                if (pendingNow && restricted) {
                    restrictedNote(c)
                    row(c, deny)
                } else if (pendingNow) {
                    row(c, action(getString(R.string.recovery_approve), Style.OK) { b ->
                        act(b, { api().post("/v1/guardian/recoveries/$id/approve") }) { getString(R.string.recovery_done) }
                    }, deny)
                } else {
                    row(c, deny)
                }
            }
        }

        val pc = card()
        heading(pc, getString(R.string.people_i_protect))
        val active = wards.filter { it.str("status") == "active" }
        if (active.isEmpty()) para(pc, getString(R.string.protect_none), MUTED)
        for (x in active) {
            item(pc)
            val who = x.str("principal_name")
            val id = x.str("principal_id")
            para(pc, who, bold = true)
            button(pc, getString(R.string.pause_theirs), style = Style.DANGER) { b ->
                confirm(getString(R.string.pause_theirs_q, who)) {
                    act(b, { api().post("/v1/guardian/wards/$id/kill-switch/on") }) { getString(R.string.paused_for, who) }
                }
            }
        }
    }

    // ---------------------------------------------------------------- Alerts
    private fun alertsView(d: Data) {
        val items = d.alerts!!.objects()
        title(getString(R.string.alerts))
        if (items.any { !it.optBoolean("read") }) {
            button(root, getString(R.string.mark_all_read), style = Style.SECONDARY) { b ->
                act(b, { api().post("/v1/me/notifications/read", JSONObject()) }) { getString(R.string.all_read) }
            }
        }
        val c = card()
        if (items.isEmpty()) para(c, getString(R.string.no_alerts_yet), MUTED)
        for (n in items) {
            item(c)
            rowWithPill(c, n.str("title"), null, if (n.optBoolean("read")) null else getString(R.string.new_badge), WARN)
            para(c, n.str("body"))
            para(c, Wire.time(n.str("created_at")), MUTED, 13f)
        }
    }

    // ---------------------------------------------------------------- Devices
    private fun devicesView(d: Data) {
        title(getString(R.string.tab_devices))
        val c = card()
        para(c, getString(R.string.devices_explain), MUTED)
        val devices = d.devices!!.objects()
        if (devices.isEmpty()) para(c, getString(R.string.no_devices), MUTED)
        for (x in devices) {
            item(c)
            val kid = x.str("key_id")
            val mine = kid == d.myKeyId
            val st = x.str("status")
            rowWithPill(c, if (mine) getString(R.string.this_device) else getString(R.string.device_id, kid.take(8)),
                getString(R.string.added_at, Wire.time(x.str("created_at"))), statusWord(st),
                when (st) { "trusted" -> OK; "probation" -> WARN; else -> MUTED })
            if (st != "revoked" && !mine && !restricted) {
                button(c, getString(R.string.remove), style = Style.SECONDARY) { b ->
                    act(b, { api().delete("/v1/me/devices/$kid") }) { getString(R.string.removed) }
                }
            }
        }
        val s = card()
        heading(s, getString(R.string.sign_out))
        row(s,
            action(getString(R.string.sign_out_here), Style.SECONDARY) { _ -> signOut(false) },
            action(getString(R.string.sign_out_everywhere), Style.SECONDARY) { _ -> signOut(true) })
    }

    private fun signOut(everywhere: Boolean) {
        val token = store.token
        store.token = null
        showSignIn(getString(R.string.signed_out))
        io.execute {
            try { Api(store.apiBase, token).post("/v1/auth/logout", JSONObject().put("everywhere", everywhere)) } catch (e: Exception) { /* already signed out */ }
        }
    }

    // ---------------------------------------------------------------- shared bits
    private fun paymentItem(parent: LinearLayout, p: JSONObject, extra: String?) {
        item(parent)
        val st = p.str("status")
        val (label, color) = statusPill(st)
        rowWithPill(parent, Wire.rupees(p.optLong("amount")), null, label, color, big = true)
        para(parent, getString(R.string.to_payee, p.str("payee")) + (extra?.let { " · $it" } ?: ""))
        val reasons = p.optJSONArray("reasons")?.let { r -> (0 until r.length()).joinToString("; ") { r.optString(it) } }.orEmpty()
        para(parent, Wire.time(p.str("created_at")) + if (reasons.isNotEmpty()) " · $reasons" else "", MUTED, 13f)
    }

    private fun restrictedNote(parent: LinearLayout) = para(parent, getString(R.string.restricted_action), WARN_TEXT, 13f)

    private fun statusPill(status: String): Pair<String, Int> = when (status) {
        "allowed" -> getString(R.string.st_allowed) to OK
        "approved" -> getString(R.string.st_approved) to OK
        "released" -> getString(R.string.st_released) to OK
        "pending_approval" -> getString(R.string.st_pending_approval) to WARN
        "cooling_off" -> getString(R.string.st_cooling_off) to WARN
        "blocked" -> getString(R.string.st_blocked) to BAD
        "denied" -> getString(R.string.st_denied) to BAD
        "expired" -> getString(R.string.st_expired) to BAD
        "cancelled" -> getString(R.string.st_cancelled) to MUTED
        "failed" -> getString(R.string.st_failed) to MUTED
        else -> status to MUTED
    }

    private fun statusWord(status: String): String = when (status) {
        "active" -> getString(R.string.w_active)
        "invited" -> getString(R.string.w_invited)
        "declined" -> getString(R.string.w_declined)
        "trusted" -> getString(R.string.w_trusted)
        "probation" -> getString(R.string.w_probation)
        "revoked" -> getString(R.string.w_revoked)
        else -> status
    }

    private fun identityText(level: String) = when (level) {
        "bank_verified" -> getString(R.string.id_bank_verified)
        "bank_min_kyc" -> getString(R.string.id_bank_min_kyc)
        "otp" -> getString(R.string.id_otp)
        else -> level
    }

    private fun changeLabel(kind: String) = when (kind) {
        "update_rules" -> getString(R.string.change_update_rules)
        "kill_switch_off" -> getString(R.string.switch_back_on)
        "remove_guardian" -> getString(R.string.change_remove_guardian)
        "change_mobile" -> getString(R.string.change_change_mobile)
        else -> kind
    }

    private fun money(rules: JSONObject, k: String) =
        if (rules.isNull(k) || !rules.has(k)) getString(R.string.no_limit) else Wire.rupees(rules.optLong(k))

    private fun yesNo(b: Boolean) = getString(if (b) R.string.yes else R.string.no)

    /** Disable the button, call the API, toast the result and redraw; re-enable on failure. */
    private fun <T> act(b: Button, call: () -> T, message: (T) -> String) {
        busy(b)
        bg(call, failed = { idle(b) }) { out ->
            toast(message(out))
            render()
        }
    }

    private fun busy(b: Button) { b.isEnabled = false; b.alpha = 0.5f }
    private fun idle(b: Button) { b.isEnabled = true; b.alpha = 1f }

    /** A JSON string field, with JSON null and missing both read as "" (optString would give "null"). */
    private fun JSONObject.str(k: String): String = if (isNull(k)) "" else optString(k)

    private fun JSONArray?.objects(): List<JSONObject> =
        if (this == null) emptyList() else (0 until length()).mapNotNull { optJSONObject(it) }

    // ---------------------------------------------------------------- tiny view kit
    private enum class Style { PRIMARY, SECONDARY, DANGER, OK }

    private fun dp(v: Int) = (v * resources.displayMetrics.density).toInt()

    private fun rounded(fill: Int, stroke: Int? = null, radius: Int = 12) = GradientDrawable().apply {
        setColor(fill); cornerRadius = dp(radius).toFloat()
        stroke?.let { setStroke(dp(1), it) }
    }

    private fun title(text: String) = root.addView(TextView(this).apply {
        this.text = text; textSize = 24f; typeface = Typeface.DEFAULT_BOLD; setTextColor(INK); setPadding(0, 0, 0, dp(6))
    })

    private fun para(text: String, color: Int = INK, size: Float = 15f) = para(root, text, color, size)

    private fun para(parent: LinearLayout, text: String, color: Int = INK, size: Float = 15f, bold: Boolean = false): TextView =
        TextView(this).apply {
            this.text = text; textSize = size; setTextColor(color); setPadding(0, dp(3), 0, dp(3))
            if (bold) typeface = Typeface.DEFAULT_BOLD
            parent.addView(this)
        }

    private fun heading(parent: LinearLayout, text: String) = parent.addView(TextView(this).apply {
        this.text = text; textSize = 18f; typeface = Typeface.DEFAULT_BOLD; setTextColor(INK); setPadding(0, 0, 0, dp(6))
    })

    /** A white card; [accent] adds a coloured border like the web app's alert cards. */
    private fun card(accent: Int? = null): LinearLayout = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        background = rounded(CARD, accent ?: LINE)
        setPadding(dp(16), dp(14), dp(16), dp(14))
        root.addView(this, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(12) })
    }

    /** A divider between list items inside a card (none before the first). */
    private fun item(parent: LinearLayout) {
        val hasContentAfterHeading = parent.childCount > 1
        if (hasContentAfterHeading) parent.addView(View(this).apply { setBackgroundColor(LINE) },
            LinearLayout.LayoutParams(-1, dp(1)).apply { topMargin = dp(8); bottomMargin = dp(8) })
    }

    /** "● Payments are on": a coloured dot, then the status as its own text. */
    private fun bigStatus(parent: LinearLayout, text: String, color: Int) {
        val r = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL; setPadding(0, 0, 0, dp(4)) }
        r.addView(View(this).apply { background = rounded(color, radius = 999) }, LinearLayout.LayoutParams(dp(12), dp(12)).apply { marginEnd = dp(10) })
        r.addView(TextView(this).apply { this.text = text; textSize = 20f; typeface = Typeface.DEFAULT_BOLD; setTextColor(INK) })
        parent.addView(r)
    }

    private fun keyValue(parent: LinearLayout, k: String, v: String) {
        val r = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; setPadding(0, dp(4), 0, dp(4)) }
        r.addView(TextView(this).apply { text = k; textSize = 14f; setTextColor(MUTED) }, LinearLayout.LayoutParams(0, -2, 1f))
        r.addView(TextView(this).apply { text = v; textSize = 14f; typeface = Typeface.DEFAULT_BOLD; setTextColor(INK); gravity = Gravity.END },
            LinearLayout.LayoutParams(-2, -2).apply { marginStart = dp(16) })
        parent.addView(r)
    }

    private fun rowWithPill(parent: LinearLayout, main: String, sub: String?, pill: String?, color: Int, big: Boolean = false) {
        val r = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL }
        val left = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        left.addView(TextView(this).apply { text = main; textSize = if (big) 18f else 15f; typeface = Typeface.DEFAULT_BOLD; setTextColor(INK) })
        sub?.let { s -> left.addView(TextView(this).apply { text = s; textSize = 13f; setTextColor(MUTED) }) }
        r.addView(left, LinearLayout.LayoutParams(0, -2, 1f))
        pill?.let { r.addView(pillView(it, tint(color), color)) }
        parent.addView(r)
    }

    private fun pill(parent: LinearLayout, text: String, bg: Int, fg: Int) =
        parent.addView(pillView(text, bg, fg), LinearLayout.LayoutParams(-2, -2).apply { bottomMargin = dp(8) })

    private fun pillView(text: String, bg: Int, fg: Int) = TextView(this).apply {
        this.text = text; textSize = 13f; typeface = Typeface.DEFAULT_BOLD; setTextColor(fg)
        background = rounded(bg, radius = 999); setPadding(dp(10), dp(3), dp(10), dp(3))
    }

    private val CHANNEL_KEYS = listOf("upi", "imps", "neft", "rtgs", "card", "netbanking")

    /** A button that shows or hides the full notice, in the language the server sent. */
    private fun noticeToggle(parent: LinearLayout, n: JSONObject) {
        // stays open across the 15-second refresh, so it doesn't close while someone reads it
        val body = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; visibility = if (noticeOpen) View.VISIBLE else View.GONE }
        button(parent, getString(R.string.privacy_read), style = Style.SECONDARY) {
            noticeOpen = !noticeOpen
            body.visibility = if (noticeOpen) View.VISIBLE else View.GONE
        }
        parent.addView(body, LinearLayout.LayoutParams(-1, -2))
        val parts = listOf("what_we_collect" to R.string.notice_collect, "why" to R.string.notice_why,
            "who_sees_it" to R.string.notice_who_sees, "who_can_use_it" to R.string.notice_who_can,
            "how_long" to R.string.notice_how_long, "your_rights" to R.string.notice_rights)
        for ((key, title) in parts) {
            val items = n.optJSONArray(key) ?: continue
            para(body, getString(title), bold = true).apply { setPadding(0, dp(12), 0, dp(2)) }
            for (i in 0 until items.length()) para(body, "•  " + items.getString(i), INK, 14f)
        }
        para(body, getString(R.string.notice_grievance), bold = true).apply { setPadding(0, dp(12), 0, dp(2)) }
        para(body, n.str("grievance_officer"), INK, 14f)
        para(body, getString(R.string.notice_version, n.str("version")), MUTED, 13f).apply { setPadding(0, dp(8), 0, 0) }
    }

    private fun hourText(h: Int) = String.format(java.util.Locale.ROOT, "%02d:00", h)

    private fun channelName(c: String) = when (c) {
        "card" -> getString(R.string.channel_card)
        "netbanking" -> getString(R.string.channel_netbanking)
        else -> c.uppercase(java.util.Locale.ROOT)
    }

    /** "UPI, Card · 22:00–06:00" */
    private fun quietText(q: JSONObject): String {
        val a = q.optJSONArray("channels") ?: org.json.JSONArray()
        val names = (0 until a.length()).joinToString(", ") { channelName(a.getString(it)) }
        return "$names · ${hourText(q.optInt("start"))}–${hourText(q.optInt("end"))}"
    }

    private fun tint(c: Int) = Color.argb(40, Color.red(c), Color.green(c), Color.blue(c))

    private fun input(parent: LinearLayout, hint: String, type: Int, value: String?): EditText = EditText(this).apply {
        this.hint = hint; inputType = type; setText(value ?: ""); textSize = 18f
        addTextChangedListener(object : android.text.TextWatcher {   // after setText: only the person's typing counts
            override fun afterTextChanged(e: android.text.Editable?) { formDirty = true }
            override fun beforeTextChanged(t: CharSequence?, a: Int, b: Int, c: Int) {}
            override fun onTextChanged(t: CharSequence?, a: Int, b: Int, c: Int) {}
        })
        parent.addView(this, LinearLayout.LayoutParams(-1, -2))
    }

    private fun styled(text: String, style: Style, onClick: (Button) -> Unit) = Button(this).apply {
        this.text = text; isAllCaps = false; textSize = 16f; minHeight = dp(48)
        val (bg, fg, line) = when (style) {
            Style.PRIMARY -> Triple(BRAND, Color.WHITE, null)
            Style.OK -> Triple(OK, Color.WHITE, null)
            Style.DANGER -> Triple(BAD, Color.WHITE, null)
            Style.SECONDARY -> Triple(CARD, BRAND, BRAND)
        }
        background = rounded(bg, line, 10); setTextColor(fg)
        setOnClickListener { onClick(this) }
    }

    private fun button(parent: LinearLayout, text: String, style: Style = Style.PRIMARY, onClick: (Button) -> Unit) {
        parent.addView(styled(text, style, onClick), LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(8) })
    }

    private fun action(label: String, style: Style, onClick: (Button) -> Unit) = Triple(label, style, onClick)

    private fun row(parent: LinearLayout, vararg buttons: Triple<String, Style, (Button) -> Unit>) {
        val r = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; isBaselineAligned = false }
        buttons.forEachIndexed { i, (label, style, onClick) ->
            // same height side by side, even when one label wraps
            r.addView(styled(label, style, onClick), LinearLayout.LayoutParams(0, -1, 1f).apply { marginStart = if (i > 0) dp(8) else 0 })
        }
        parent.addView(r, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(8) })
    }

    private fun confirm(question: String, yes: () -> Unit) {
        dialogOpen = true
        AlertDialog.Builder(this).setMessage(question)
            .setPositiveButton(getString(R.string.yes)) { _, _ -> yes() }
            .setNegativeButton(getString(R.string.no), null)
            .setOnDismissListener { dialogOpen = false }
            .show()
    }

    private fun toast(text: String) = Toast.makeText(this, text, Toast.LENGTH_LONG).show()

    companion object {
        const val REFRESH_MS = 15_000L
        val BRAND = Color.parseColor("#1F5FBF")
        val PAGE = Color.parseColor("#F4F6FA")
        val CARD = Color.WHITE
        val LINE = Color.parseColor("#DDE3EC")
        val INK = Color.parseColor("#111827")
        val MUTED = Color.parseColor("#5B6472")
        val OK = Color.parseColor("#15803D")
        val WARN = Color.parseColor("#B45309")
        val BAD = Color.parseColor("#B91C1C")
        val WARN_BG = Color.parseColor("#FEF3C7")
        val WARN_TEXT = Color.parseColor("#92400E")
    }
}
