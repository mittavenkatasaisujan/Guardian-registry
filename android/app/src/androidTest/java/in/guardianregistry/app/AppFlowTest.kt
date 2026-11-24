package `in`.guardianregistry.app

import android.os.SystemClock
import android.view.View
import android.widget.Button
import androidx.test.core.app.ActivityScenario
import androidx.test.espresso.Espresso.onData
import androidx.test.espresso.Espresso.onView
import androidx.test.espresso.action.ViewActions.click
import androidx.test.espresso.action.ViewActions.closeSoftKeyboard
import androidx.test.espresso.action.ViewActions.replaceText
import androidx.test.espresso.action.ViewActions.scrollTo
import androidx.test.espresso.assertion.ViewAssertions.matches
import androidx.test.espresso.matcher.RootMatchers.isDialog
import androidx.test.espresso.matcher.ViewMatchers.Visibility
import androidx.test.espresso.matcher.ViewMatchers.isAssignableFrom
import androidx.test.espresso.matcher.ViewMatchers.isDescendantOfA
import androidx.test.espresso.matcher.ViewMatchers.withContentDescription
import androidx.test.espresso.matcher.ViewMatchers.withEffectiveVisibility
import androidx.test.espresso.matcher.ViewMatchers.withHint
import androidx.test.espresso.matcher.ViewMatchers.withText
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.hamcrest.Matcher
import org.hamcrest.Matchers.allOf
import org.hamcrest.Matchers.instanceOf
import org.hamcrest.Matchers.`is`
import org.hamcrest.Matchers.not
import org.hamcrest.Matchers.startsWith
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import androidx.test.rule.GrantPermissionRule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Drives the real screens on an emulator against a real registry (scripts/dev_server.py on
 * the host at 10.0.2.2:8010), the same flows a person uses in the web app: rules and presets,
 * pausing and the held "switch back on", inviting a guardian, a guardian approving that change,
 * approving and denying payments a bank sent, pausing someone else's payments, alerts, devices,
 * sign-in through the screens, sign-out and lost phone. Every UI action is checked against the
 * registry's own API afterwards.
 */
@RunWith(AndroidJUnit4::class)
class AppFlowTest {
    // no system permission dialog over the screens under test
    @get:Rule val notifications: GrantPermissionRule = GrantPermissionRule.grant(android.Manifest.permission.POST_NOTIFICATIONS)

    private val ctx = InstrumentationRegistry.getInstrumentation().targetContext
    private val base = BuildConfig.API_BASE
    private val anon = Api(base, null)
    private val admin = Api(base, null, mapOf("X-Admin-Token" to "dev-admin"))
    private val run = (1000..9999).random()
    private fun s(id: Int, vararg args: Any) = ctx.getString(id, *args)

    private fun mobile() = "+9196" + (10_000_000..99_999_999).random()

    private fun person(mobile: String, name: String): String {
        val code = (anon.post("/v1/auth/otp", JSONObject().put("mobile", mobile)) as JSONObject).getString("dev_code")
        return (anon.post("/v1/auth/verify", JSONObject().put("mobile", mobile).put("code", code).put("display_name", name)) as JSONObject)
            .getString("token")
    }

    private fun bank(): Api {
        val ref = "RBI-APP-$run"
        admin.put("/v1/admin/register/bank", JSONObject().put("source", "app test").put("as_of", "2026-11-24")
            .put("entities", org.json.JSONArray().put(JSONObject().put("regulator_ref", ref).put("name", "App Test Bank"))))
        val b = admin.post("/v1/admin/participants", JSONObject().put("name", "App Test Bank $run").put("kind", "bank")
            .put("regulator_ref", ref)) as JSONObject
        assertEquals("active", b.getString("status"))
        return Api(base, null, mapOf("X-Api-Key" to b.getString("api_key")))
    }

    private fun check(bank: Api, mobile: String, txn: String, rupees: Long) = bank.post("/v1/checks",
        JSONObject().put("mobile", mobile).put("participant_txn_id", "$txn-$run").put("amount", rupees * 100)
            .put("payee", "shop$run@upi").put("channel", "upi")) as JSONObject

    @Before
    fun freshApp() {
        val store = Store(ctx)
        store.token = null
        store.apiBase = base
    }

    private fun launchAs(token: String?): ActivityScenario<MainActivity> {
        Store(ctx).token = token
        return ActivityScenario.launch(MainActivity::class.java)
    }

    // ------------------------------------------------------------------ helpers

    /** Retry [block] until it passes: screens load data off the main thread. */
    private fun eventually(timeoutMs: Long = 20_000, block: () -> Unit) {
        val end = SystemClock.uptimeMillis() + timeoutMs
        while (true) {
            try {
                block(); return
            } catch (e: Throwable) {
                if (SystemClock.uptimeMillis() > end) throw e
                Thread.sleep(300)
            }
        }
    }

    private fun inContent(m: Matcher<View>) = allOf(m, isDescendantOfA(isAssignableFrom(android.widget.ScrollView::class.java)))

    private fun see(text: String) = eventually {
        onView(inContent(withText(text))).check(matches(withEffectiveVisibility(Visibility.VISIBLE)))
    }

    private fun seeNo(text: String) = eventually {
        onView(inContent(withText(text))).check(androidx.test.espresso.assertion.ViewAssertions.doesNotExist())
    }

    private fun tap(text: String) = eventually {
        onView(inContent(allOf(withText(text), isAssignableFrom(Button::class.java)))).perform(scrollTo(), click())
    }

    private fun tab(label: Int) = eventually {
        onView(allOf(isAssignableFrom(Button::class.java), withText(startsWith(s(label))),
            not(isDescendantOfA(isAssignableFrom(android.widget.ScrollView::class.java))))).perform(click())
    }

    private fun yes() = eventually { onView(withText(s(R.string.yes))).inRoot(isDialog()).perform(click()) }

    /** Save what the screen shows now; CI pulls these and keeps them as the app-screens artifact. */
    private fun shot(name: String) {
        Thread.sleep(400)
        val bmp = InstrumentationRegistry.getInstrumentation().uiAutomation.takeScreenshot() ?: return
        val dir = java.io.File(ctx.getExternalFilesDir(null), "shots").apply { mkdirs() }
        java.io.File(dir, "$name.png").outputStream().use { bmp.compress(android.graphics.Bitmap.CompressFormat.PNG, 100, it) }
    }

    private fun until(timeoutMs: Long = 20_000, what: String, cond: () -> Boolean) {
        val end = SystemClock.uptimeMillis() + timeoutMs
        while (!cond()) {
            if (SystemClock.uptimeMillis() > end) throw AssertionError("timed out waiting for: $what")
            Thread.sleep(300)
        }
    }

    // ------------------------------------------------------------------ the flows

    @Test
    fun everyScreenWorksForAPersonAndTheirGuardian() {
        val pm = mobile(); val gm = mobile(); val third = mobile()
        val p = person(pm, "Asha $run"); val g = person(gm, "Ravi $run"); person(third, "Meena $run")
        val P = Api(base, p); val G = Api(base, g)
        val inv = P.post("/v1/me/guardians", JSONObject().put("mobile", gm)) as JSONObject
        G.post("/v1/guardian/invitations/${inv.getString("id")}/accept")
        val bank = bank()

        // ---- the protected person: My protection
        var app = launchAs(p)
        see(s(R.string.hello, "Asha $run"))
        see(s(R.string.payments_on))
        see(s(R.string.my_rules))
        see("Ravi $run")
        shot("01-my-protection")

        // a ready-made set from the spinner
        eventually { onView(withContentDescription(s(R.string.preset_label))).perform(scrollTo(), click()) }
        onData(allOf(instanceOf(String::class.java), `is`("Trusted person approves large payments"))).perform(click())
        tap(s(R.string.apply))
        until(what = "preset applied") { P.obj("/v1/me/rules").optLong("approval_threshold") == 10_000L * 100 }

        // pause, then ask to switch back on: held for the guardian
        tap(s(R.string.pause_all_payments))
        see(s(R.string.payments_paused))
        assertTrue(P.obj("/v1/me/rules").getBoolean("kill_switch"))
        tap(s(R.string.switch_back_on))
        see(s(R.string.changes_waiting))
        shot("02-paused-change-waiting")
        assertTrue("still paused until a guardian approves", P.obj("/v1/me/rules").getBoolean("kill_switch"))

        // invite a second guardian by number
        eventually { onView(inContent(withHint(s(R.string.mobile_number)))).perform(scrollTo(), replaceText(third), closeSoftKeyboard()) }
        tap(s(R.string.invite))
        until(what = "invitation") { (0 until P.arr("/v1/me/guardians").length()).any { P.arr("/v1/me/guardians").getJSONObject(it).optString("status") == "invited" } }
        see(s(R.string.w_invited))
        shot("03-guardian-invited")
        app.close()

        // ---- the guardian: I protect
        app = launchAs(g)
        see(s(R.string.hello, "Ravi $run"))
        tab(R.string.tab_guardian)
        see(s(R.string.changes_waiting_g))
        see(s(R.string.wants_to, "Asha $run", s(R.string.switch_back_on)))
        shot("04-guardian-change-waiting")
        tap(s(R.string.approve_now))
        until(what = "payments back on") { !P.obj("/v1/me/rules").getBoolean("kill_switch") }
        seeNo(s(R.string.changes_waiting_g))

        // a bank asks about a large payment: the guardian approves it
        val c1 = check(bank, pm, "big", 20_000)
        assertEquals("pending_approval", c1.getString("status"))
        tab(R.string.tab_guardian)
        see(s(R.string.to_payee, "shop$run@upi") + " · " + s(R.string.from_name, "Asha $run"))
        shot("05-guardian-payment-waiting")
        tap(s(R.string.approve))
        yes()
        until(what = "approved") { bank.obj("/v1/checks/${c1.getString("check_id")}").getString("status") == "approved" }

        // and denies the next one
        val c2 = check(bank, pm, "deny", 15_000)
        tab(R.string.tab_guardian)
        tap(s(R.string.deny))
        until(what = "denied") { bank.obj("/v1/checks/${c2.getString("check_id")}").getString("status") == "denied" }
        see(s(R.string.nothing_waiting))

        // pause the person's payments from the guardian's phone
        tap(s(R.string.pause_theirs))
        yes()
        until(what = "paused by guardian") { P.obj("/v1/me/rules").getBoolean("kill_switch") }

        // devices: signed in by API without a device key
        tab(R.string.tab_devices)
        see(s(R.string.no_devices))
        see(s(R.string.sign_out_here))
        shot("06-devices")
        app.close()

        // ---- back to the person: alerts, recent payments, lost phone
        app = launchAs(p)
        see(s(R.string.payments_paused))
        see(s(R.string.recent_payments))
        see(s(R.string.st_approved))
        see(s(R.string.st_denied))
        shot("07-recent-payments")
        tab(R.string.alerts)
        see(s(R.string.mark_all_read))
        shot("08-alerts")
        tap(s(R.string.mark_all_read))
        until(what = "alerts read") { P.arr("/v1/me/notifications?unread_only=true&limit=100").length() == 0 }
        see(s(R.string.alerts))
        tab(R.string.tab_me)
        tap(s(R.string.report_lost))
        yes()
        see(s(R.string.send_code))
        try {
            P.obj("/v1/me")
            throw AssertionError("the old session still works after a lost-phone report")
        } catch (e: ApiError) {
            assertEquals(401, e.status)
        }
        assertTrue(Store(ctx).token == null)
        app.close()
    }

    @Test
    fun signInThroughTheScreensWithTheDeviceKey() {
        DeviceKey(ctx).delete()
        val m = mobile()
        val app = launchAs(null)
        eventually { onView(withHint(s(R.string.mobile_number))).perform(replaceText(m), closeSoftKeyboard()) }
        shot("09-sign-in")
        tap(s(R.string.send_code))
        eventually { onView(withHint(s(R.string.your_name_first))).perform(replaceText("Kiran $run"), closeSoftKeyboard()) }
        tap(s(R.string.sign_in))
        see(s(R.string.hello, "Kiran $run"))
        see(s(R.string.no_guardians))
        tab(R.string.tab_devices)
        see(s(R.string.this_device))
        see(s(R.string.w_trusted))
        shot("10-this-device")
        tap(s(R.string.sign_out_here))
        see(s(R.string.send_code))
        assertTrue(Store(ctx).token == null)
        app.close()
        DeviceKey(ctx).delete()
    }
}
