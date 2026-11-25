package `in`.guardianregistry.app

import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Runs on an emulator against a real registry (scripts/dev_server.py on the host, reached
 * at 10.0.2.2:8010). Exercises the real Android Keystore: key generation with an
 * attestation challenge, signing, and the server's verification of both.
 *
 * The attestation evidence is written to logcat (tag GRATTEST) so CI can check the real
 * Keystore certificate chain with the registry's own parser (scripts/check_attestation.py).
 */
@RunWith(AndroidJUnit4::class)
class SignInTest {
    private val ctx = InstrumentationRegistry.getInstrumentation().targetContext
    private val anon = Api(BuildConfig.API_BASE, null)

    private fun newMobile() = "+9197" + (10_000_000..99_999_999).random()
    private fun code(mobile: String) =
        (anon.post("/v1/auth/otp", JSONObject().put("mobile", mobile)) as JSONObject).getString("dev_code")
    private fun challenge() = (anon.post("/v1/auth/challenge") as JSONObject).getString("challenge")

    @Test
    fun keystoreKeyEnrolsThenProvesTheDevice() {
        val key = DeviceKey(ctx)
        key.delete()
        val mobile = newMobile()

        val ch1 = challenge()
        val attestation = key.create(ch1)
        val first = anon.post(
            "/v1/auth/verify",
            Wire.verifyBody(mobile, code(mobile), "Emulator Test", "emu-device", key.publicKey(), ch1, key.sign(ch1), attestation, adult = true)
        ) as JSONObject
        assertTrue(first.getBoolean("new_user"))
        emit(JSONObject().put("challenge", ch1).put("device_key", key.publicKey()).put("attestation", attestation))

        Thread.sleep(31_000)  // the registry's resend cooldown for the same number
        val ch2 = challenge()
        val second = anon.post(
            "/v1/auth/verify",
            Wire.verifyBody(mobile, code(mobile), null, "emu-device", key.publicKey(), ch2, key.sign(ch2), null)
        ) as JSONObject
        assertTrue("a trusted Keystore key proves the device", second.getBoolean("device_proven"))
        assertFalse(second.getBoolean("restricted"))

        val devices = Api(BuildConfig.API_BASE, second.getString("token")).arr("/v1/me/devices")
        assertEquals(1, devices.length())
        assertEquals("trusted", devices.getJSONObject(0).getString("status"))
    }

    @Test
    fun aSignatureOverTheWrongChallengeIsRefused() {
        val key = DeviceKey(ctx)
        key.delete()
        val mobile = newMobile()
        val ch = challenge()
        key.create(ch)
        try {
            anon.post(
                "/v1/auth/verify",
                Wire.verifyBody(mobile, code(mobile), "Tamper Test", "emu-2", key.publicKey(), ch, key.sign("not-$ch"), null, adult = true)
            )
            fail("the registry accepted a signature over a different challenge")
        } catch (e: ApiError) {
            assertEquals(401, e.status)
            assertTrue(e.message, e.message!!.contains("signature"))
        } finally {
            key.delete()
        }
    }

    @Test
    fun hindiStringsShip() {
        val config = android.content.res.Configuration(ctx.resources.configuration)
        config.setLocale(java.util.Locale("hi"))
        val hi = ctx.createConfigurationContext(config)
        assertEquals("मंज़ूर करें", hi.getString(R.string.approve))
        assertEquals("नमस्ते, Asha", hi.getString(R.string.hello, "Asha"))
        assertEquals("Approve", ctx.createConfigurationContext(
            android.content.res.Configuration(config).apply { setLocale(java.util.Locale.ENGLISH) }
        ).getString(R.string.approve))
    }

    private fun emit(doc: JSONObject) {
        val text = doc.toString()
        val parts = text.chunked(3000)
        parts.forEachIndexed { i, p -> Log.i("GRATTEST", "${i + 1}/${parts.size}:$p") }
    }
}
