package `in`.guardianregistry.app

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

class WireTest {
    @Test
    fun signingInputMatchesTheServer() {
        assertEquals("guardian-registry/v1:chl_abc", String(Wire.signingInput("chl_abc")))
    }

    @Test
    fun attestationIsTheFormatTheServerParses() {
        val json = JSONObject(Wire.androidAttestation(listOf(byteArrayOf(1, 2), byteArrayOf(3))))
        assertEquals("android-key", json.getString("format"))
        assertEquals("AQI=", json.getJSONArray("chain").getString(0))
    }

    @Test
    fun verifyBodyOmitsEmptyOptionalFields() {
        val b = Wire.verifyBody("+919800000001", "123456", "", "dev-1", "KEY", "chl", "SIG", null)
        assertFalse(b.has("display_name"))
        assertFalse(b.has("key_attestation"))
        assertEquals("android", b.getString("platform"))
    }
}
