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
        assertEquals("ta", Wire.language("ta"))
        assertEquals("hi", Wire.language("hi-IN"))
        assertEquals("en", Wire.language(""))
    }

    @Test
    fun timesAndKeyIdsMatchTheServer() {
        val utc = java.time.ZoneOffset.UTC
        val t = Wire.time("2026-11-24T06:38:00+00:00", utc, java.util.Locale.ENGLISH)
        org.junit.Assert.assertTrue(t, t.contains("2026") && t.contains("6:38"))
        assertEquals(Wire.time("2026-11-24T06:38:00", utc, java.util.Locale.ENGLISH), t)
        assertEquals("not a time", Wire.time("not a time"))
        org.junit.Assert.assertTrue(Wire.isFuture("2999-01-01T00:00:00+00:00"))
        assertFalse(Wire.isFuture("2000-01-01T00:00:00Z"))
        assertFalse(Wire.isFuture(""))
        // SHA-256 of the bytes 1, 2, 3
        assertEquals("039058c6f2c0cb492c533b0a4d14ef77cc0f78abccced5287d84a1a2011cfb81", Wire.keyId("AQID"))
    }
}
