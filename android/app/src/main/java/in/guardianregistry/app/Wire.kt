package `in`.guardianregistry.app

import org.json.JSONArray
import org.json.JSONObject
import java.text.NumberFormat
import java.util.Base64
import java.util.Locale

/** Pure helpers (no Android types), unit-tested on the JVM. */
object Wire {
    const val SIGNING_PREFIX = "guardian-registry/v1:"

    /** The phone's language ("hi", "ta", ...). The registry uses it if that language is enabled
     *  there, and English otherwise. */
    fun language(tag: String = java.util.Locale.getDefault().language): String =
        tag.lowercase().take(2).ifBlank { "en" }

    fun b64(bytes: ByteArray): String = Base64.getEncoder().encodeToString(bytes)

    fun signingInput(challenge: String): ByteArray = (SIGNING_PREFIX + challenge).toByteArray(Charsets.UTF_8)

    fun androidAttestation(chain: List<ByteArray>): String =
        JSONObject()
            .put("format", "android-key")
            .put("chain", JSONArray(chain.map { b64(it) }))
            .toString()

    fun verifyBody(
        mobile: String, code: String, displayName: String?, deviceId: String,
        deviceKey: String, challenge: String, proof: String, attestation: String?,
    ): JSONObject = JSONObject().apply {
        put("mobile", mobile)
        put("code", code)
        if (!displayName.isNullOrBlank()) put("display_name", displayName)
        put("device_id", deviceId)
        put("device_key", deviceKey)
        put("challenge", challenge)
        put("device_proof", proof)
        if (attestation != null) put("key_attestation", attestation)
        put("platform", "android")
        put("language", language())
    }

    /** The registry's device key id: SHA-256 of the public key (SPKI DER), in hex. */
    fun keyId(publicKeyB64: String): String =
        java.security.MessageDigest.getInstance("SHA-256").digest(Base64.getDecoder().decode(publicKeyB64))
            .joinToString("") { "%02x".format(it) }

    private fun instant(iso: String): java.time.Instant? = if (iso.isBlank()) null else try {
        java.time.OffsetDateTime.parse(iso).toInstant()
    } catch (e: java.time.format.DateTimeParseException) {
        try { java.time.LocalDateTime.parse(iso).toInstant(java.time.ZoneOffset.UTC) } catch (e2: Exception) { null }
    }

    /** "24 Nov 2026, 12:08 pm" in the phone's language and time zone, like the web app. */
    fun time(iso: String, zone: java.time.ZoneId = java.time.ZoneId.systemDefault(), locale: Locale = Locale.getDefault()): String {
        val t = instant(iso) ?: return iso
        return java.time.format.DateTimeFormatter
            .ofLocalizedDateTime(java.time.format.FormatStyle.MEDIUM, java.time.format.FormatStyle.SHORT)
            .withLocale(locale).withZone(zone).format(t)
    }

    private val ISO_TIME = Regex("""\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?""")

    /** Server reasons carry ISO times ("restricted until 2026-11-25T15:23:36+00:00"): show them readably. */
    fun readableTimes(text: String, zone: java.time.ZoneId = java.time.ZoneId.systemDefault(), locale: Locale = Locale.getDefault()): String =
        ISO_TIME.replace(text) { time(it.value, zone, locale) }

    fun isFuture(iso: String, now: java.time.Instant = java.time.Instant.now()): Boolean = instant(iso)?.isAfter(now) == true

    /** Amounts are in paise. */
    fun rupees(paise: Long): String {
        val f = NumberFormat.getCurrencyInstance(Locale("en", "IN"))
        f.maximumFractionDigits = 0
        return f.format(paise / 100.0)
    }
}
