package `in`.guardianregistry.app

import org.json.JSONArray
import org.json.JSONObject
import java.text.NumberFormat
import java.util.Base64
import java.util.Locale

/** Pure helpers (no Android types), unit-tested on the JVM. */
object Wire {
    const val SIGNING_PREFIX = "guardian-registry/v1:"

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
    }

    /** Amounts are in paise. */
    fun rupees(paise: Long): String {
        val f = NumberFormat.getCurrencyInstance(Locale("en", "IN"))
        f.maximumFractionDigits = 0
        return f.format(paise / 100.0)
    }
}
