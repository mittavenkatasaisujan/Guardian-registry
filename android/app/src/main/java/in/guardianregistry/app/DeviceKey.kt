package `in`.guardianregistry.app

import android.content.Context
import android.content.pm.PackageManager
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec

/**
 * The device key: an EC P-256 key made inside Android Keystore (StrongBox when the phone
 * has one, otherwise the TEE). The private key never leaves the secure hardware.
 *
 * The key is created at the first sign-in, AFTER the app has a challenge, so the Keystore
 * attestation certificate carries that challenge. The registry checks the chain against
 * Google's root, that the certified key is this key, that the challenge is this sign-in's,
 * and that the app's package and signing certificate are ours (see attestation.py).
 */
class DeviceKey(private val context: Context) {
    private val ks: KeyStore = KeyStore.getInstance(KEYSTORE).apply { load(null) }

    val exists: Boolean get() = ks.containsAlias(ALIAS)

    /** Create the key bound to [challenge]. Returns the attestation evidence JSON. */
    fun create(challenge: String): String {
        val strongBox = context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
        try {
            generate(challenge, strongBox)
        } catch (e: StrongBoxUnavailableException) {
            generate(challenge, false)
        }
        val chain = ks.getCertificateChain(ALIAS).map { it.encoded }
        return Wire.androidAttestation(chain)
    }

    private fun generate(challenge: String, strongBox: Boolean) {
        val spec = KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setAttestationChallenge(challenge.toByteArray(Charsets.UTF_8))
            .setIsStrongBoxBacked(strongBox)
            .build()
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, KEYSTORE).apply {
            initialize(spec)
            generateKeyPair()
        }
    }

    /** SubjectPublicKeyInfo DER, base64: what the registry calls device_key. */
    fun publicKey(): String = Wire.b64(ks.getCertificate(ALIAS).publicKey.encoded)

    /** ECDSA-SHA256 over "guardian-registry/v1:" + challenge, DER, base64. */
    fun sign(challenge: String): String {
        val key = ks.getKey(ALIAS, null) as PrivateKey
        val s = Signature.getInstance("SHA256withECDSA")
        s.initSign(key)
        s.update(Wire.signingInput(challenge))
        return Wire.b64(s.sign())
    }

    /** After a lost-phone report or recovery the registry revoked the key: start over. */
    fun delete() {
        if (exists) ks.deleteEntry(ALIAS)
    }

    companion object {
        private const val KEYSTORE = "AndroidKeyStore"
        private const val ALIAS = "guardian-registry-device-key"
    }
}
