package `in`.guardianregistry.app

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import java.util.Base64
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** Session token encrypted with a Keystore AES key; device id; signed-in mobile. */
class Store(context: Context) {
    private val prefs = context.getSharedPreferences("guardian", Context.MODE_PRIVATE)

    val deviceId: String
        get() = prefs.getString("device_id", null) ?: UUID.randomUUID().toString().also {
            prefs.edit().putString("device_id", it).apply()
        }

    var mobile: String?
        get() = prefs.getString("mobile", null)
        set(v) = prefs.edit().putString("mobile", v).apply()

    var token: String?
        get() = prefs.getString("token", null)?.let { decrypt(it) }
        set(v) = prefs.edit().putString("token", v?.let { encrypt(it) }).apply()

    var pushToken: String?
        get() = prefs.getString("push_token", null)
        set(v) = prefs.edit().putString("push_token", v).apply()

    private fun key(): SecretKey {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (ks.getKey(ALIAS, null) as SecretKey?)?.let { return it }
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply {
            init(
                KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .build()
            )
        }.generateKey()
    }

    private fun encrypt(plain: String): String {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, key())
        return Base64.getEncoder().encodeToString(c.iv + c.doFinal(plain.toByteArray()))
    }

    private fun decrypt(stored: String): String? = try {
        val raw = Base64.getDecoder().decode(stored)
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, raw, 0, 12))
        String(c.doFinal(raw, 12, raw.size - 12))
    } catch (e: Exception) {
        null  // key lost (e.g. backup restored onto a new phone): sign in again
    }

    companion object {
        private const val ALIAS = "guardian-registry-token-key"
    }
}
