package `in`.guardianregistry.app

import org.json.JSONArray
import org.json.JSONObject
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL

class ApiError(val status: Int, message: String) : IOException(message)

/** Blocking JSON client. Call it off the main thread. */
class Api(private val base: String, var token: String?, private val headers: Map<String, String> = emptyMap()) {

    fun get(path: String): Any = call("GET", path, null)
    fun post(path: String, body: JSONObject? = JSONObject()): Any = call("POST", path, body)
    fun delete(path: String): Any = call("DELETE", path, null)
    fun put(path: String, body: JSONObject): Any = call("PUT", path, body)
    /** Android's HttpURLConnection (OkHttp inside) allows PATCH; desktop Java's doesn't. */
    fun patch(path: String, body: JSONObject): Any = call("PATCH", path, body)

    fun obj(path: String) = get(path) as JSONObject
    fun arr(path: String) = get(path) as JSONArray

    private fun call(method: String, path: String, body: JSONObject?): Any {
        val conn = URL(base.trimEnd('/') + path).openConnection() as HttpURLConnection
        try {
            conn.requestMethod = method
            conn.connectTimeout = 10_000
            conn.readTimeout = 15_000
            conn.setRequestProperty("Accept", "application/json")
            conn.setRequestProperty("Accept-Language", Wire.language())  // server errors in the phone's language
            token?.let { conn.setRequestProperty("Authorization", "Bearer $it") }
            headers.forEach { (k, v) -> conn.setRequestProperty(k, v) }
            if (body != null) {
                conn.doOutput = true
                conn.setRequestProperty("Content-Type", "application/json")
                conn.outputStream.use { it.write(body.toString().toByteArray(Charsets.UTF_8)) }
            }
            val status = conn.responseCode
            val stream = if (status >= 400) conn.errorStream else conn.inputStream
            val text = stream?.bufferedReader()?.use { it.readText() } ?: ""
            if (status >= 400) throw ApiError(status, detail(text) ?: "HTTP $status")
            if (text.isBlank()) return JSONObject()
            return if (text.trimStart().startsWith("[")) JSONArray(text) else JSONObject(text)
        } finally {
            conn.disconnect()
        }
    }

    private fun detail(text: String): String? = try {
        JSONObject(text).optString("detail").ifBlank { null }
    } catch (e: Exception) {
        null
    }
}
