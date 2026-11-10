package com.rivalafk.zentmail

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder

/** Тонкий HTTPS-клиент API почты (mail.rival-afk.com/api) — без зависимостей. */
class Api(private val ctx: Context) {
    private val base get() = Prefs.host(ctx).trimEnd('/')

    class ApiException(val code: Int, msg: String) : Exception(msg)

    fun login(user: String, pass: String): JSONObject =
        call("POST", "/login", JSONObject().put("user", user).put("pass", pass))

    fun me(): JSONObject = call("GET", "/me", null)

    fun folders(): List<String> {
        val r = call("GET", "/folders", null)
        val arr = r.getJSONArray("folders")
        return (0 until arr.length()).map { arr.getString(it) }
    }

    fun messages(folder: String, limit: Int = 50): JSONArray {
        val r = call("GET", "/messages?folder=${enc(folder)}&limit=$limit", null)
        return r.getJSONArray("messages")
    }

    fun message(folder: String, uid: Int): JSONObject {
        val r = call("GET", "/messages/${enc(folder)}/$uid", null)
        return r.getJSONObject("message")
    }

    fun delete(folder: String, uid: Int): Boolean {
        val r = call("POST", "/messages/${enc(folder)}/$uid/delete", JSONObject().put("dest", "Trash"))
        return r.optBoolean("ok", false)
    }

    fun move(folder: String, uid: Int, dest: String): Boolean {
        val r = call("POST", "/messages/${enc(folder)}/$uid/move", JSONObject().put("dest", dest))
        return r.optBoolean("ok", false)
    }

    fun send(to: String, subject: String, body: String): Boolean {
        val r = call("POST", "/send", JSONObject().put("to", to).put("subject", subject).put("body", body))
        return r.optBoolean("ok", false)
    }

    fun logout(): Boolean = try {
        val r = call("POST", "/logout", JSONObject())
        r.optBoolean("ok", true)
    } catch (_: Exception) {
        true
    }

    // ----------------------------------------------------------

    private fun enc(s: String): String = URLEncoder.encode(s, "UTF-8")

    private fun call(method: String, path: String, body: JSONObject?): JSONObject {
        val token = Prefs.token(ctx)
        val conn = (URL(base + path).openConnection() as HttpURLConnection).apply {
            requestMethod = method
            connectTimeout = 12000
            readTimeout = 12000
            setRequestProperty("Accept", "application/json")
            setRequestProperty("Content-Type", "application/json")
            setRequestProperty("User-Agent", "ZentMail/0.1")
            if (token != null) setRequestProperty("Authorization", "Bearer $token")
            doInput = true
        }
        try {
            if (body != null) {
                conn.doOutput = true
                conn.outputStream.use { it.write(body.toString().toByteArray(Charsets.UTF_8)) }
            }
            val code = conn.responseCode
            val stream = if (code in 200..299) conn.inputStream else conn.errorStream
            val text = stream?.bufferedReader(Charsets.UTF_8)?.use { it.readText() } ?: ""
            if (code !in 200..299) throw ApiException(code, text.ifEmpty { "HTTP $code" })
            return JSONObject(text)
        } catch (e: ApiException) {
            throw e
        } catch (e: IOException) {
            throw ApiException(-1, "Ошибка сети: ${e.message}")
        } finally {
            conn.disconnect()
        }
    }
}
