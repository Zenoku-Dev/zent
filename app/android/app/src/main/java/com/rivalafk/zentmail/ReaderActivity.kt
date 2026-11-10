package com.rivalafk.zentmail

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.text.format.DateUtils
import android.view.View
import android.widget.ImageButton
import android.widget.TextView
import android.widget.Toast
import org.json.JSONException
import kotlin.concurrent.thread

class ReaderActivity : Activity() {

    private lateinit var subjectView: TextView
    private lateinit var metaView: TextView
    private lateinit var bodyView: TextView

    private var folder = "INBOX"
    private var uid = -1
    private var subject = ""
    private var from = ""
    private var to = ""
    private var dateRaw = ""

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_reader)
        subjectView = findViewById(R.id.subject)
        metaView = findViewById(R.id.meta)
        bodyView = findViewById(R.id.body)

        folder = intent.getStringExtra("folder") ?: "INBOX"
        uid = intent.getIntExtra("uid", -1)
        subject = intent.getStringExtra("subject").orEmpty()
        from = intent.getStringExtra("from").orEmpty()
        to = intent.getStringExtra("to").orEmpty()
        dateRaw = intent.getStringExtra("date").orEmpty()

        subjectView.text = subject
        metaView.text = "$from\n$to  ·  $dateRaw"

        findViewById<ImageButton>(R.id.back_btn).setOnClickListener { finish() }
        findViewById<ImageButton>(R.id.delete_btn).setOnClickListener { deleteThenFinish() }
        findViewById<ImageButton>(R.id.spam_btn).setOnClickListener { spamThenFinish() }
        findViewById<ImageButton>(R.id.reply_btn).setOnClickListener { reply() }

        if (uid == -1) {
            Toast.makeText(this, "Письмо не найдено", Toast.LENGTH_SHORT).show()
            finish(); return
        }
        loadMessage()
    }

    private fun loadMessage() {
        thread {
            try {
                val api = Api(this)
                val m = api.message(folder, uid)
                runOnUiThread {
                    val body = m.optString("html").ifEmpty { m.optString("text") }
                    bodyView.text = if (body.isEmpty()) "(пусто)" else htmlToText(body)
                }
            } catch (e: Api.ApiException) {
                runOnUiThread {
                    Toast.makeText(this, e.message ?: "Ошибка загрузки", Toast.LENGTH_LONG).show()
                    bodyView.text = "Не удалось открыть письмо: ${e.message}"
                }
            }
        }
    }

    private fun deleteThenFinish() = moveThenFinish("Trash")
    private fun spamThenFinish() = moveThenFinish("Junk")

    private fun moveThenFinish(dest: String) {
        thread {
            try {
                val api = Api(this)
                api.move(folder, uid, dest)
                runOnUiThread { finish() }
            } catch (_: Exception) {
                runOnUiThread { finish() }
            }
        }
    }

    private fun reply() {
        val i = Intent(this, ComposeActivity::class.java).apply {
            putExtra("to", from)
            putExtra("subject", "Re: $subject")
        }
        startActivity(i)
    }

    private fun htmlToText(html: String): String {
        return html
            .replace(Regex("<(br|/p|/div|/li|/tr)[^>]*>", RegexOption.IGNORE_CASE), "\n")
            .replace(Regex("<[^>]+>"), "")
            .replace("&nbsp;", " ")
            .replace("&amp;", "&")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&quot;", "\"")
            .replace(Regex("\n{3,}"), "\n\n")
            .trim()
    }
}
