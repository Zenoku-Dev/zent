package com.rivalafk.zentmail

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.ImageButton
import android.widget.Toast
import kotlin.concurrent.thread

class ComposeActivity : Activity() {

    private lateinit var to: EditText
    private lateinit var subject: EditText
    private lateinit var body: EditText

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_compose)
        to = findViewById(R.id.to)
        subject = findViewById(R.id.subject)
        body = findViewById(R.id.body)

        findViewById<ImageButton>(R.id.back_btn).setOnClickListener { finish() }
        findViewById<Button>(R.id.send_btn).setOnClickListener { send() }

        intent.getStringExtra("to")?.let { to.setText(it) }
        intent.getStringExtra("subject")?.let { subject.setText(it) }
    }

    private fun send() {
        val t = to.text?.toString().orEmpty().trim()
        val s = subject.text?.toString().orEmpty().trim()
        val b = body.text?.toString().orEmpty()
        if (t.isEmpty()) { Toast.makeText(this, "Заполни получателя", Toast.LENGTH_SHORT).show(); return }
        thread {
            try {
                val api = Api(this)
                api.send(t, s, b)
                runOnUiThread {
                    Toast.makeText(this, "Отправлено", Toast.LENGTH_SHORT).show()
                    finish()
                }
            } catch (e: Api.ApiException) {
                runOnUiThread {
                    if (e.code == 401) {
                        Prefs.clear(this)
                        startActivity(Intent(this, LoginActivity::class.java))
                        finish()
                    } else {
                        Toast.makeText(this, e.message ?: "Ошибка отправки", Toast.LENGTH_LONG).show()
                    }
                }
            }
        }
    }
}
