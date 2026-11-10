package com.rivalafk.zentmail

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.view.View
import android.view.inputmethod.EditorInfo
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import kotlin.concurrent.thread

class LoginActivity : Activity() {

    private lateinit var email: EditText
    private lateinit var password: EditText
    private lateinit var error: TextView
    private lateinit var signIn: Button

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // уже авторизован → сразу в почту
        if (Prefs.token(this) != null) {
            goMail(); return
        }
        setContentView(R.layout.activity_login)
        email = findViewById(R.id.email)
        password = findViewById(R.id.password)
        error = findViewById(R.id.error)
        signIn = findViewById(R.id.sign_in)

        Prefs.user(this)?.let { email.setText(it) }

        signIn.setOnClickListener { attemptLogin() }
        password.imeOptions = EditorInfo.IME_ACTION_GO
        password.setOnEditorActionListener { _, _, _ -> attemptLogin(); true }
    }

    private fun attemptLogin() {
        val u = email.text?.toString()?.trim().orEmpty().lowercase()
        val p = password.text?.toString().orEmpty()
        if (u.isEmpty() || p.isEmpty()) {
            error.text = "Заполни почту и пароль"
            return
        }
        setLoading(true)
        error.text = ""
        thread {
            try {
                val api = Api(this)
                val r = api.login(u, p)
                runOnUiThread {
                    Prefs.setUser(this, r.getString("user"))
                    Prefs.setToken(this, r.getString("token"))
                    goMail()
                }
            } catch (e: Api.ApiException) {
                runOnUiThread {
                    setLoading(false)
                    error.text = when (e.code) {
                        401 -> getString(R.string.wrong_credentials)
                        else -> e.message ?: getString(R.string.network_error)
                    }
                }
            }
        }
    }

    private fun setLoading(on: Boolean) {
        signIn.isEnabled = !on
        signIn.text = if (on) getString(R.string.signing_in) else getString(R.string.sign_in)
    }

    private fun goMail() {
        startActivity(Intent(this, MailActivity::class.java))
        finish()
    }

    override fun onBackPressed() {
        if (Prefs.token(this) != null) finishAffinity() else super.onBackPressed()
    }
}
