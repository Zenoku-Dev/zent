package com.rivalafk.zentmail

import android.content.Context
import android.content.SharedPreferences

object Prefs {
    private const val FILE = "zent-mail"
    private const val KEY_HOST = "host"
    private const val KEY_USER = "user"
    private const val KEY_TOKEN = "token"

    private fun sp(ctx: Context): SharedPreferences = ctx.getSharedPreferences(FILE, Context.MODE_PRIVATE)

    fun host(ctx: Context): String = sp(ctx).getString(KEY_HOST, "https://mail.rival-afk.com/api")!!
    fun user(ctx: Context): String? = sp(ctx).getString(KEY_USER, null)
    fun token(ctx: Context): String? = sp(ctx).getString(KEY_TOKEN, null)

    fun setHost(ctx: Context, h: String) = sp(ctx).edit().putString(KEY_HOST, h).apply()
    fun setUser(ctx: Context, u: String) = sp(ctx).edit().putString(KEY_USER, u).apply()
    fun setToken(ctx: Context, t: String?) =
        if (t == null) sp(ctx).edit().remove(KEY_TOKEN).apply()
        else sp(ctx).edit().putString(KEY_TOKEN, t).apply()

    fun clear(ctx: Context) = sp(ctx).edit().clear().apply()
}
