package com.rivalafk.zentmail

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.AdapterView
import android.widget.BaseAdapter
import android.widget.Button
import android.widget.ImageButton
import android.widget.ListView
import android.widget.Spinner
import android.widget.SpinnerAdapter
import android.widget.TextView
import android.widget.Toast
import org.json.JSONArray
import org.json.JSONObject
import kotlin.concurrent.thread

class MailActivity : Activity() {

    private lateinit var folderSpinner: Spinner
    private lateinit var messageList: ListView
    private lateinit var emptyView: TextView

    private var folders: List<String> = listOf("INBOX")
    private var currentFolder = "INBOX"
    private var messages = JSONArray()

    private val folderNames = mapOf(
        "INBOX" to R.string.inbox,
        "Junk" to R.string.spam,
        "Sent" to R.string.sent,
        "Trash" to R.string.trash,
    )

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        folderSpinner = findViewById(R.id.folder_spinner)
        messageList = findViewById(R.id.message_list)
        emptyView = findViewById(R.id.empty)
        findViewById<Button>(R.id.compose_btn).setOnClickListener {
            startActivity(Intent(this, ComposeActivity::class.java))
        }

        bindSpinner()
        loadFoldersAndMessages()

        messageList.setOnItemClickListener { _, _, position, _ ->
            val m = messages.optJSONObject(position) ?: return@setOnItemClickListener
            val i = Intent(this, ReaderActivity::class.java).apply {
                putExtra("folder", currentFolder)
                putExtra("uid", m.optInt("uid"))
                putExtra("subject", m.optString("subject"))
                putExtra("from", m.optString("from"))
                putExtra("to", m.optString("to"))
                putExtra("date", m.optString("date"))
            }
            startActivity(i)
        }
    }

    override fun onResume() {
        super.onResume()
        loadMessages()
    }

    private fun bindSpinner() {
        folderSpinner.adapter = object : SpinnerAdapter {
            override fun getCount() = folders.size
            override fun getItem(position: Int) = folders[position]
            override fun getItemId(position: Int) = position.toLong()
            override fun getView(p: Int, convertView: View?, parent: ViewGroup) =
                (convertView ?: LayoutInflater.from(this@MailActivity).inflate(android.R.layout.simple_spinner_item, parent, false)).also {
                    (it as TextView).text = folderLabel(folders[p])
                }
            override fun getDropDownView(p: Int, convertView: View?, parent: ViewGroup) =
                (convertView ?: LayoutInflater.from(this@MailActivity).inflate(android.R.layout.simple_spinner_dropdown_item, parent, false)).also {
                    (it as TextView).text = folderLabel(folders[p])
                }
            override fun hasStableIds() = true
            override fun getItemViewType(p: Int) = 0
            override fun getViewTypeCount() = 1
            override fun registerDataSetObserver(observer: android.database.DataSetObserver?) {}
            override fun unregisterDataSetObserver(observer: android.database.DataSetObserver?) {}
            override fun isEmpty() = folders.isEmpty()
        }
        folderSpinner.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
            override fun onItemSelected(parent: AdapterView<*>?, view: View?, position: Int, id: Long) {
                val folder = folders[position]
                if (folder != currentFolder) {
                    currentFolder = folder
                    loadMessages()
                }
            }
            override fun onNothingSelected(parent: AdapterView<*>?) {}
        }
    }

    private fun folderLabel(f: String): String = folderNames[f]?.let { getString(it) } ?: f

    private fun loadFoldersAndMessages() {
        thread {
            try {
                val api = Api(this)
                val list = api.folders()
                runOnUiThread {
                    folders = if (list.contains("INBOX")) list else listOf("INBOX") + list
                    bindSpinner()
                    folderSpinner.setSelection(folders.indexOf("INBOX").coerceAtLeast(0))
                    loadMessages()
                }
            } catch (e: Api.ApiException) {
                runOnUiThread { loadMessages() }
            }
        }
    }

    private fun loadMessages() {
        messageList.adapter = null
        emptyView.visibility = View.GONE
        messageList.visibility = View.VISIBLE
        thread {
            try {
                val api = Api(this)
                val list = api.messages(currentFolder)
                runOnUiThread {
                    messages = JSONArray()
                    for (i in 0 until list.length()) messages.put(list.get(i))
                    if (messages.length() == 0) {
                        messageList.visibility = View.GONE
                        emptyView.text = getString(R.string.inbox) + " — пусто"
                        emptyView.visibility = View.VISIBLE
                    } else {
                        messageList.adapter = MessageAdapter(messages)
                    }
                }
            } catch (e: Api.ApiException) {
                runOnUiThread {
                    if (e.code == 401) {
                        Prefs.clear(this)
                        startActivity(Intent(this, LoginActivity::class.java))
                        finish()
                    } else {
                        Toast.makeText(this, e.message ?: getString(R.string.error_load), Toast.LENGTH_LONG).show()
                        emptyView.text = getString(R.string.error_load)
                        emptyView.visibility = View.VISIBLE
                        messageList.visibility = View.GONE
                    }
                }
            }
        }
    }

    private inner class MessageAdapter(private val items: JSONArray) : BaseAdapter() {
        override fun getCount() = items.length()
        override fun getItem(position: Int): Any = items.get(position)
        override fun getItemId(position: Int) = position.toLong()
        override fun hasStableIds() = true

        override fun getView(position: Int, convertView: View?, parent: ViewGroup): View {
            val m = items.optJSONObject(position) ?: JSONObject()
            val view = convertView ?: LayoutInflater.from(this@MailActivity)
                .inflate(R.layout.item_message, parent, false)
            val from = view.findViewById<TextView>(R.id.item_from)
            val subject = view.findViewById<TextView>(R.id.item_subject)
            val preview = view.findViewById<TextView>(R.id.item_preview)
            val date = view.findViewById<TextView>(R.id.item_date)
            val row = view.findViewById<View>(R.id.item_row)

            from.text = m.optString("from", "—")
            subject.text = m.optString("subject", "—")
            preview.text = m.optString("subject", "") + " · " + m.optString("date", "")
            date.text = m.optString("date", "")
            row.setBackgroundResource(
                if (m.optBoolean("unread", false)) R.drawable.row_unread else R.drawable.row_normal
            )
            return view
        }
    }
}
