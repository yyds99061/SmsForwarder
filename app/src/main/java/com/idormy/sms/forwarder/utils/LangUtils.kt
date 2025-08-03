package com.idormy.sms.forwarder.utils

import java.util.Locale

/**
 * 统一获取 Accept-Language，用于请求头
 * zh → zh-cn
 * vi → vi
 * th → th
 * 其它 → en
 */
object LangUtils {
    fun getAcceptLang(): String {
        val lang = Locale.getDefault().language.lowercase()
        return when {
            lang.startsWith("zh") -> "zh-cn"
            lang.startsWith("vi") -> "vi"
            lang.startsWith("th") -> "th"
            else -> "en"
        }
    }
}