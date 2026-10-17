package com.shieldsvpn.vpn

/** Strips anything that could be key material from text before it is logged or shown. */
object Redact {
    private val pem = Regex("-----BEGIN [A-Z0-9 ]+-----[\\s\\S]*?(-----END [A-Z0-9 ]+-----|$)")
    private val longBase64 = Regex("[A-Za-z0-9+/_-]{40,}={0,2}")

    fun text(s: String?): String =
        (s ?: "").replace(pem, "[redacted key]").replace(longBase64, "[redacted]").take(800)

    /** "com.chaquo.python.PyException: ProfileError: message" -> "message". */
    fun pythonError(t: Throwable): String {
        val msg = text(t.message ?: t.javaClass.simpleName)
        return msg.substringAfter("PyException: ").replace(Regex("^[A-Za-z]+Error: "), "")
    }
}
