package com.amurcanov.tgwsproxy

/**
 * Fake TLS (ee-secret): проверка домена маскировки и секрет для ссылки
 * tg://proxy. Ядро (SetFakeTlsDomain) включает Fake TLS непустым доменом.
 */
object FakeTls {

    /** Домен в нижнем регистре или null, если он не годится как имя хоста. */
    fun normalizeDomain(raw: String): String? {
        val d = raw.trim().trimEnd('.').lowercase()
        if (d.length !in 4..253 || '.' !in d) return null
        val ok = d.split('.').all { label ->
            label.length in 1..63 &&
                label.first() != '-' && label.last() != '-' &&
                label.all { it in 'a'..'z' || it in '0'..'9' || it == '-' }
        }
        return if (ok) d else null
    }

    /** Домен для ядра: пусто, если Fake TLS выключен или домен неверен. */
    fun effectiveDomain(enabled: Boolean, raw: String): String =
        if (enabled) normalizeDomain(raw) ?: "" else ""

    /** dd{secret} без Fake TLS, ee{secret}{hex(domain)} с ним (как GetSecretWithPrefix). */
    fun linkSecret(secret: String, domain: String): String =
        if (domain.isEmpty()) {
            "dd$secret"
        } else {
            "ee$secret" + domain.toByteArray(Charsets.US_ASCII).joinToString("") { "%02x".format(it) }
        }
}
