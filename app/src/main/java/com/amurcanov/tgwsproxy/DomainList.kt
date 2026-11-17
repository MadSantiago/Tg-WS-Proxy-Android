package com.amurcanov.tgwsproxy

/**
 * Список доменов из текстового поля (CF Worker-домены). Записи разделяются
 * запятой или переводом строки.
 */
object DomainList {

    /** Один домен: без схемы и пути, нижний регистр; null, если это не имя хоста. */
    fun normalizeOne(raw: String): String? {
        var d = raw.trim().lowercase()
        d = d.removePrefix("https://").removePrefix("http://")
        d = d.substringBefore('/').trimEnd('.')
        return FakeTls.normalizeDomain(d)
    }

    private fun tokens(raw: String): List<String> =
        raw.split(',', '\n', '\r').map { it.trim() }.filter { it.isNotEmpty() }

    /** Допустимые домены без повторов в порядке ввода. */
    fun parse(raw: String): List<String> =
        tokens(raw).mapNotNull { normalizeOne(it) }.distinct()

    /** Есть ли в тексте записи, не похожие на домен. */
    fun hasInvalid(raw: String): Boolean = tokens(raw).any { normalizeOne(it) == null }

    /** Строка для ядра (SetCfWorkerDomains): домены через запятую. */
    fun forCore(raw: String): String = parse(raw).joinToString(",")
}
