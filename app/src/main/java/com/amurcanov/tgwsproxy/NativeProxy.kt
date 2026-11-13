package com.amurcanov.tgwsproxy

import com.sun.jna.Library
import com.sun.jna.Native
import com.sun.jna.Pointer

interface ProxyLibrary : Library {
    companion object {
        val INSTANCE = Native.load("tgwsproxy", ProxyLibrary::class.java) as ProxyLibrary
    }

    fun StartProxy(host: String, port: Int, dcIps: String, secret: String, verbose: Int): Int
    fun StopProxy(): Int
    fun SetPoolSize(size: Int)
    fun SetBufferSizeKb(kb: Int)
    fun SetCfProxyCacheDir(cacheDir: String)
    fun SetCfProxyConfig(enabled: Int, priority: Int, userDomain: String)
    fun SetCfWorkerDomains(domains: String)
    fun SetFakeTlsDomain(domain: String)
    fun SetDisableSecure(v: Int)
    fun SetCfH2Media(v: Int)
    fun SetTlsVerify(v: Int)
    fun SetForceTestDc(v: Int)
    fun SetProxyProtocol(v: Int)
    fun OnNetworkChanged(state: Int, transport: Int): Int
    fun GetSecretWithPrefix(): Pointer?
    fun GetStats(): Pointer?
    fun FreeString(p: Pointer)
}

object NativeProxy {
    fun startProxy(host: String, port: Int, dcIps: String, secret: String, verbose: Int): Int {
        return ProxyLibrary.INSTANCE.StartProxy(host, port, dcIps, secret, verbose)
    }

    fun stopProxy(): Int {
        return ProxyLibrary.INSTANCE.StopProxy()
    }

    fun setPoolSize(size: Int) {
        ProxyLibrary.INSTANCE.SetPoolSize(size)
    }

    fun setBufferSizeKb(kb: Int) {
        ProxyLibrary.INSTANCE.SetBufferSizeKb(kb)
    }

    fun setCfProxyCacheDir(cacheDir: String) {
        ProxyLibrary.INSTANCE.SetCfProxyCacheDir(cacheDir)
    }

    fun setCfProxyConfig(enabled: Boolean, priority: Boolean, userDomain: String) {
        ProxyLibrary.INSTANCE.SetCfProxyConfig(
            if (enabled) 1 else 0,
            if (priority) 1 else 0,
            userDomain
        )
    }

    fun setCfWorkerDomains(domains: String) {
        ProxyLibrary.INSTANCE.SetCfWorkerDomains(domains)
    }

    fun setFakeTlsDomain(domain: String) {
        ProxyLibrary.INSTANCE.SetFakeTlsDomain(domain)
    }

    fun setDisableSecure(v: Boolean) {
        ProxyLibrary.INSTANCE.SetDisableSecure(if (v) 1 else 0)
    }

    /** Проверка TLS-сертификатов WS (по умолчанию в ядре включена); до startProxy. */
    fun setTlsVerify(v: Boolean) {
        ProxyLibrary.INSTANCE.SetTlsVerify(if (v) 1 else 0)
    }

    /** HTTP/2-мультиплексирование медиа через CF; вызывать до startProxy. */
    fun setCfH2Media(v: Boolean) {
        ProxyLibrary.INSTANCE.SetCfH2Media(if (v) 1 else 0)
    }

    fun setForceTestDc(v: Boolean) {
        ProxyLibrary.INSTANCE.SetForceTestDc(if (v) 1 else 0)
    }

    fun setProxyProtocol(v: Boolean) {
        ProxyLibrary.INSTANCE.SetProxyProtocol(if (v) 1 else 0)
    }

    /**
     * Сообщает ядру о смене сети по умолчанию (state=1) или её потере (state=0).
     * transport: 0 неизвестно, 1 Wi-Fi, 2 сотовая, 3 прочее.
     * Возврат: 0 принято, -1 прокси не запущен. Не блокирует.
     */
    fun onNetworkChanged(state: Int, transport: Int): Int {
        return ProxyLibrary.INSTANCE.OnNetworkChanged(state, transport)
    }

    /** Returns the full secret with correct prefix (dd or ee+domain_hex) */
    fun getSecretWithPrefix(): String? {
        val ptr = ProxyLibrary.INSTANCE.GetSecretWithPrefix() ?: return null
        val res = ptr.getString(0)
        ProxyLibrary.INSTANCE.FreeString(ptr)
        return res
    }

    fun getStats(): String? {
        val ptr = ProxyLibrary.INSTANCE.GetStats() ?: return null
        val res = ptr.getString(0)
        ProxyLibrary.INSTANCE.FreeString(ptr)
        return res
    }
}
