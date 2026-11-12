package com.amurcanov.tgwsproxy

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Build
import android.util.Log

/**
 * Следит за сменой сети по умолчанию и сообщает о ней ядру через
 * [NativeProxy.onNetworkChanged].
 *
 * Сообщается только смена самой сети: onAvailable с другим объектом
 * [Network], чем прошлый, и потеря текущей сети. onCapabilitiesChanged и
 * onLinkPropertiesChanged не пробрасываются: они приходят часто и сети не
 * меняют. Повторные события дополнительно сливает ядро (дебаунс 1,5 с).
 *
 * API 24+: registerDefaultNetworkCallback. API 21–23: registerNetworkCallback
 * с NET_CAPABILITY_INTERNET (метода для сети по умолчанию там нет, поэтому
 * при одновременных Wi-Fi и сотовой возможны лишние сбросы пула).
 */
class NetworkChangeMonitor(context: Context) {

    private val connectivityManager =
        context.applicationContext.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager

    private var callback: ConnectivityManager.NetworkCallback? = null

    // Сеть, о которой ядро уже знает (или которая была при регистрации).
    @Volatile
    private var currentNetwork: Network? = null

    // API 21–22: activeNetwork нет, поэтому первый onAvailable после
    // регистрации считаем исходной сетью и не сообщаем.
    @Volatile
    private var skipFirstAvailable = false

    companion object {
        private const val TAG = "NetworkChangeMonitor"

        // Значения transport в OnNetworkChanged.
        private const val TRANSPORT_UNKNOWN = 0
        private const val TRANSPORT_WIFI = 1
        private const val TRANSPORT_CELLULAR = 2
        private const val TRANSPORT_OTHER = 3
    }

    @Synchronized
    fun start() {
        val cm = connectivityManager ?: return
        if (callback != null) return

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            currentNetwork = cm.activeNetwork
            skipFirstAvailable = false
        } else {
            currentNetwork = null
            @Suppress("DEPRECATION")
            skipFirstAvailable = cm.activeNetworkInfo?.isConnected == true
        }

        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                if (skipFirstAvailable) {
                    skipFirstAvailable = false
                    currentNetwork = network
                    return
                }
                if (network == currentNetwork) return
                currentNetwork = network
                notifyNative(1, transportOf(network))
            }

            override fun onLost(network: Network) {
                if (network != currentNetwork) return
                currentNetwork = null
                notifyNative(0, TRANSPORT_UNKNOWN)
            }
        }

        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                cm.registerDefaultNetworkCallback(cb)
            } else {
                val request = NetworkRequest.Builder()
                    .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                    .build()
                cm.registerNetworkCallback(request, cb)
            }
            callback = cb
            Log.d(TAG, "Network callback registered")
        } catch (e: Exception) {
            // SecurityException без ACCESS_NETWORK_STATE, лимит колбэков и т.п.:
            // прокси работает без сигнала о смене сети, на keepalive и таймаутах.
            Log.w(TAG, "Failed to register network callback", e)
        }
    }

    @Synchronized
    fun stop() {
        val cb = callback ?: return
        callback = null
        currentNetwork = null
        skipFirstAvailable = false
        try {
            connectivityManager?.unregisterNetworkCallback(cb)
            Log.d(TAG, "Network callback unregistered")
        } catch (e: Exception) {
            Log.w(TAG, "Failed to unregister network callback", e)
        }
    }

    private fun transportOf(network: Network): Int {
        val caps = try {
            connectivityManager?.getNetworkCapabilities(network)
        } catch (e: Exception) {
            null
        } ?: return TRANSPORT_UNKNOWN
        return when {
            caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> TRANSPORT_WIFI
            caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> TRANSPORT_CELLULAR
            else -> TRANSPORT_OTHER
        }
    }

    private fun notifyNative(state: Int, transport: Int) {
        try {
            val result = NativeProxy.onNetworkChanged(state, transport)
            Log.i(TAG, "Network ${if (state == 1) "changed" else "lost"} (transport=$transport), core=$result")
        } catch (e: Throwable) {
            // UnsatisfiedLinkError, если .so собрана без OnNetworkChanged.
            Log.w(TAG, "OnNetworkChanged failed", e)
        }
    }
}
