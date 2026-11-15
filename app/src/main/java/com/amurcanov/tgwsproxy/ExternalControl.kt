package com.amurcanov.tgwsproxy

import android.app.Activity
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.os.IBinder
import android.os.RemoteException
import android.util.Log
import android.view.WindowManager
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull

/**
 * Entry points for other apps (for example a Telegram client plugin):
 *  - START_PROXY (activity): start with the saved settings;
 *  - STOP_PROXY (receiver): stop;
 *  - ARM_GUARD / DISARM_GUARD (receiver): stop the proxy when the caller dies.
 * No extras are read except the guard binder, nothing about the configuration
 * is returned.
 *
 * Every entry point is exported without a permission, so any installed app can
 * reach it. They do nothing unless the user turned on «Управление прокси извне»
 * in the experimental features card (off by default).
 */
object ExternalControl {
    const val ACTION_START_PROXY = "com.amurcanov.tgwsproxy.action.START_PROXY"
    const val ACTION_STOP_PROXY = "com.amurcanov.tgwsproxy.action.STOP_PROXY"
    const val ACTION_ARM_GUARD = "com.amurcanov.tgwsproxy.action.ARM_GUARD"
    const val ACTION_DISARM_GUARD = "com.amurcanov.tgwsproxy.action.DISARM_GUARD"
    const val EXTRA_GUARD = "guard"
    const val TAG = "ExternalControl"
    const val STOP_WAIT_MS = 5_000L
    const val SETTLE_MS = 350L

    /** Reads the switch; a read failure counts as "off". */
    suspend fun isAllowed(context: Context): Boolean =
        try {
            SettingsStore(context).externalControl.first()
        } catch (e: Exception) {
            Log.w(TAG, "cannot read external control setting", e)
            false
        }
}

/**
 * Stops the proxy when the process that handed over the guard binder dies
 * (swiped away, killed by the system, crashed). The binder carries no data.
 * Turning the switch off disarms it (see SettingsStore.saveExternalControl callers).
 */
object ExternalGuard {
    private var token: IBinder? = null
    private var appContext: Context? = null
    private val recipient = IBinder.DeathRecipient { onOwnerDied() }

    @Synchronized
    fun arm(context: Context, binder: IBinder) {
        unlink()
        appContext = context
        try {
            binder.linkToDeath(recipient, 0)
            token = binder
            Log.i(ExternalControl.TAG, "guard armed")
        } catch (e: RemoteException) {
            onOwnerDied()
        }
    }

    @Synchronized
    fun disarm() {
        unlink()
        Log.i(ExternalControl.TAG, "guard disarmed")
    }

    private fun unlink() {
        val current = token ?: return
        try {
            current.unlinkToDeath(recipient, 0)
        } catch (e: NoSuchElementException) {
        }
        token = null
    }

    @Synchronized
    private fun onOwnerDied() {
        token = null
        val context = appContext ?: return
        Log.i(ExternalControl.TAG, "guard owner died, running=${ProxyService.isRunning.value}")
        if (!ProxyService.isRunning.value) return
        try {
            ProxyController.stop(context)
        } catch (e: Exception) {
            Log.w(ExternalControl.TAG, "stop on owner death refused", e)
        }
    }
}

/**
 * START only. A start request that arrives while the service is still shutting
 * down is held until the shutdown finishes; the service silently ignores starts
 * during it. While the activity is on screen the app counts as foreground, so
 * Android 12+ lets it start the foreground service. The window is not touchable
 * and not focusable so it never blocks the app below. The caller must be
 * visible itself, otherwise Android blocks starting this activity.
 */
class ExternalControlActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(
            WindowManager.LayoutParams.FLAG_NOT_TOUCHABLE or
                WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE
        )

        if (intent?.action != ExternalControl.ACTION_START_PROXY) {
            finish()
            return
        }

        val appContext = applicationContext
        // finish() only after the request, so the app stays foreground until then.
        CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate).launch {
            try {
                if (!ExternalControl.isAllowed(appContext)) {
                    Log.i(ExternalControl.TAG, "start ignored: external control is off")
                    return@launch
                }
                val wasRunning = ProxyService.isRunning.value
                Log.i(ExternalControl.TAG, "start requested, running=$wasRunning")
                val stopped = withTimeoutOrNull(ExternalControl.STOP_WAIT_MS) {
                    ProxyService.isRunning.first { !it }
                } != null
                if (!stopped) {
                    Log.i(ExternalControl.TAG, "still running, start skipped")
                    return@launch
                }
                if (wasRunning) delay(ExternalControl.SETTLE_MS)
                ProxyController.startFromSavedSettings(
                    context = appContext,
                    showInvalidPortToast = false
                )
            } catch (e: Exception) {
                Log.w(ExternalControl.TAG, "start refused", e)
            } finally {
                finish()
            }
        }
    }
}

/** STOP, ARM_GUARD, DISARM_GUARD. Starting from the background is not offered. */
class ExternalControlReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent?) {
        val action = intent?.action
        if (action != ExternalControl.ACTION_STOP_PROXY &&
            action != ExternalControl.ACTION_ARM_GUARD &&
            action != ExternalControl.ACTION_DISARM_GUARD
        ) return
        val appContext = context.applicationContext
        val binder = if (action == ExternalControl.ACTION_ARM_GUARD) {
            intent.extras?.getBinder(ExternalControl.EXTRA_GUARD)
        } else null
        // The switch lives in DataStore, which is read asynchronously.
        val pending = goAsync()
        CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate).launch {
            try {
                if (!ExternalControl.isAllowed(appContext)) {
                    Log.i(ExternalControl.TAG, "$action ignored: external control is off")
                    return@launch
                }
                when (action) {
                    ExternalControl.ACTION_STOP_PROXY -> ProxyController.stop(appContext)
                    ExternalControl.ACTION_ARM_GUARD ->
                        if (binder != null) ExternalGuard.arm(appContext, binder)
                    ExternalControl.ACTION_DISARM_GUARD -> ExternalGuard.disarm()
                }
            } catch (e: Exception) {
                Log.w(ExternalControl.TAG, "$action refused", e)
            } finally {
                pending.finish()
            }
        }
    }
}
