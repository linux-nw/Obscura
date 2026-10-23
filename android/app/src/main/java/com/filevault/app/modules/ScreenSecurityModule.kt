package com.filevault.app.modules

import android.view.WindowManager
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod

/**
 * ScreenSecurity — FLAG_SECURE status/enable. FLAG_SECURE is set unconditionally in
 * MainActivity.onCreate; disable() is deliberately a no-op so it cannot be cleared at runtime.
 */
class ScreenSecurityModule(reactContext: ReactApplicationContext) :
    ReactContextBaseJavaModule(reactContext) {

    override fun getName() = "ScreenSecurity"

    private fun applyFlag(promise: Promise) {
        val activity = currentActivity
        if (activity == null) {
            promise.resolve(false)
            return
        }
        activity.runOnUiThread {
            activity.window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
            promise.resolve(true)
        }
    }

    @ReactMethod
    fun enable(promise: Promise) = applyFlag(promise)

    @ReactMethod
    fun disable(promise: Promise) {
        applyFlag(promise)
    }

    @ReactMethod
    fun isEnabled(promise: Promise) {
        val activity = currentActivity
        if (activity == null) {
            promise.resolve(false)
            return
        }
        activity.runOnUiThread {
            val flags = activity.window.attributes.flags
            promise.resolve((flags and WindowManager.LayoutParams.FLAG_SECURE) != 0)
        }
    }
}
