package com.filevault.app

import com.facebook.react.ReactPackage
import com.facebook.react.bridge.NativeModule
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.uimanager.ViewManager
import com.filevault.app.modules.*

class FileVaultPackage : ReactPackage {

    override fun createNativeModules(reactContext: ReactApplicationContext): List<NativeModule> =
        listOf(
            RNFileVaultModule(reactContext),
            NativeKeyCustodyModule(reactContext),
            Argon2Module(reactContext),
            HardwareKeystoreModule(reactContext),
            DeviceSecurityModule(reactContext),
            IntegrityModule(reactContext),
            ScreenSecurityModule(reactContext),
        )

    override fun createViewManagers(reactContext: ReactApplicationContext): List<ViewManager<*, *>> =
        emptyList()
}
