-keep class com.sun.jna.** { *; }
-keep class * implements com.sun.jna.** { *; }
-dontwarn com.sun.jna.**
-keep class com.goterl.lazysodium.** { *; }
-dontwarn com.goterl.lazysodium.**
-keep class com.filevault.app.modules.** { *; }
-keep class com.filevault.app.FileVaultPackage { *; }
-keepclassmembers class * {
    @com.facebook.react.bridge.ReactMethod <methods>;
}
-assumenosideeffects class android.util.Log {
    public static int d(...);
    public static int v(...);
    public static int i(...);
}
