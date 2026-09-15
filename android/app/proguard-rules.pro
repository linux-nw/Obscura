# Add project specific ProGuard rules here.
# By default, the flags in this file are appended to flags specified
# in /usr/local/Cellar/android-sdk/24.3.3/tools/proguard/proguard-android.txt
# You can edit the include path and order by changing the proguardFiles
# directive in build.gradle.
#
# For more details, see
#   http://developer.android.com/guide/developing/tools/proguard.html

# react-native-reanimated
-keep class com.swmansion.reanimated.** { *; }
-keep class com.facebook.react.turbomodule.** { *; }

# Add any project specific keep options here:

# Native crypto bridge (Argon2id + XChaCha20-Poly1305 via libsodium, JNA-bound). JNA binds
# native (C) libsodium symbols by reflecting over these classes' method names at runtime;
# if R8 renames them, the binding silently fails and the app falls back to (weaker,
# non-constant-time) pure-JS crypto with no visible error. React Native's own bundled
# consumer rules already keep classes implementing NativeModule, but not this layer
# underneath them — see AUDIT_2026-09-15-v2.md, B.3.
-keep class com.filevault.app.modules.** { *; }
-keep class com.goterl.lazysodium.** { *; }
-keep class com.sun.jna.** { *; }
