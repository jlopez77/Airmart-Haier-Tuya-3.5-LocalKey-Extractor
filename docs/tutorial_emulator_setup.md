# Emulator Setup (Android Studio)

1. Install Android Studio
2. Create a new device:
   - Pixel 6 or similar
   - Android 13 (API 33)
   - ARM64 image
3. Boot the emulator
4. Download from apkpure & Install the Haier/Airmart APK (Intelligent AC):
adb install APP.apk

Install Frida server:


adb push frida-server-17.5.1-android-arm64 /data/local/tmp/frida-server

adb shell "chmod 755 /data/local/tmp/frida-server"

adb shell "/data/local/tmp/frida-server &"
