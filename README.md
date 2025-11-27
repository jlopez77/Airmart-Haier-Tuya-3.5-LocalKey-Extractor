# Airmart / Haier Tuya 3.5 LocalKey Extractor

Extract the **Device ID** and **LocalKey** from any **Tuya 3.5** WiFi device
(Airmart, Haier, Gree-Tuya, TCL, Galanz, Midea OEM, etc.)
using a reproducible **Frida + Android emulator** method.

No root required.  
No MITM.  
No firmware hacking.  
No cloud access needed.

This method works even for **devices locked to the Haier/Thingclips cloud**
which do not expose their local keys through Tuya IoT.

---

## ✨ Features

- Works with Tuya 3.5 (encrypted ECDH session)
- Dumps **devId** and **localKey** directly from the official app
- Compatible with:
  - Haier-based Airmart AC units
  - Gree OEM units with Tuya WiFi
  - “Thingclips Platform” devices
  - Tuya 3.3 and 3.4 (legacy)
- 100% offline, reproducible and cross-platform.
- Produces ready-to-use YAML for Home Assistant (Tuya Local).

---

## 🚀 Quick Start (5 minutes)

Prerequisites:

Python 3.8+ installed and working.



STEP 1 — Install Android Studio + ADB (Platform-Tools)

This step ensures:

Android Studio installed

SDK + Platform-Tools installed

adb works globally

1. Download & Install Android Studio

macOS / Windows / Linux
Download from the official Android Studio website and install normally.

No custom configuration needed.

2. Open Android Studio and install SDK components

Launch Android Studio.

On the welcome screen click:
More Actions → SDK Manager
(If a project is open: File → Settings → Android SDK)

In SDK Platforms:

Select any Android version, ideally Android 11 or 12.

Click Apply → wait for download.

Go to SDK Tools tab:

Check Android SDK Platform-Tools

(Optional but recommended) check:

Android Emulator

Android SDK Build-Tools

Click Apply → OK

This installs:

adb

Emulator system

Essential build tools

3. Ensure adb is available from terminal
macOS / Linux:

If Android Studio added it to PATH automatically, this works:

adb version


If not, add platform-tools manually:

export PATH=$PATH:$HOME/Library/Android/sdk/platform-tools     # macOS
export PATH=$PATH:$HOME/Android/Sdk/platform-tools             # Linux


To make it persistent:

echo 'export PATH=$PATH:$HOME/Library/Android/sdk/platform-tools' >> ~/.zshrc
source ~/.zshrc

Windows:

Check:

adb version


If it fails, add this to PATH:

C:\Users\<YOUR_USER>\AppData\Local\Android\Sdk\platform-tools

4. Verify ADB is working

Run:

adb version


Expected output:

Android Debug Bridge version x.y.z


If you see this → Step 1 is fully complete ✔️






2. Create an Android 13 ARM64 emulator
3. Install the official Haier/Airmart app (Intelligent Air for the Airmart ACs)
4. Install Frida-Server in the emulator
5. Run:

python extractor/extract_localkeys.py

Example output:

[KEY] bf2bbc01486531b8942uho = ZwT(dgeE][f07_Vc

[KEY] bf76f636ff6f0b420fllmo = HyDbylnt7biqI$Yr

[KEY] bfa0a38a8dd580dcd7a1n = !6LnGCaT'bsfeQ9?

Copy these into Home Assistant → Tuya Local (https://github.com/make-all/tuya-local) → and the device works 100% LAN only.

---

## 📁 Project Structure

extractor/

hook_localkeys.js # Frida script that hooks DeviceBean.getLocalKey()

extract_localkeys.py # Automated runner

frida_launcher.py # Utility to launch frida-server + inject the script

adb_helpers.py # ADB utilities


---

## 📝 License

MIT License.
