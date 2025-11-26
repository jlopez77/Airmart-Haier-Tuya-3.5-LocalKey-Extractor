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

1. Install Android Studio
2. Create an Android 13 ARM64 emulator
3. Install the official Haier/Airmart app
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
