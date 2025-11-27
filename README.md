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

# 🚀 Quick Start (5 minutes)

**Prerequisites:**
- Python **3.8+** installed and working.

---

# ✅ STEP 1 — Install Android Studio + ADB (Platform-Tools)

This step ensures:

- Android Studio installed  
- Android SDK + Platform-Tools installed  
- `adb` working globally on **macOS / Windows / Linux**

---

## 1. Download & Install Android Studio

**macOS / Windows / Linux**

- Download the installer from the official Android Studio website.
- Install normally.
- No custom configuration required at this stage.

---

## 2. Open Android Studio and Install SDK Components

1. Launch **Android Studio**.
2. On the welcome screen click:  
   **More Actions → SDK Manager**  
   *(If a project is open: File → Settings → Android SDK)*

3. In **SDK Platforms**:
   - Select **any Android version**, ideally **Android 11 or Android 12**.
   - Click **Apply** → wait for the download to finish.

4. Go to **SDK Tools** tab:
   - Enable **Android SDK Platform-Tools**
   - *(Optional but recommended)* enable:
     - **Android Emulator**
     - **Android SDK Build-Tools**
   - Click **Apply → OK**

This installs:

- `adb`
- Emulator system images
- Essential build tools

---

## 3. Ensure `adb` Is Available in the Terminal

### macOS / Linux

Try:

```bash
adb version
```

If it works → you're done.

If not, add platform-tools manually:
```bash
export PATH=$PATH:$HOME/Library/Android/sdk/platform-tools     # macOS
export PATH=$PATH:$HOME/Android/Sdk/platform-tools             # Linux
```
To make it persistent:
```bash
echo 'export PATH=$PATH:$HOME/Library/Android/sdk/platform-tools' >> ~/.zshrc
source ~/.zshrc
```

### Windows

Test in PowerShell or CMD:

```powershell
adb version
```

If it prints the version → done.

If it says "adb is not recognized" then add the following folder to your PATH:
```bash
C:\Users\<YOUR_USER>\AppData\Local\Android\Sdk\platform-tools
```

To add it permanently (PowerShell):
```bash
setx PATH "$Env:PATH;C:\Users\<YOUR_USER>\AppData\Local\Android\Sdk\platform-tools"
```

Now close/open the terminal and test again:
```
adb version
```

If it prints something like:
```
Android Debug Bridge version x.y.z
```


## → ADB is successfully installed.




# ✅ STEP 2 — Install Frida on the Host (macOS / Windows / Linux)

In this step we install **Frida CLI** and **Frida Python bindings** on your computer.

We’ll need:

- `frida` (the core)
- `frida-tools` (CLI commands like `frida-ps`)

Later, we’ll match this version with `frida-server` on the Android side.

---

## 2.1 Install Frida via `pip`

**Same commands on macOS / Windows / Linux**  
(Use `python` instead of `python3` if that’s your default.)

```bash
python3 -m pip install --upgrade frida frida-tools
```

If you are using a virtualenv, activate it first, then run the same command.

## 2.2 Verify Frida Installation

### 1) Check Frida CLI

Run this in your terminal:

```
frida --version
```

You should see a version number, for example:

```
16.5.6
```

**Important:**  
Remember this version. You must download **the same version** of `frida-server` later.

---

### 2) Check Frida Python bindings

Run:

```
python3 -c "import frida; print(frida.version)"
```

You should see the same (or very close) version number.

If both checks return a version number →  
🎉 **STEP 2 is fully complete.**

# ✅ STEP 3 — Create an Android Emulator & Verify ADB Detection

We now create a clean Android environment where we will later run  
**frida-server** and install the **com.aircondition.smart** app.

This step works the same on **macOS / Windows / Linux**.

---

## 3.1 Open Android Studio → Device Manager

1. Launch **Android Studio**.
2. On the welcome screen select:  
   **More Actions → Device Manager**  
   *(If a project is open: Tools → Device Manager)*

3. Click **Create Device**.

---

## 3.2 Choose an Emulator Device

Recommended:

- **Pixel 6** or **Pixel 4**
- **Android 11 (R)** or **Android 12 (S)**  
  (Both work perfectly with Frida.)

Avoid:

- Android 13/14 images (some restrictions).
- ARM images on Intel CPUs (too slow).

If possible:

- Prefer **x86_64** image (fastest).
- If using Apple Silicon, prefer **arm64-v8a**.

Click **Next** → download image if needed → **Finish**.

---

## 3.3 Start the Emulator

In Device Manager:

- Click the **▶ Play** button next to your virtual device.

Wait until Android fully boots.

---

## 3.4 Verify the Emulator with ADB

Open a terminal and run:

```
adb devices
```

Expected output:

```
List of devices attached
emulator-5554 device
```

If your output contains at least one line like:

- `emulator-5554 device`
- `emulator-xxxx device`

→ The emulator is detected correctly.

---

## 3.5 (Optional) Restart ADB if the device doesn't appear

If you see `unauthorized` or nothing shows up:

```
adb kill-server
adb start-server
adb devices
```

If still not appearing, close the emulator and start it again.

---

🎉 **STEP 3 is complete when:**

- The emulator boots.
- `adb devices` shows the emulator as `device`.





