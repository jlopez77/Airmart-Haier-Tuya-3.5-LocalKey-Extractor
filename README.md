# Airmart / Haier Tuya 3.5 LocalKey Extractor

Extract the **Device ID** and **LocalKey** from Intelligent Air APP **Tuya 3.5** WiFi device
(Airmart, Haier, Gree-Tuya, TCL, Galanz, Midea OEM, etc.)
using a reproducible **Frida + Android emulator** method.

No root required.  
No MITM.  
No firmware hacking.  
No cloud access needed.

This method works for **devices locked to the Haier/Thingclips cloud** which do not expose their local keys through Tuya IoT.
Probably will work with other apps that use ThingClips with little or no modification. 

**USE AT YOUR OWN RISK**

---

## ✨ Features

- Works with Tuya 3.5 (encrypted ECDH session)
- Dumps **devId** and **localKey** directly from the official app
- Compatible with:
  - Haier-based Airmart AC units
  - Gree OEM units with Tuya WiFi
  - “Thingclips Platform” devices
  - Tuya 3.3 and 3.4 (legacy)

- DeviceId & LocalKey ready to use with Tuya Local (please use a static IP in your router for the devices)

---

# 🚀 Quick Start (10 minutes)

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


# ✅ STEP 4 — Install **frida-server** on the Android Emulator

Now that the emulator is running and ADB detects it, we install  
**frida-server** inside the device.  
This is required for hooking the app later.

---

# 4.1 Determine the Emulator CPU Architecture

In your terminal:

```
adb shell getprop ro.product.cpu.abi
```

Typical outputs:

- `x86_64` → emulator using Intel/AMD image
- `arm64-v8a` → emulator using ARM image (Apple Silicon or ARM-based image)

Remember this value — you need the matching frida-server binary.

---

# 4.2 Download the Matching frida-server

1. Run on your PC:

```
frida --version
```

Example output:

```
16.5.6
```

2. Go to the official Frida releases page. (https://github.com/frida/frida/releases)

3. Download the file:

```
frida-server-<VERSION>-android-<ABI>.xz
```

For example:

- `frida-server-16.5.6-android-x86_64.xz`  
- `frida-server-16.5.6-android-arm64.xz`

4. Extract the `.xz` file:

**macOS / Linux:**
```
xz -d frida-server-<VERSION>-android-<ABI>.xz
```

**Windows:**
Use 7-Zip to extract the file.

After extraction you should have a file like:

```
frida-server-16.5.6-android-x86_64
```

---

# 4.3 Push frida-server to the Emulator

Run:

```
adb root
adb push frida-server-<VERSION>-android-<ABI> /data/local/tmp/frida-server
adb shell chmod 755 /data/local/tmp/frida-server
```

`adb root` should work automatically on Android emulators  
(it does **not** work on physical unrooted phones).

---

# 4.4 Start frida-server inside the Emulator

Run:

```
adb shell /data/local/tmp/frida-server &
```

This launches frida-server in the background.

---

# 4.5 Verify frida-server is Running

On your PC:

```
frida-ps -U
```

Expected output: a list of running Android processes, for example:

```
PID Name

123 system_server
456 com.android.settings
789 com.android.systemui
```

If you see processes listed → **frida-server is working** 🎉

If you get:

- `Failed to enumerate processes`  
- or `Timed out while waiting for the connection`

Then try restarting:

```
adb kill-server
adb start-server
adb shell /data/local/tmp/frida-server &
frida-ps -U
```

🎉 **STEP 4 is now complete** when:

- The emulator is running
- frida-server is installed and executable
- `frida-ps -U` lists processes

---

# ✅ STEP 5 — Install the **com.aircondition.smart** App in the Emulator

Now we need the **exact same app** you use on your phone:  
`com.aircondition.smart` (the Intelligent Air / ThingClips-based AC app).

The goal: have it running **inside the emulator**, so Frida can hook it.

---

## 5.1 Get the APK (high-level options)

You need an APK file named something like:

- `com.aircondition.smart.apk`

There are several ways to obtain it (you only need **one**):

1. **From your physical Android phone (recommended)**
   - Use an APK extractor app (e.g. “APK Extractor” from Play Store).
   - Extract the **Intelligent Air** / `com.aircondition.smart` app.
   - Transfer the resulting `.apk` file to your PC (via USB, email, cloud, etc.).

2. **From a trusted APK repository**
   - Search for `com.aircondition.smart` on a reputable APK site.
   - Download the APK and verify it’s the correct package name.

> 🔴 Important: Make sure the APK is **exactly** `com.aircondition.smart`,  
> otherwise Frida hooks we write later won’t match.

Place the APK somewhere convenient, e.g.:

- macOS / Linux: `~/Downloads/com.aircondition.smart.apk`
- Windows: `C:\Users\<YOU>\Downloads\com.aircondition.smart.apk`

---

## 5.2 Install the APK into the Emulator

With the emulator **running** and ADB working, install the APK:

### macOS / Linux

From the folder where the APK lives, or with full path:

```
adb install com.aircondition.smart.apk
```

Or:

```
adb install ~/Downloads/com.aircondition.smart.apk
```

In PowerShell or CMD:

```
adb install C:\Users<YOU>\Downloads\com.aircondition.smart.apk
```

If the app was previously installed, you may need:

```
adb install -r com.aircondition.smart.apk
```

Expected output:
```
Performing Streamed Install
Success
```

## 5.3 Verify the Package Is Installed

Run:

```
adb shell pm list packages | grep aircondition
```

On Windows (PowerShell):

```
adb shell pm list packages | findstr aircondition
```

You should see:

```
package:com.aircondition.smart
```

---

## 5.4 (Optional) Launch the App Manually

You can start it from the emulator’s app drawer,  
or via ADB:

```
adb shell monkey -p com.aircondition.smart -c android.intent.category.LAUNCHER 1
```

You should see the app UI appear in the emulator.

---

🎉 **STEP 5 is complete when:**

- `adb install` finishes with `Success`
- `adb shell pm list packages` shows `com.aircondition.smart`
- You can open the app in the emulator

---

# ✅ STEP 6 — First Frida Hook into `com.aircondition.smart`

Goal:  
Verify that we can **inject code** into the app process and see our own log messages.

We’ll:

1. Write a tiny Frida script (`test-hook.js`)
2. Run it against `com.aircondition.smart`
3. Confirm we see output from inside the app

---

## 6.1 Create a Simple Frida Script

On your PC, create a file named:

`test-hook.js`

With this content:

```
Java.perform(function () {
    console.log("[Frida] test-hook.js loaded inside com.aircondition.smart");

    // As a smoke test, print the app's main Application class if any
    try {
        var appClass = Java.use("android.app.Application");
        console.log("[Frida] Application class found:", appClass.$className);
    } catch (e) {
        console.log("[Frida] Could not access Application:", e);
    }
});
```

This just confirms:

- Java VM is accessible

- Our code runs inside the app

## 6.2 Run the Hook with Frida (spawn the app)

Make sure:

- The emulator is running
- `frida-server` is running (`frida-ps -U` shows processes)

Then run:

```
frida -U -f com.aircondition.smart -l test-hook.js
```

Explanation:

- -U → use USB / emulator device (our emulator)

- -f com.aircondition.smart → spawn this app

- -l test-hook.js → load our script into it


## 6.3 Expected Output

If the hook is successful, your terminal should display something like:

```
[Frida] test-hook.js loaded inside com.aircondition.smart
[Frida] Application class found: android.app.Application
```

The second line may vary or may show an error — that’s fine.  
The **important part** is that the first line appears, meaning:

- The script was injected
- Java.perform() executed inside the target app
- Frida is working end-to-end

You should also see the app launching inside the emulator.

---

## 6.4 If It Fails (common issues)

### **Problem:**  

```
Failed to spawn: unable to connect to remote frida-server
```

**Fix:**  
- Ensure frida-server is running:

```
adb shell ps | grep frida
```

- If not, start it again:

```
adb shell /data/local/tmp/frida-server &
```

---

### **Problem:**  

```
Frida: Process terminated
```

**Fix:**
- Try running the command again.  
  Some OEM-based apps crash during the first spawn but succeed on the second try.

---

### **Problem:**  
```
`frida-ps -U` does not list processes
```


**Fix:**

```
adb kill-server
adb start-server
adb shell /data/local/tmp/frida-server &
frida-ps -U
```

---

Once the hook prints:

```
[Frida] test-hook.js loaded inside com.aircondition.smart
```

🎉 **STEP 6 is fully complete.**

# ✅ STEP 7 — Hook `ThingApiParams.putPostData` to Inspect Outgoing API Calls

Goal:  
See the **logical request data** the app sends to Tuya/ThingClips (before crypto/signing).  
This includes things like:

- `apiName` (e.g. `smartlife.m.user.email.password.login`)
- Keys like `email`, `passwd`, `gid`, etc.

We’ll hook `com.thingclips.smart.android.network.ThingApiParams.putPostData(...)`.

---

## 7.1 Create `hook_thingapiparams.js`

On your PC, create a file:

`hook_thingapiparams.js`

With this content:

```
Java.perform(function () {
    try {
        var ThingApiParams = Java.use("com.thingclips.smart.android.network.ThingApiParams");

        // Helper to safely get apiName
        function getApiName(obj) {
            try {
                if (obj.apiName) {
                    return obj.apiName.value;
                }
            } catch (e) {}
            return "(unknown)";
        }

        // Overload 1: (String, Object) - very common
        try {
            ThingApiParams.putPostData.overload('java.lang.String', 'java.lang.Object')
                .implementation = function (key, value) {
                    var apiName = getApiName(this);
                    console.log("[ThingApiParams.putPostData]");
                    console.log("apiName =", apiName);
                    console.log("key =", key, "value =", String(value));
                    console.log("--------------------------------------------");
                    return this.putPostData(key, value);
                };
            console.log("[Frida] Hooked ThingApiParams.putPostData(String, Object)");
        } catch (e) {
            console.log("[Frida] Could not hook putPostData(String, Object):", e);
        }

        // Overload 2: (String, JSONObject) - used by some APIs
        try {
            var JSONObject = Java.use("com.alibaba.fastjson.JSONObject");
            ThingApiParams.putPostData.overload('java.lang.String', 'com.alibaba.fastjson.JSONObject')
                .implementation = function (key, jsonObj) {
                    var apiName = getApiName(this);
                    console.log("[ThingApiParams.putPostData(JSON)]");
                    console.log("apiName =", apiName);
                    console.log("key =", key, "value(JSON) =", jsonObj.toJSONString());
                    console.log("--------------------------------------------");
                    return this.putPostData(key, jsonObj);
                };
            console.log("[Frida] Hooked ThingApiParams.putPostData(String, JSONObject)");
        } catch (e) {
            console.log("[Frida] Could not hook putPostData(String, JSONObject):", e);
        }

    } catch (e) {
        console.log("[Frida] Error setting up ThingApiParams hook:", e);
    }
});
```

This will log every key/value added to the postData for each API call.

## 7.2 Run the Hook Against `com.aircondition.smart`

With the emulator and `frida-server` running, execute:

```
frida -U -f com.aircondition.smart -l hook_thingapiparams.js
```

You should see something like:

```
[Frida] Hooked ThingApiParams.putPostData(String, Object)
[Frida] Hooked ThingApiParams.putPostData(String, JSONObject)
```

The app will launch inside the emulator.

---

## 7.3 Interact with the App (Login / Home Screen)

Now, in the emulator:

1. Open `com.aircondition.smart` (it should already be launched by Frida).
2. Perform the **login** with your usual account.
3. Wait until the app loads your “Home” / device list.

While you do this, watch the terminal where Frida is running.  
You should start seeing logs like:

```
[ThingApiParams.putPostData]
apiName = smartlife.m.user.email.password.login
key = email value = your_email@example.com
[ThingApiParams.putPostData]
apiName = smartlife.m.user.email.password.login
key = passwd value = <long encrypted string>
[ThingApiParams.putPostData]
apiName = m.life.my.group.device.list
key = gid value = 263074449
```
This confirms that:

- The hook is active in `ThingApiParams`.
- You see the **API name** (`apiName`) for each logical call.
- You see all the **keys/values** for the POST body before encryption/signing.

---

## 7.4 STEP 7 Completion Checklist

🎉  STEP 7 is **complete** when:

- `frida -U -f com.aircondition.smart -l hook_thingapiparams.js` starts without errors.
- The app opens in the emulator.
- While you log in and navigate to the main/home screen, you see lines like:
  - `apiName = smartlife.m.user.email.password.login`
  - `apiName = m.life.my.group.device.list`
- For each `apiName`, you see several `key = ... value = ...` lines.

---

# ✅ STEP 8 — Hook `fastjson.parseObject` to Dump Full JSON Responses (Device List + localKey)

Goal:  
Intercept the **decoded JSON** that the SDK parses from Tuya, especially:

- `m.life.my.group.device.list` → devices + `localKey`, `devId`, `ip`, etc.

We’ll hook `com.alibaba.fastjson.JSON.parseObject(String, Class)`.

---

## 8.1 Create `hook_fastjson.js`

Create a file on your PC:

`hook_fastjson.js`

With this content:

```
Java.perform(function () {
    try {
        var JSONcls = Java.use("com.alibaba.fastjson.JSON");

        JSONcls.parseObject.overload('java.lang.String', 'java.lang.Class')
            .implementation = function (text, clazz) {
                var clsName = "";
                try {
                    clsName = clazz.getName();
                } catch (e) {}

                // Only care about ApiResponeBean
                if (clsName === "com.thingclips.smart.android.network.bean.ApiResponeBean") {
                    try {
                        var obj = JSON.parse(text);
                        var api = obj.a;

                        // This is the one with devId + localKey
                        if (api === "m.life.my.group.device.list") {
                            console.log("==== Device list (m.life.my.group.device.list) ====");
                            (obj.result || []).forEach(function (dev) {
                                console.log(
                                    "Name:", dev.name,
                                    "| devId:", dev.devId,
                                    "| localKey:", dev.localKey
                                );
                            });
                            console.log("==================================================");
                        }
                    } catch (e) {
                        console.log("[Frida] JSON.parse error:", e);
                    }
                }

                return this.parseObject(text, clazz);
            };

        console.log("[Frida] fastjson hook for device list installed");

    } catch (e) {
        console.log("[Frida] Error hooking fastjson:", e);
    }
});
```

## 8.2 Run the Hook from Frida CLI

With the emulator and `frida-server` running, execute:

```
frida -U -f com.aircondition.smart -l hook_fastjson.js
```

You should see:

```
[Frida] Hooked fastjson.JSON.parseObject(String, Class)
```

The app will launch inside the emulator.
Log in and go to the home / device list screen as usual.

## 8.3 View the JSON Responses

In the Frida CLI output you’ll see messages like:

```
==== Device list (m.life.my.group.device.list) ====
Name: AC1 | devId: bf2bbc01412371b8942aao | localKey: ZwT(abcd][f07_Vc
Name: AC2 | devId: bf76f639f1230b420aalmo | localKey: HkDbyabcdbiqI$Yr
Name: AC3 | devId: bfa0a38a812380aa0d7a1n | localKey: !6LnGCabcdsfeQ9?
==================================================

```


## 8.5 STEP 8 Completion Checklist

STEP 8 is considered complete when:

The command:

```frida -U -f com.aircondition.smart -l hook_fastjson.js```

runs successfully and prints:

```[Frida] Hooked fastjson.JSON.parseObject(String, Class)```

And you have a complete list of your devices with the localKey ready to use :)


