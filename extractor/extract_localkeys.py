# extract_localkeys.py

import subprocess
import time
import os

SCRIPT = os.path.join(os.path.dirname(__file__), "frida", "hook_localkeys.js")

def run(cmd):
    return subprocess.check_output(cmd, shell=True, text=True)

def main():
    print("🔄 Restarting frida-server in emulator...")
    run("adb shell pkill frida-server || true")
    run("adb shell /data/local/tmp/frida-server &")
    time.sleep(1)

    print("📱 Launching the target app...")
    run("adb shell monkey -p com.aircondition.smart -c android.intent.category.LAUNCHER 1")
    time.sleep(2)

    print("🧪 Injecting Frida script...\n")

    cmd = f"frida -U -f com.aircondition.smart -l {SCRIPT}"
    print("⚡ Now *use the app normally* to trigger LocalKey loading...\n")
    os.system(cmd)

if __name__ == "__main__":
    main()
