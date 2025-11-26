# adb_helpers.py
# Small convenience wrappers around adb commands

import subprocess
import time

def run(cmd):
    """Run shell command and return output as string."""
    return subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.STDOUT)

def adb(cmd):
    """Run an adb command."""
    return run(f"adb {cmd}")

def wait_for_device(timeout=30):
    print("Waiting for emulator/device...")
    for _ in range(timeout):
        try:
            adb("get-state")
            print("Device detected.")
            return True
        except:
            time.sleep(1)
    raise RuntimeError("No adb device detected.")

def push_frida_server(local_path="/data/local/tmp/frida-server"):
    print("Pushing frida-server to emulator...")
    adb(f"push frida-server {local_path}")
    adb(f"shell chmod 755 {local_path}")

def start_frida_server(local_path="/data/local/tmp/frida-server"):
    print("Starting frida-server...")
    # kill any previous instance
    adb("shell pkill frida-server || true")
    time.sleep(0.5)
    adb(f"shell '{local_path} &'")
    time.sleep(1)
    print("frida-server started.")

def launch_app(package_name):
    print(f"Launching {package_name}…")
    adb(f"shell monkey -p {package_name} -c android.intent.category.LAUNCHER 1")
    time.sleep(2)
