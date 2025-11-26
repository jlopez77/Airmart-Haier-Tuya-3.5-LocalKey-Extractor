# extract_localkeys.py
# Orchestrates adb + frida + hook script to extract Tuya 3.5 localKey

import os
import time
from adb_helpers import wait_for_device, push_frida_server, start_frida_server, launch_app
from frida_launcher import inject

PACKAGE = "com.aircondition.smart"   # Change if needed
SCRIPT = os.path.join(os.path.dirname(__file__), "frida", "hook_localkeys.js")

def main():
    print("=== Tuya 3.5 LocalKey Extractor ===\n")

    wait_for_device()

    # Ensure frida-server is on the emulator
    push_frida_server()

    # Start frida-server
    start_frida_server()

    # Launch the Airmart/Haier app
    launch_app(PACKAGE)

    # Inject Frida script and print keys
    inject(PACKAGE, SCRIPT)

if __name__ == "__main__":
    main()
