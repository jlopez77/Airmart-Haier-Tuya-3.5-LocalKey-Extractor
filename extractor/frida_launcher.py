# frida_launcher.py
# Helper for injecting Frida scripts into the emulator

import os
import subprocess

def inject(package, script_path):
    """
    Launch frida with the given script and attach to the specified package.
    Blocks until user closes frida session.
    """
    if not os.path.exists(script_path):
        raise RuntimeError(f"Script not found: {script_path}")

    cmd = f'frida -U -f {package} -l "{script_path}"'
    print(f"Injecting Frida script into {package}…")
    print("⚡ Use the app normally now. LocalKeys will appear here.\n")

    os.system(cmd)
