import sys
import os
import ctypes

def run_as_admin(extra_arg=None):
    print("⚙️ Elevating to admin...")  # Debug print

    if ctypes.windll.shell32.IsUserAnAdmin():
        print("✅ Already running as admin")
        return True

    script = os.path.abspath(sys.argv[0])
    args = sys.argv[1:]

    if extra_arg:
        args.append(extra_arg)

    params = ' '.join([f'"{arg}"' for arg in args])
    print(f"🔁 Relaunching with: {sys.executable} {script} {params}")

    try:
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, f'"{script}" {params}', None, 1
        )
        print("✅ Relaunch initiated")
        return False
    except Exception as e:
        print(f"❌ Failed to elevate: {e}")
        return False
