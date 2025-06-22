import sys
import os
import ctypes

def run_as_admin(*extra_args):
    print("⚙️ Elevating to admin...")

    if ctypes.windll.shell32.IsUserAnAdmin():
        print("✅ Already running as admin")
        return False

    script = os.path.abspath(sys.argv[0])
    args = sys.argv[1:]
    args.extend(extra_args)

    params = ' '.join([f'"{arg}"' for arg in args])
    print(f"🔁 Relaunching with: {sys.executable} {script} {params}")

    try:
        SW_HIDE = 0
        ctypes.windll.shell32.ShellExecuteW(
            None,
            "runas",
            sys.executable,
            f'"{script}" {params}',
            None,
            SW_HIDE
        )
        print("✅ Relaunch initiated (no CMD)")
        return True
    except Exception as e:
        print(f"❌ Failed to elevate: {e}")
        return False

