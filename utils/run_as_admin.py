import sys
import os
import ctypes

# def run_as_admin(extra_arg=None):
#     print("⚙️ Elevating to admin...")  # Debug print

#     if ctypes.windll.shell32.IsUserAnAdmin():
#         print("✅ Already running as admin")
#         return True

#     script = os.path.abspath(sys.argv[0])
#     args = sys.argv[1:]

#     if extra_arg:
#         args.append(extra_arg)

#     params = ' '.join([f'"{arg}"' for arg in args])
#     print(f"🔁 Relaunching with: {sys.executable} {script} {params}")

#     try:
#         ctypes.windll.shell32.ShellExecuteW(
#             None, "runas", sys.executable, f'"{script}" {params}', None, 1
#         )
#         print("✅ Relaunch initiated")
#         return False
#     except Exception as e:
#         print(f"❌ Failed to elevate: {e}")
#         return False



# def run_as_admin(extra_arg=None):
#     print("⚙️ Elevating to admin...")

#     if ctypes.windll.shell32.IsUserAnAdmin():
#         print("✅ Already running as admin")
#         return False  # Don't relaunch if already admin

#     script = os.path.abspath(sys.argv[0])
#     args = sys.argv[1:]

#     if extra_arg:
#         args.append(extra_arg)

#     params = ' '.join([f'"{arg}"' for arg in args])
#     print(f"🔁 Relaunching with: {sys.executable} {script} {params}")

#     try:
#         ctypes.windll.shell32.ShellExecuteW(
#             None, "runas", sys.executable, f'"{script}" {params}', None, 1
#         )
#         print("✅ Relaunch initiated")
#         return True  # Relaunch happened
#     except Exception as e:
#         print(f"❌ Failed to elevate: {e}")
#         return False




# def run_as_admin(*extra_args):
#     print("⚙️ Elevating to admin...")

#     if ctypes.windll.shell32.IsUserAnAdmin():
#         print("✅ Already running as admin")
#         return False

#     script = os.path.abspath(sys.argv[0])
#     args = sys.argv[1:]

#     if extra_args:
#         args.extend(extra_args)

#     params = ' '.join([f'"{arg}"' for arg in args])
#     print(f"🔁 Relaunching with: {sys.executable} {script} {params}")

#     try:
#         ctypes.windll.shell32.ShellExecuteW(
#             None, "runas", sys.executable, f'"{script}" {params}', None, 1
#         )
#         print("✅ Relaunch initiated")
#         return True
#     except Exception as e:
#         print(f"❌ Failed to elevate: {e}")
#         return False


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
        SW_HIDE = 0  # 🔇 Hides the console window
        ctypes.windll.shell32.ShellExecuteW(
            None,
            "runas",
            sys.executable,
            f'"{script}" {params}',
            None,
            SW_HIDE  # ✅ This prevents the new CMD window
        )
        print("✅ Relaunch initiated (no CMD)")
        return True
    except Exception as e:
        print(f"❌ Failed to elevate: {e}")
        return False

