from PyQt6.QtCore import QObject, pyqtSignal
import subprocess
import os
import ctypes

class MemoryDumpWorker(QObject):
    finished = pyqtSignal(str)
    error = pyqtSignal(str)
    progress = pyqtSignal(str)

    def __init__(self, winpmem_path, dump_path):
        super().__init__()
        self.winpmem_path = winpmem_path
        self.dump_path = dump_path

    def run(self):
        try:
            self.progress.emit("🧠 Checking WinPmem path...")
            if not os.path.exists(self.winpmem_path):
                self.error.emit(f"❌ WinPmem not found at: {self.winpmem_path}")
                return

            self.progress.emit("🔐 Checking admin privileges...")
            if not ctypes.windll.shell32.IsUserAnAdmin():
                self.error.emit("🔒 Not running as administrator.")
                return

            self.progress.emit("⏳ Creating memory dump...")

            process = subprocess.Popen(
                [self.winpmem_path, self.dump_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )

            for line in process.stdout:
                line = line.strip()
                if line:
                    self.progress.emit(f"📈 {line}")

            process.stdout.close()
            return_code = process.wait()

            if return_code in [0, 1] and os.path.exists(self.dump_path) and os.path.getsize(self.dump_path) > 100 * 1024 * 1024:
                self.progress.emit("✅ Dump created successfully.")
                self.finished.emit(self.dump_path)
            else:
                self.error.emit("❌ Dump creation failed or file too small.")

        except Exception as e:
            self.error.emit(f"❌ Unexpected error: {e}")
