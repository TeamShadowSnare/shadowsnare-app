"""
Memory dump worker (Qt-friendly background task).

Runs WinPmem to create a physical memory dump and streams progress back to the UI.
Emits:
- finished(str): absolute path to the created dump file on success
- error(str): error message on failure
- progress(str): textual status/progress updates
"""


from PyQt6.QtCore import QObject, pyqtSignal
import subprocess
import os
import ctypes

class MemoryDumpWorker(QObject):
    """Worker that invokes WinPmem to create a memory dump file."""
    finished = pyqtSignal(str)
    error = pyqtSignal(str)
    progress = pyqtSignal(str)

    def __init__(self, winpmem_path, dump_path):
        """
        Parameters
        ----------
        winpmem_path : str
            Path to the WinPmem executable (e.g., C:/winpmem/winpmem.exe).
        dump_path : str
            Target path for the memory dump file (e.g., C:/dumps/mem.raw).
        """
        super().__init__()
        self.winpmem_path = winpmem_path
        self.dump_path = dump_path

    def run(self):
        """Main worker entry: validates prerequisites, runs WinPmem, streams output, and reports result."""
        try:
            # 1) Validate the WinPmem executable exists
            self.progress.emit("🧠 Checking WinPmem path...")
            if not os.path.exists(self.winpmem_path):
                self.error.emit(f"❌ WinPmem not found at: {self.winpmem_path}")
                return

            # 2) Ensure the process is elevated (required for raw memory access)
            self.progress.emit("🔐 Checking admin privileges...")
            if not ctypes.windll.shell32.IsUserAnAdmin():
                self.error.emit("🔒 Not running as administrator.")
                return

            # 3) Launch WinPmem and stream its stdout to the UI
            self.progress.emit("⏳ Creating memory dump...")

            process = subprocess.Popen(
                [self.winpmem_path, self.dump_path],  # WinPmem CLI: winpmem.exe <output_path>
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )

            # Read lines as they are produced and forward them to the UI
            for line in process.stdout:
                line = line.strip()
                if line:
                    self.progress.emit(f"📈 {line}")

            # Finalize process and capture return code
            process.stdout.close()
            return_code = process.wait()

            # 4) Consider return codes 0/1 acceptable and verify file was created with a sane size (>100MB)
            if return_code in [0, 1] and os.path.exists(self.dump_path) and os.path.getsize(self.dump_path) > 100 * 1024 * 1024:
                self.progress.emit("✅ Dump created successfully.")
                self.finished.emit(self.dump_path)
            else:
                self.error.emit("❌ Dump creation failed or file too small.")

        except Exception as e:
            # Catch-all to avoid crashing the worker thread; report back to UI
            self.error.emit(f"❌ Unexpected error: {e}")
