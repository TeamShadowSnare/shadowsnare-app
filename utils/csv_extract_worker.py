from PyQt6.QtCore import QObject, pyqtSignal
import traceback
from services.memory_dump_service import extract_features_and_convert_to_csv

class CsvExtractWorker(QObject):
    progress = pyqtSignal(str)
    finished = pyqtSignal(str)
    error    = pyqtSignal(str)

    def __init__(self, dump_path: str, csv_dir: str):
        super().__init__()
        self.dump_path = dump_path
        self.csv_dir   = csv_dir

    def run(self):
        try:
            def _log(msg):
                print(msg)
                self.progress.emit(msg)

            _log("📥 Extracting features from memory dump…")
            csv_path = extract_features_and_convert_to_csv(
                self.dump_path, self.csv_dir, progress_callback=_log
            )
            _log("✅ CSV extraction complete.")
            self.finished.emit(csv_path)

        except Exception as e:
            traceback.print_exc()
            self.error.emit(str(e))
