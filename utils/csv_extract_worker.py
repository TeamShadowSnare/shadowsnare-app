"""
CSV extraction worker (Qt-friendly, runs off the UI thread).

Takes a memory dump path and an output directory, calls the extraction service
to produce <csv_dir>/output.csv, and reports progress/status via Qt signals.
"""


from PyQt6.QtCore import QObject, pyqtSignal
import traceback
from services.memory_dump_service import extract_features_and_convert_to_csv

class CsvExtractWorker(QObject):
    """
    Background worker that runs memory-dump → features CSV extraction.

    Signals
    -------
    progress : str
        Streaming log messages for the UI.
    finished : str
        Emitted with the CSV file path when extraction completes.
    error : str
        Emitted with an error message on failure.
    """
    progress = pyqtSignal(str)
    finished = pyqtSignal(str)
    error    = pyqtSignal(str)

    def __init__(self, dump_path: str, csv_dir: str):
        """
        Parameters
        ----------
        dump_path : str
            Path to the memory dump file (.raw/.vmem/.mem).
        csv_dir : str
            Directory where the resulting CSV will be written.
        """
        super().__init__()
        self.dump_path = dump_path
        self.csv_dir   = csv_dir

    def run(self):
        """Entry point to be invoked from a QThread: performs the extraction."""
        try:
            def _log(msg):
                print(msg)
                self.progress.emit(msg)

            _log("📥 Extracting features from memory dump…")
            # Perform the actual extraction; returns "<csv_dir>/output.csv"
            csv_path = extract_features_and_convert_to_csv(
                self.dump_path, self.csv_dir, progress_callback=_log
            )
            _log("✅ CSV extraction complete.")
            # Notify listeners with the output path
            self.finished.emit(csv_path)

        except Exception as e:
            # Keep stack trace for developers; emit a user-facing error string
            traceback.print_exc()
            self.error.emit(str(e))
