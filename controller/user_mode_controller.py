"""
User Mode controller.

Coordinates the end-user flow:
1) Create memory dump (WinPmem) → 2) Extract features to CSV (Volatility3) → 3) Analyze CSV with the ML model,
plus SHAP explainability and a friendly HTML summary.

Notes
-----
- Long-running tasks (dump creation, CSV extraction) are run in QThreads via worker objects to keep the UI responsive.
- Default directories are persisted with QSettings (see utils.default_path.get_default/set_default).
- Requires Administrator privileges for memory dump creation on Windows.
"""


import os
import pandas as pd
from PyQt6.QtWidgets import QFileDialog
from services.prediction_service import PredictionService
from services.explainability_service import ExplainabilityService
from services.summary_service import SummaryService
from PyQt6.QtCore import QThread
from PyQt6.QtWidgets import QApplication, QMessageBox
from utils.memory_dump_worker import MemoryDumpWorker
from utils.csv_extract_worker import CsvExtractWorker
from utils.default_path import get_default, set_default

import ctypes
import sys
from model.malware_model import MalwareDetector

class UserModeController:
    """Controller bound to `view.user_mode_view.UserMode` (User Mode tab)."""
    def __init__(self, view):
        """
        Parameters
        ----------
        view : UserMode
            The view exposing:
            - setup_connections(self)
            - data_display (QTextBrowser), analysis_widget, instructions
            - create_dump_button, extract_csv_button, upload_csv_button
            - arrow_labels (for hiding the arrows after analysis)
            - append_shap_explanation(process_index, text)
        """
        self.view = view
        self.view.setup_connections(self) # connect buttons → handlers
        
        # Core components/services
        self.model = MalwareDetector() # Keras model + selected_features
        self.explainer = ExplainabilityService() # SHAP wrapper
        self.summarizer = SummaryService() # HTML summary templating
        self.predictor = PredictionService() # (not used in this path; kept for parity)

        # Controller state
        self.data = None
        self.feature_names = []
        self.feature_data = None


    def handle_create_dump(self):
        """
        Create a memory dump using WinPmem in a background thread.

        Flow
        ----
        1) Resolve/ask for a dump directory (persist via QSettings).
        2) Validate WinPmem path and administrator privileges.
        3) Spin up QThread + MemoryDumpWorker(winpmem_path, dump_path).
        4) Stream progress to the UI; on finish, show a success dialog.
        """
        print("🧠 Entered handle_create_dump()")

        # Resolve default dump directory or ask the user
        dump_dir = get_default("dump")
        if not dump_dir or not os.path.isdir(dump_dir):
            dump_dir = QFileDialog.getExistingDirectory(self.view, "Choose dump directory")
            if not dump_dir:
                print("🚫 No directory selected for dump.")
                return
            set_default("dump", dump_dir)

        # Where to write the dump file
        dump_path = os.path.join(dump_dir, "mem.raw")
        self.view.memory_file_path = dump_path  

        # WinPmem binary location (expected path in the onboarding guide)
        winpmem_path = "C:/winpmem/winpmem.exe"
        if not os.path.exists(winpmem_path):
            self.view.show_result(f"❌ WinPmem not found at: {winpmem_path}")
            return
        
        
        if not ctypes.windll.shell32.IsUserAnAdmin():
            self.view.show_result(
                "❌ Administrator privileges are required to create a memory dump.<br>"
                "Please close ShadowSnare and run it via <b>Right-click → Run as administrator</b>."
            )
            return

        # UI feedback before starting the background job
        self.view.show_result("🧠 Creating memory dump... please wait...")

        # Offload the dump creation to a worker in its own thread to keep UI responsive
        self.dump_thread = QThread()
        self.dump_worker = MemoryDumpWorker(winpmem_path, dump_path)
        self.dump_worker.moveToThread(self.dump_thread)

        # Connect thread lifecycle + worker signals
        self.dump_thread.started.connect(self.dump_worker.run)
        self.dump_worker.progress.connect(self.on_progress_update)
        self.dump_worker.finished.connect(self.on_dump_finished)
        self.dump_worker.error.connect(lambda msg: self.view.show_result(f"<span style='color:red;'>{msg}</span>"))

        # Ensure proper cleanup (quit thread → delete worker → delete thread)
        self.dump_worker.finished.connect(self.dump_thread.quit)
        self.dump_worker.finished.connect(self.dump_worker.deleteLater)
        self.dump_thread.finished.connect(self.dump_thread.deleteLater)

        # Start Thread
        self.dump_thread.start()

    def on_progress_update(self, message):
        """Append streaming log/progress lines from workers to the right-side text area."""
        self.view.data_display.append(message)
        self.view.data_display.repaint()
        QApplication.processEvents()
        
    def on_dump_finished(self, dump_path):
        """Show success message when the dump worker completes."""
        self.view.show_result(f"✅ Memory dump created at:<br><code>{dump_path}</code>")
        QMessageBox.information(self.view, "Dump Created", f"Memory dump saved at:\n{dump_path}")

    def handle_raw_to_csv(self):
        """
        Convert a memory dump to a feature CSV (Volatility3) in the background.

        Steps
        -----
        - Resolve dump path (ask user if needed).
        - Resolve output CSV directory (ask user if needed).
        - Run CsvExtractWorker on a QThread; stream progress; show path on finish.
        """
        dump_path = self._resolve_dump_path()
        csv_dir   = self._resolve_csv_dir()
        if not dump_path or not csv_dir:
            return

        self.view.show_result("🔄 Starting extraction…")

        # Background thread for feature extraction
        self.csv_thread = QThread()
        self.csv_worker = CsvExtractWorker(dump_path, csv_dir)

        # Stream progress and handle completion/errors
        self.csv_worker.progress.connect(self.view.data_display.append)
        self.csv_worker.finished.connect(self.on_csv_extracted)
        self.csv_worker.error.connect(lambda msg: self.view.show_result(f"<span style='color:red;'>{msg}</span>"))

        # Thread lifecycle wiring
        self.csv_worker.moveToThread(self.csv_thread)
        self.csv_thread.started.connect(self.csv_worker.run)
        self.csv_worker.finished.connect(self.csv_thread.quit)
        self.csv_worker.finished.connect(self.csv_worker.deleteLater)
        self.csv_thread.finished.connect(self.csv_thread.deleteLater)
        self.csv_thread.start()

    def on_csv_extracted(self, csv_path: str):
        """Record last CSV path and guide the user to the 'Analyze CSV' step."""
        self.last_csv_path = csv_path           
        self.view.show_result(
            f"📑 Feature extraction completed.<br>"
            f"✅ CSV saved at:<br><code>{csv_path}</code><br><br>"
            f"You can now press <b>Analyze CSV</b>."
        )

    def _resolve_dump_path(self):
        """
        Find a valid dump path to use:
        - Prefer the path stored in the view.
        - Otherwise open a file picker (filters *.raw, *.vmem).
        Persists the chosen folder as the default 'dump' directory.
        """
        dump_path = self.view.memory_file_path
        if not dump_path or not os.path.isfile(dump_path):
            dump_path, _ = QFileDialog.getOpenFileName(
                self.view, "Select dump file",
                get_default("dump"), "Raw files (*.raw *.vmem)"
            )
            if not dump_path:
                return None
            set_default("dump", os.path.dirname(dump_path))
            self.view.memory_file_path = dump_path
        return dump_path


    def _resolve_csv_dir(self):
        """
        Find a directory to save the CSV:
        - Prefer default 'csv' directory.
        - Otherwise ask the user and persist the choice.
        """
        csv_dir = get_default("csv")
        if not csv_dir or not os.path.isdir(csv_dir):
            csv_dir = QFileDialog.getExistingDirectory(
                self.view, "Choose CSV directory"
            )
            if not csv_dir:
                return None
            set_default("csv", csv_dir)
        return csv_dir


    def handle_analyze_csv(self): 
        """
        Analyze a features CSV with the ML model, summarize, and show SHAP.

        Behavior
        --------
        - Try last exported CSV; otherwise look in default 'analysis' dir for output.csv;
          otherwise prompt the user.
        - Load CSV, keep only numeric columns (drop known metadata if present).
        - Predict with MalwareDetector; compute counts/status and render summary HTML
          including a "View explanation" link (opens SHAP popup).
        - Initialize SHAP and append explanations for malicious rows.
        - Hide the initial step UI and show the analysis area.
        """   
        
        # Prefer the CSV we just created (if any)
        csv_path = getattr(self, "last_csv_path", None)

        # Else, try default analysis dir / output.csv
        if not csv_path:
            default_dir = get_default("analysis")
            if default_dir:
                tentative_path = os.path.join(default_dir, "output.csv")
                if os.path.isfile(tentative_path):
                    csv_path = tentative_path

        # Else, ask the user
        if not csv_path or not os.path.isfile(csv_path):
            csv_path, _ = QFileDialog.getOpenFileName(
                self.view, "Select CSV", get_default("analysis"), "CSV Files (*.csv)"
            )
            if not csv_path:
                return

        self.view.show_result("🔄 Starting analysis…")
        print(f"📂 Analyzing file: {csv_path}")

        try:
            # Load CSV then drop non-numeric/metadata columns if present
            self.data = pd.read_csv(csv_path)
            print("✅ CSV loaded.")
            df = self.data.drop(columns=["filename", "sample_id", "label", "mem.name_extn"], errors="ignore")
            df = df.select_dtypes(include=[float, int]) # ensure numeric only for the model

            # Keep feature names for any downstream display (optional)
            self.feature_names = list(df.columns)
            formatted_data = "\n\n".join([
                f"Dump file {i+1}:\n" + ", ".join(map(str, row))
                for i, row in df.iterrows()
            ])
            print("📄 Data formatted.")

            # Run the model
            probabilities, binary_preds, labels, features_df = self.model.predict(df)
            print("🔮 Prediction complete.")

            # Aggregate results
            benign_count = (binary_preds == 0).sum()
            malicious_count = (binary_preds == 1).sum()
            total_count = len(binary_preds)
            status = "Potential Malware Detected" if malicious_count > 0 else "Device Clean"

            # Clickable link that the view routes to the popup
            explanation_link_html = """
            <a href="#" style="color: white; text-decoration: none; font-size: 18px;">
                🔍 View explanation
            </a>
            """

            # Render the summary
            summary_html = self.summarizer.generate_summary(
                total_count, benign_count, malicious_count, status,
                explanation_link=explanation_link_html
            )

            self.view.data_display.setHtml(summary_html)

            # Initialize SHAP explainer with the correct feature order
            self.explainer.initialize_explainer(self.model.model, features_df, self.model.selected_features)
            
            # Append SHAP text only for items predicted as malicious
            for idx in (binary_preds == 1).nonzero()[0]:
                sample = features_df.iloc[idx]
                shap_text = self.explainer.generate_explanation_for_sample(features_df, sample, idx)
                self.view.append_shap_explanation(idx + 1, shap_text)

            # Reveal analysis area and hide the step UI
            self.view.analysis_widget.setVisible(True)
            self.view.instructions.setVisible(False)
            self.view.create_dump_button.setVisible(False)
            self.view.extract_csv_button.setVisible(False)
            self.view.upload_csv_button.setVisible(False)

            for arrow in self.view.arrow_labels:
                arrow.setVisible(False)

            print("✅ Analysis done.")

        except Exception as e:
            # Surface the exception in the UI; keep console log for debugging
            print(f"❌ Error during analysis: {e}")
            self.view.data_display.setText(f"<span style='color:red;'>❌ Error: {e}</span>")
        
