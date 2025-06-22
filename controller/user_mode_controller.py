import os
import numpy as np
import pandas as pd
from PyQt6.QtWidgets import QFileDialog
from services.prediction_service import PredictionService
from services.explainability_service import ExplainabilityService
from services.summary_service import SummaryService
from services.memory_dump_service import extract_features_and_convert_to_csv
import traceback
from utils.analysis_worker import CsvAnalyzeWorker
from PyQt6.QtCore import QThread
from PyQt6.QtWidgets import QApplication, QMessageBox
from utils.memory_dump_worker import MemoryDumpWorker
from utils.csv_extract_worker import CsvExtractWorker
from utils.default_path import get_default, set_default

import ctypes
import sys
import subprocess
from utils.run_as_admin import run_as_admin
from model.malware_model import MalwareDetector

class UserModeController:
    def __init__(self, view):
        self.view = view
        self.view.setup_connections(self)

        self.model = MalwareDetector()
        self.explainer = ExplainabilityService()
        self.summarizer = SummaryService()
        self.predictor = PredictionService()

        self.data = None
        self.feature_names = []
        self.feature_data = None


    def handle_create_dump(self):
        print("🧠 Entered handle_create_dump()")

        dump_dir = get_default("dump")
        if not dump_dir or not os.path.isdir(dump_dir):
            dump_dir = QFileDialog.getExistingDirectory(self.view, "Choose dump directory")
            if not dump_dir:
                print("🚫 No directory selected for dump.")
                return
            set_default("dump", dump_dir)

        dump_path = os.path.join(dump_dir, "mem.raw")
        self.view.memory_file_path = dump_path  

        winpmem_path = "C:/winpmem/winpmem.exe"
        if not os.path.exists(winpmem_path):
            self.view.show_result(f"❌ WinPmem not found at: {winpmem_path}")
            return

        # ✅ Check if admin — if not, try elevation and exit if successful
        if not ctypes.windll.shell32.IsUserAnAdmin():
            self.view.show_result("🔒 Requesting admin permissions...")

            if run_as_admin("--create-dump", "--user-mode"):
                sys.exit()  # Exit current non-admin instance
            else:
                self.view.show_result("❌ Admin elevation failed or cancelled.")
                return

        # ✅ If already admin — continue with dump creation
        self.view.show_result("🧠 Creating memory dump... please wait...")

        self.dump_thread = QThread()
        self.dump_worker = MemoryDumpWorker(winpmem_path, dump_path)
        self.dump_worker.moveToThread(self.dump_thread)

        self.dump_thread.started.connect(self.dump_worker.run)
        self.dump_worker.progress.connect(self.on_progress_update)
        self.dump_worker.finished.connect(self.on_dump_finished)
        self.dump_worker.error.connect(lambda msg: self.view.show_result(f"<span style='color:red;'>{msg}</span>"))

        self.dump_worker.finished.connect(self.dump_thread.quit)
        self.dump_worker.finished.connect(self.dump_worker.deleteLater)
        self.dump_thread.finished.connect(self.dump_thread.deleteLater)

        self.dump_thread.start()

    def on_progress_update(self, message):
        self.view.data_display.append(message)
        self.view.data_display.repaint()
        QApplication.processEvents()
        
    def on_dump_finished(self, dump_path):
        self.view.show_result(f"✅ Memory dump created at:<br><code>{dump_path}</code>")
        QMessageBox.information(self.view, "Dump Created", f"Memory dump saved at:\n{dump_path}")

    def handle_raw_to_csv(self):
        dump_path = self._resolve_dump_path()
        csv_dir   = self._resolve_csv_dir()
        if not dump_path or not csv_dir:
            return

        self.view.show_result("🔄 Starting extraction…")

        self.csv_thread = QThread()
        self.csv_worker = CsvExtractWorker(dump_path, csv_dir)

        self.csv_worker.progress.connect(self.view.data_display.append)
        self.csv_worker.finished.connect(self.on_csv_extracted)
        self.csv_worker.error.connect(lambda msg: self.view.show_result(f"<span style='color:red;'>{msg}</span>"))

        self.csv_worker.moveToThread(self.csv_thread)
        self.csv_thread.started.connect(self.csv_worker.run)
        self.csv_worker.finished.connect(self.csv_thread.quit)
        self.csv_worker.finished.connect(self.csv_worker.deleteLater)
        self.csv_thread.finished.connect(self.csv_thread.deleteLater)
        self.csv_thread.start()

    def on_csv_extracted(self, csv_path: str):
        self.last_csv_path = csv_path           
        self.view.show_result(
            f"📑 Feature extraction completed.<br>"
            f"✅ CSV saved at:<br><code>{csv_path}</code><br><br>"
            f"You can now press <b>Analyze CSV</b>."
        )

    def _resolve_dump_path(self):
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
        # Step 1: Get last known CSV path or ask user
        csv_path = getattr(self, "last_csv_path", None)

        if not csv_path:
            default_dir = get_default("analysis")
            if default_dir:
                tentative_path = os.path.join(default_dir, "output.csv")
                if os.path.isfile(tentative_path):
                    csv_path = tentative_path

        if not csv_path or not os.path.isfile(csv_path):
            csv_path, _ = QFileDialog.getOpenFileName(
                self.view, "Select CSV", get_default("analysis"), "CSV Files (*.csv)"
            )
            if not csv_path:
                return

        self.view.show_result("🔄 Starting analysis…")
        print(f"📂 Analyzing file: {csv_path}")

        try:
            self.data = pd.read_csv(csv_path)
            print("✅ CSV loaded.")

            # Step 2: Drop metadata and keep numeric features
            df = self.data.drop(columns=["filename", "sample_id", "label", "mem.name_extn"], errors="ignore")
            df = df.select_dtypes(include=[float, int])

            self.feature_names = list(df.columns)
            formatted_data = "\n\n".join([
                f"Dump file {i+1}:\n" + ", ".join(map(str, row))
                for i, row in df.iterrows()
            ])
            print("📄 Data formatted.")

            # Step 3: Predict
            probabilities, binary_preds, labels, features_df = self.model.predict(df)
            print("🔮 Prediction complete.")

            # Step 4: Summary
            benign_count = (binary_preds == 0).sum()
            malicious_count = (binary_preds == 1).sum()
            total_count = len(binary_preds)
            status = "Potential Malware Detected" if malicious_count > 0 else "Device Clean"

            # Step 5: Add clickable SHAP message
            explanation_link_html = """
            <a href="#" style="color: white; text-decoration: none; font-size: 18px;">
                🔍 View explanation
            </a>
            """

            summary_html = self.summarizer.generate_summary(
                total_count, benign_count, malicious_count, status,
                explanation_link=explanation_link_html
            )

            self.view.data_display.setHtml(summary_html)

            # Step 6: SHAP explanations
            self.explainer.initialize_explainer(self.model.model, features_df, self.model.selected_features)
            for idx in (binary_preds == 1).nonzero()[0]:
                sample = features_df.iloc[idx]
                shap_text = self.explainer.generate_explanation_for_sample(features_df, sample, idx)
                self.view.append_shap_explanation(idx + 1, shap_text)

            # Step 7: Update UI
            self.view.analysis_widget.setVisible(True)
            self.view.instructions.setVisible(False)
            self.view.create_dump_button.setVisible(False)
            self.view.extract_csv_button.setVisible(False)
            self.view.upload_csv_button.setVisible(False)

            for arrow in self.view.arrow_labels:
                arrow.setVisible(False)

            print("✅ Analysis done.")

        except Exception as e:
            print(f"❌ Error during analysis: {e}")
            self.view.data_display.setText(f"<span style='color:red;'>❌ Error: {e}</span>")
        
