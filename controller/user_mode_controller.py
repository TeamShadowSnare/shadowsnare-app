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

#     def handle_upload_memory_file(self):
#         file_path, _ = QFileDialog.getOpenFileName(
#             self.view, "Select memory dump file", "", "Memory Files (*.raw *.vmem)"
#         )
#         if file_path and (file_path.endswith(".raw") or file_path.endswith(".vmem")):
#             self.view.memory_file_path = file_path
#             self.view.try_enable_run_button()
#         else:
#             self.view.data_display.setHtml("<span style='color:red;'>❌ Invalid file. Please select a .raw or .vmem file.</span>")

#     def handle_choose_output_directory(self):
#         directory = QFileDialog.getExistingDirectory(
#             self.view, "Select directory to save CSV"
#         )
#         if directory:
#             self.view.output_directory = directory
#             self.view.try_enable_run_button()


#     # def handle_run_analysis(self):
#     #     memory_path = self.view.memory_file_path
#     #     output_dir = self.view.output_directory
#     #     if not memory_path or not output_dir:
#     #         self.view.show_result("❌ Please upload a memory file and select output directory.")
#     #         return
#     #     try:
#     #         print("HOWWDY FELLAS!!!")
#     #         # Step 1: Extract features and convert to CSV
#     #         csv_path = extract_features_and_convert_to_csv(memory_path, output_dir)
#     #         # Step 2: Load CSV
#     #         df, feature_names = self.predictor.load_csv(csv_path)
#     #         # Step 3: Keep only numeric columns (drop sample_id, file name, etc.)
#     #         numeric_df = df.select_dtypes(include=[float, int])
#     #         self.feature_names = list(numeric_df.columns)
#     #         self.feature_data = numeric_df.values
#     #         print(f"[DEBUG]: feature_data = {self.feature_data}")
            
#     #         # Step 4: Predict using the model (scaling happens inside)
#     #         probabilities, binary_preds, labels, used_features = self.predictor.predict(df)
#     #         print("Type of used_features:", type(used_features))
            
#     #         # Fix: Handle DataFrame properly
#     #         if isinstance(used_features, pd.DataFrame):
#     #             print("DataFrame shape:", used_features.shape)
#     #             print("First row shape:", used_features.iloc[0].shape)
#     #             # Convert to numpy array for easier indexing later
#     #             used_features_array = used_features.values
#     #         else:
#     #             # If it's already an array
#     #             used_features_array = used_features
#     #             print("Array shape:", used_features_array.shape)
            
#     #         # Step 5: Summary
#     #         benign_count = np.count_nonzero(binary_preds == 0)
#     #         malicious_count = np.count_nonzero(binary_preds == 1)
#     #         total_count = len(binary_preds)
#     #         status = "✅ Clean" if malicious_count == 0 else "⚠️ Potential Malware Detected"
#     #         summary_html = self.summarizer.generate_summary(
#     #             total_count, benign_count, malicious_count, status
#     #         )
#     #         self.view.show_result(
#     #             f"<b>✅ Memory file:</b> {memory_path}<br><b>📁 CSV saved at:</b> {csv_path}<br><br>{summary_html}<br><br><a href='#'>Click here for explanation</a>"
#     #         )
            
#     #         # Step 6: SHAP explanations
#     #         # Step 6: SHAP explanations
#     #         self.view.explanation_text_edit.clear()
#     #         self.explainer = ExplainabilityService()

#     #         # Use the feature names from the model's selected features, not from numeric_df
#     #         model_feature_names = self.predictor.model.selected_features

#     #         self.explainer.initialize_explainer(
#     #             model=self.predictor.model,  # Pass the MalwareDetector object
#     #             X_train=used_features,  # This should be a DataFrame
#     #             feature_names=model_feature_names  # Use model's feature names
#     #         )

#     #         for idx in np.where(binary_preds == 1)[0]:
#     #             # Get the row as a pandas Series for proper handling
#     #             sample = used_features.iloc[idx]
#     #             shap_text = self.explainer.generate_explanation_for_sample(used_features, sample, idx)
#     #             # self.view.append_shap_explanation(idx + 1, shap_text)
                
#     #     except Exception as e:
#     #         print(f"[DEBUG]: {e}")
#     #         traceback.print_exc()
#     #         self.view.show_result(f"<span style='color:red;'>❌ Error during analysis: {e}</span>")


#     def handle_run_analysis(self):
#         memory_path = self.view.memory_file_path
#         output_dir = self.view.output_directory

#         if not memory_path or not output_dir:
#             self.view.show_result("❌ Please upload a memory file and select output directory.")
#             return
#         # ORTAL

#         # try:
#         #     print("HOWWDY FELLAS!!!")
#         #     # Step 1: Extract features and convert to CSV
#         #     csv_path = extract_features_and_convert_to_csv(memory_path, output_dir)
#         #     # Step 2: Load CSV
#         #     df, feature_names = self.predictor.load_csv(csv_path)
#         #     # Step 3: Keep only numeric columns (drop sample_id, file name, etc.)
#         #     numeric_df = df.select_dtypes(include=[float, int])
#         #     self.feature_names = list(numeric_df.columns)
#         #     self.feature_data = numeric_df.values
#         #     print(f"[DEBUG]: feature_data = {self.feature_data}")
            
#         #     # Step 4: Predict using the model (scaling happens inside)
#         #     probabilities, binary_preds, labels, used_features = self.predictor.predict(df)
#         #     print("Type of used_features:", type(used_features))
            
#         #     # Fix: Handle DataFrame properly
#         #     if isinstance(used_features, pd.DataFrame):
#         #         print("DataFrame shape:", used_features.shape)
#         #         print("First row shape:", used_features.iloc[0].shape)
#         #         # Convert to numpy array for easier indexing later
#         #         used_features_array = used_features.values
#         #     else:
#         #         # If it's already an array
#         #         used_features_array = used_features
#         #         print("Array shape:", used_features_array.shape)
            
#         #     # Step 5: Summary
#         #     benign_count = np.count_nonzero(binary_preds == 0)
#         #     malicious_count = np.count_nonzero(binary_preds == 1)
#         #     total_count = len(binary_preds)
#         #     status = "✅ Clean" if malicious_count == 0 else "⚠️ Potential Malware Detected"
#         #     summary_html = self.summarizer.generate_summary(
#         #         total_count, benign_count, malicious_count, status
#         #     )
#         #     self.view.show_result(
#         #         f"<b>✅ Memory file:</b> {memory_path}<br><b>📁 CSV saved at:</b> {csv_path}<br><br>{summary_html}<br><br><a href='#'>Click here for explanation</a>"
#         #     )
            
#         #     # Step 6: SHAP explanations
#         #     self.view.explanation_text_edit.clear()
#         #     self.explainer = ExplainabilityService()

#         self.view.show_result("🔄 Analyzing memory dump... please wait...")

#         self.thread = QThread()
#         self.worker = AnalysisWorker(memory_path, output_dir, self.predictor, self.summarizer)
#         self.worker.progress.connect(self.on_progress_update)
#         self.worker.moveToThread(self.thread)

#         self.thread.started.connect(self.worker.run)
#         self.worker.finished.connect(self.on_analysis_finished)
#         self.worker.error.connect(self.on_analysis_error)

#         self.worker.finished.connect(self.thread.quit)
#         self.worker.finished.connect(self.worker.deleteLater)
#         self.thread.finished.connect(self.thread.deleteLater)

#         self.thread.start()
        
#     def on_progress_update(self, message):
#         self.view.data_display.append(message)
#         self.view.data_display.repaint()
#         QApplication.processEvents()

#     def on_analysis_finished(self, summary_html, explanation_text):
#         self.view.show_result(summary_html)
#         self.view.explanation_text_edit.setPlainText(explanation_text)

#     def on_analysis_error(self, message):
#         self.view.show_result(f"<span style='color:red;'>❌ Error during analysis: {message}</span>")
























        #     self.explainer.initialize_explainer(
        #         model=self.predictor.model,  # Pass the MalwareDetector object
        #         X_train=used_features,  # This should be a DataFrame
        #         feature_names=model_feature_names  # Use model's feature names
        #     )
        # #     model=self.predictor.model.model,  # ✅ Keras model only
        # #     X_train=used_features,             # ✅ DataFrame of input features
        # #     feature_names=self.predictor.model.selected_features  # ✅ Column names
        # # )

        #     for idx in np.where(binary_preds == 1)[0]:
        #         # Get the row as a pandas Series for proper handling
        #         sample = used_features.iloc[idx]
        #         shap_text = self.explainer.generate_explanation_for_sample(used_features, sample, idx)
        #         self.view.append_shap_explanation(idx + 1, shap_text)
        #     self.view.show_explanation_popup()

        # except Exception as e:
        #     print(f"[DEBUG]: {e}")
        #     traceback.print_exc()
        #     self.view.show_result(f"<span style='color:red;'>❌ Error during analysis: {e}</span>")


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

        winpmem_path = "C:/winpmem/winpmem_mini_x64_rc2.exe"
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









    # def handle_create_dump(self):
    #     print("🧠 Entered handle_create_dump()")

    #     dump_dir = get_default("dump")
    #     if not dump_dir or not os.path.isdir(dump_dir):
    #         dump_dir = QFileDialog.getExistingDirectory(self.view, "Choose dump directory")
    #         if not dump_dir:
    #             print("🚫 No directory selected for dump.")
    #             return
    #         set_default("dump", dump_dir)

    #     dump_path = os.path.join(dump_dir, "mem.raw")
    #     self.view.memory_file_path = dump_path  

    #     # 2. Check if WinPmem exists
    #     winpmem_path = "C:/winpmem/winpmem_mini_x64_rc2.exe"
    #     if not os.path.exists(winpmem_path):
    #         self.view.show_result(f"❌ WinPmem not found at: {winpmem_path}")
    #         return

    #     # 3. Check if Admin
    #     if not ctypes.windll.shell32.IsUserAnAdmin():
    #         print("🔒 Not admin — requesting elevation...")
    #         self.view.show_result("🔒 Requesting admin permissions...")
    #         if not run_as_admin("--create-dump"):
    #             sys.exit()
    #         return

    #     # 4. Run WinPmem
    #     try:
    #         print(f"⏳ Running WinPmem: {winpmem_path} {dump_path}")
    #         result = subprocess.run([winpmem_path, dump_path], check=False)

    #         # 5. Check success
    #         if result.returncode in [0, 1] and os.path.exists(dump_path) and os.path.getsize(dump_path) > 100 * 1024 * 1024:
    #             print("✅ Dump created!")
    #             self.view.show_result(f"✅ Memory dump created at:<br><code>{dump_path}</code>")
    #             QMessageBox.information(self.view, "Dump Created", f"Memory dump saved at:\n{dump_path}")
    #         else:
    #             raise subprocess.CalledProcessError(result.returncode, result.args)

    #     except subprocess.CalledProcessError as e:
    #         print(f"❌ Dump creation failed (subprocess error): {e}")
    #         self.view.show_result(f"❌ Dump creation failed: {e}")
    #     except Exception as e:
    #         print(f"❌ Unexpected error: {e}")
    #         self.view.show_result(f"❌ Unexpected error: {e}")

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
        
# import os
# import numpy as np
# import pandas as pd
# from PyQt6.QtWidgets import QFileDialog
# from services.prediction_service import PredictionService
# from services.explainability_service import ExplainabilityService
# from services.summary_service import SummaryService
# from services.memory_dump_service import extract_features_and_convert_to_csv

# class UserModeController:
#     def __init__(self, view):
#         self.view = view
#         self.view.setup_connections(self)

#         self.predictor = PredictionService()
#         self.explainer = None
#         self.summarizer = SummaryService()

#         self.data = None
#         self.feature_names = None

#     def handle_upload_memory_file(self):
#         file_path, _ = QFileDialog.getOpenFileName(
#             self.view, "Select memory dump file", "", "Memory Files (*.raw *.vmem)"
#         )
#         if file_path and (file_path.endswith(".raw") or file_path.endswith(".vmem")):
#             self.view.memory_file_path = file_path
#             self.view.try_enable_run_button()
#         else:
#             self.view.data_display.setHtml("<span style='color:red;'>❌ Invalid file. Please select a .raw or .vmem file.</span>")

#     def handle_choose_output_directory(self):
#         directory = QFileDialog.getExistingDirectory(
#             self.view, "Select directory to save CSV"
#         )
#         if directory:
#             self.view.output_directory = directory
#             self.view.try_enable_run_button()

#     def handle_run_analysis(self):
#         memory_path = self.view.memory_file_path
#         output_dir = self.view.output_directory

#         if not memory_path or not output_dir:
#             self.view.show_result("❌ Please upload a memory file and select output directory.")
#             return

#         try:
#             # Step 1: Extract CSV from memory dump
#             csv_path = extract_features_and_convert_to_csv(memory_path, output_dir)

#             # Step 2: Load CSV with pandas
#             self.data, self.feature_names = self.predictor.load_csv(csv_path)

#             # Step 3: Predict using updated model
#             probabilities, binary_preds, labels, features_df = self.predictor.predict(self.data)

#             # Step 4: Summarize
#             benign_count = (binary_preds == 0).sum()
#             malicious_count = (binary_preds == 1).sum()
#             total_count = len(binary_preds)
#             status = "✅ Clean" if malicious_count == 0 else "⚠️ Potential Malware Detected"

#             summary_html = self.summarizer.generate_summary(
#                 total_count, benign_count, malicious_count, status
#             )

#             self.view.show_result(
#                 f"<b>✅ Memory file:</b> {memory_path}<br><b>📁 CSV saved at:</b> {csv_path}<br><br>{summary_html}<br><br><a href='#'>Click here for explanation</a>"
#             )

#             # Step 5: Generate SHAP explanations
#             self.view.explanation_text_edit.clear()
#             self.explainer = ExplainabilityService()
#             self.explainer.initialize_explainer(
#                 model=self.predictor.model.model,
#                 X_train=features_df,
#                 feature_names=self.predictor.model.selected_features
#             )

#             for idx in np.where(binary_preds == 1)[0]:
#                 sample = features_df.iloc[idx]
#                 shap_text = self.explainer.generate_explanation_for_sample(features_df, sample, idx)
#                 self.view.append_shap_explanation(idx + 1, shap_text)

#         except Exception as e:
#             self.view.show_result(f"<span style='color:red;'>❌ Error during analysis: {e}</span>")
