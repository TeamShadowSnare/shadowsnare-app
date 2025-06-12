import os
import numpy as np
import pandas as pd
from PyQt6.QtWidgets import QFileDialog
from services.prediction_service import PredictionService
from services.explainability_service import ExplainabilityService
from services.summary_service import SummaryService
from services.memory_dump_service import extract_features_and_convert_to_csv
import traceback
from utils.analysis_worker import AnalysisWorker
from PyQt6.QtCore import QThread
from PyQt6.QtWidgets import QApplication

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

    def handle_upload_memory_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self.view, "Select memory dump file", "", "Memory Files (*.raw *.vmem)"
        )
        if file_path and (file_path.endswith(".raw") or file_path.endswith(".vmem")):
            self.view.memory_file_path = file_path
            self.view.try_enable_run_button()
        else:
            self.view.data_display.setHtml("<span style='color:red;'>❌ Invalid file. Please select a .raw or .vmem file.</span>")

    def handle_choose_output_directory(self):
        directory = QFileDialog.getExistingDirectory(
            self.view, "Select directory to save CSV"
        )
        if directory:
            self.view.output_directory = directory
            self.view.try_enable_run_button()


    # def handle_run_analysis(self):
    #     memory_path = self.view.memory_file_path
    #     output_dir = self.view.output_directory
    #     if not memory_path or not output_dir:
    #         self.view.show_result("❌ Please upload a memory file and select output directory.")
    #         return
    #     try:
    #         print("HOWWDY FELLAS!!!")
    #         # Step 1: Extract features and convert to CSV
    #         csv_path = extract_features_and_convert_to_csv(memory_path, output_dir)
    #         # Step 2: Load CSV
    #         df, feature_names = self.predictor.load_csv(csv_path)
    #         # Step 3: Keep only numeric columns (drop sample_id, file name, etc.)
    #         numeric_df = df.select_dtypes(include=[float, int])
    #         self.feature_names = list(numeric_df.columns)
    #         self.feature_data = numeric_df.values
    #         print(f"[DEBUG]: feature_data = {self.feature_data}")
            
    #         # Step 4: Predict using the model (scaling happens inside)
    #         probabilities, binary_preds, labels, used_features = self.predictor.predict(df)
    #         print("Type of used_features:", type(used_features))
            
    #         # Fix: Handle DataFrame properly
    #         if isinstance(used_features, pd.DataFrame):
    #             print("DataFrame shape:", used_features.shape)
    #             print("First row shape:", used_features.iloc[0].shape)
    #             # Convert to numpy array for easier indexing later
    #             used_features_array = used_features.values
    #         else:
    #             # If it's already an array
    #             used_features_array = used_features
    #             print("Array shape:", used_features_array.shape)
            
    #         # Step 5: Summary
    #         benign_count = np.count_nonzero(binary_preds == 0)
    #         malicious_count = np.count_nonzero(binary_preds == 1)
    #         total_count = len(binary_preds)
    #         status = "✅ Clean" if malicious_count == 0 else "⚠️ Potential Malware Detected"
    #         summary_html = self.summarizer.generate_summary(
    #             total_count, benign_count, malicious_count, status
    #         )
    #         self.view.show_result(
    #             f"<b>✅ Memory file:</b> {memory_path}<br><b>📁 CSV saved at:</b> {csv_path}<br><br>{summary_html}<br><br><a href='#'>Click here for explanation</a>"
    #         )
            
    #         # Step 6: SHAP explanations
    #         # Step 6: SHAP explanations
    #         self.view.explanation_text_edit.clear()
    #         self.explainer = ExplainabilityService()

    #         # Use the feature names from the model's selected features, not from numeric_df
    #         model_feature_names = self.predictor.model.selected_features

    #         self.explainer.initialize_explainer(
    #             model=self.predictor.model,  # Pass the MalwareDetector object
    #             X_train=used_features,  # This should be a DataFrame
    #             feature_names=model_feature_names  # Use model's feature names
    #         )

    #         for idx in np.where(binary_preds == 1)[0]:
    #             # Get the row as a pandas Series for proper handling
    #             sample = used_features.iloc[idx]
    #             shap_text = self.explainer.generate_explanation_for_sample(used_features, sample, idx)
    #             # self.view.append_shap_explanation(idx + 1, shap_text)
                
    #     except Exception as e:
    #         print(f"[DEBUG]: {e}")
    #         traceback.print_exc()
    #         self.view.show_result(f"<span style='color:red;'>❌ Error during analysis: {e}</span>")


    def handle_run_analysis(self):
        memory_path = self.view.memory_file_path
        output_dir = self.view.output_directory

        if not memory_path or not output_dir:
            self.view.show_result("❌ Please upload a memory file and select output directory.")
            return
        # ORTAL

        # try:
        #     print("HOWWDY FELLAS!!!")
        #     # Step 1: Extract features and convert to CSV
        #     csv_path = extract_features_and_convert_to_csv(memory_path, output_dir)
        #     # Step 2: Load CSV
        #     df, feature_names = self.predictor.load_csv(csv_path)
        #     # Step 3: Keep only numeric columns (drop sample_id, file name, etc.)
        #     numeric_df = df.select_dtypes(include=[float, int])
        #     self.feature_names = list(numeric_df.columns)
        #     self.feature_data = numeric_df.values
        #     print(f"[DEBUG]: feature_data = {self.feature_data}")
            
        #     # Step 4: Predict using the model (scaling happens inside)
        #     probabilities, binary_preds, labels, used_features = self.predictor.predict(df)
        #     print("Type of used_features:", type(used_features))
            
        #     # Fix: Handle DataFrame properly
        #     if isinstance(used_features, pd.DataFrame):
        #         print("DataFrame shape:", used_features.shape)
        #         print("First row shape:", used_features.iloc[0].shape)
        #         # Convert to numpy array for easier indexing later
        #         used_features_array = used_features.values
        #     else:
        #         # If it's already an array
        #         used_features_array = used_features
        #         print("Array shape:", used_features_array.shape)
            
        #     # Step 5: Summary
        #     benign_count = np.count_nonzero(binary_preds == 0)
        #     malicious_count = np.count_nonzero(binary_preds == 1)
        #     total_count = len(binary_preds)
        #     status = "✅ Clean" if malicious_count == 0 else "⚠️ Potential Malware Detected"
        #     summary_html = self.summarizer.generate_summary(
        #         total_count, benign_count, malicious_count, status
        #     )
        #     self.view.show_result(
        #         f"<b>✅ Memory file:</b> {memory_path}<br><b>📁 CSV saved at:</b> {csv_path}<br><br>{summary_html}<br><br><a href='#'>Click here for explanation</a>"
        #     )
            
        #     # Step 6: SHAP explanations
        #     self.view.explanation_text_edit.clear()
        #     self.explainer = ExplainabilityService()

        self.view.show_result("🔄 Analyzing memory dump... please wait...")

        self.thread = QThread()
        self.worker = AnalysisWorker(memory_path, output_dir, self.predictor, self.summarizer)
        self.worker.progress.connect(self.on_progress_update)
        self.worker.moveToThread(self.thread)

        self.thread.started.connect(self.worker.run)
        self.worker.finished.connect(self.on_analysis_finished)
        self.worker.error.connect(self.on_analysis_error)

        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)

        self.thread.start()
        
    def on_progress_update(self, message):
        self.view.data_display.append(message)
        self.view.data_display.repaint()
        QApplication.processEvents()

    def on_analysis_finished(self, summary_html, explanation_text):
        self.view.show_result(summary_html)
        self.view.explanation_text_edit.setPlainText(explanation_text)

    def on_analysis_error(self, message):
        self.view.show_result(f"<span style='color:red;'>❌ Error during analysis: {message}</span>")
























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

        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("🔒 Not admin — requesting elevation...")
            self.view.show_result("🔒 Requesting admin permissions...")
            from utils.run_as_admin import run_as_admin
            if not run_as_admin("--create-dump"):
                sys.exit()
            return

        try:
            # Save to Desktop as mem.raw
            dump_path = os.path.join(os.path.expanduser("~"), "Desktop", "mem.raw")
            winpmem_path = "C:/winpmem/winpmem_mini_x64_rc2.exe"

            if not os.path.exists(winpmem_path):
                self.view.show_result(f"❌ WinPmem not found at: {winpmem_path}")
                return

            print(f"⏳ Running WinPmem: {winpmem_path} {dump_path}")
            result = subprocess.run([winpmem_path, dump_path], check=False)

            if result.returncode in [0, 1] and os.path.exists(dump_path) and os.path.getsize(dump_path) > 100 * 1024 * 1024:
                print("✅ Dump created!")
                self.view.memory_file_path = dump_path
                self.view.show_result(f"✅ Memory dump created at:<br><code>{dump_path}</code>")
            else:
                raise subprocess.CalledProcessError(result.returncode, result.args)

        except subprocess.CalledProcessError as e:
            print(f"❌ Dump creation failed (subprocess error): {e}")
            self.view.show_result(f"❌ Dump creation failed: {e}")
        except Exception as e:
            print(f"❌ Unexpected error: {e}")
            self.view.show_result(f"❌ Unexpected error: {e}")


    def handle_raw_to_csv(self):
        memory_path = self.view.memory_file_path

        if not memory_path:
            self.view.show_result("❌ Please upload or create a memory file first.")
            return

        try:
            # Automatically place CSV next to the .raw file
            base_dir = os.path.dirname(memory_path)
            csv_path = extract_features_and_convert_to_csv(memory_path, base_dir)

            self.view.show_result(
                f"📑 Feature extraction completed.<br>✅ CSV saved at:<br><code>{csv_path}</code><br><br>Use 'Upload CSV' to analyze it."
            )

        except Exception as e:
            import traceback
            print(f"[CSV EXTRACT ERROR]: {e}")
            traceback.print_exc()
            self.view.show_result(f"<span style='color:red;'>❌ Failed to extract CSV: {e}</span>")

    def handle_upload_csv_directly(self):
        file_path, _ = QFileDialog.getOpenFileName(self.view, "Select CSV file", "", "CSV Files (*.csv)")
        print(f"📂 File selected: {file_path}")  # Debug line

        if not file_path:
            print("🚫 No file selected.")
            return

        try:
            self.data = pd.read_csv(file_path)
            print("✅ CSV loaded.")

            self.feature_names = list(self.data.columns[1:])
            formatted_data = "\n\n".join([
                f"Dump file {i+1}:\n" + ", ".join(map(str, row[1:]))
                for i, row in self.data.iterrows()
            ])
            print("📄 Data displayed.")

            probabilities, binary_preds, labels, features_df = self.model.predict(self.data)
            print("🔮 Prediction complete.")

            benign_count = (binary_preds == 0).sum()
            malicious_count = (binary_preds == 1).sum()
            total_count = len(binary_preds)
            status = "Potential Malware Detected" if malicious_count > 0 else "Device Clean"
            summary_html = self.summarizer.generate_summary(
                total_count, benign_count, malicious_count, status
            )

            # Append a clickable link to show SHAP explanation
            summary_html += """
                <div style='text-align:center; margin-top: 20px;'>
                    <a href='#' style='font-size:18px; color:#00bcd4;'>🔍 Click here to view explanation</a>
                </div>
            """

            self.view.data_display.setHtml(summary_html)

            self.explainer.initialize_explainer(self.model.model, features_df, self.model.selected_features)
            for idx in (binary_preds == 1).nonzero()[0]:
                sample = features_df.iloc[idx]
                shap_text = self.explainer.generate_explanation_for_sample(features_df, sample, idx)
                self.view.append_shap_explanation(idx + 1, shap_text)

            self.view.analysis_widget.setVisible(True)
            print("✅ Done.")

        except Exception as e:
            print(f"❌ Error: {e}")
            self.view.data_display.setText(f"Error processing CSV file: {e}")

        self.view.title.setVisible(False)
        self.view.instructions.setVisible(False)
        self.view.create_dump_button.setVisible(False)
        self.view.extract_csv_button.setVisible(False)
        self.view.upload_csv_button.setVisible(False)

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
