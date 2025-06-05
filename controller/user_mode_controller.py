import os
import numpy as np
from PyQt6.QtWidgets import QFileDialog
from services.prediction_service import PredictionService
from services.explainability_service import ExplainabilityService
from services.summary_service import SummaryService
from services.memory_dump_service import extract_features_and_convert_to_csv

class UserModeController:
    def __init__(self, view):
        self.view = view
        self.view.setup_connections(self)

        self.predictor = PredictionService()
        self.explainer = None
        self.summarizer = SummaryService()

        self.data = None
        self.feature_data = None
        self.feature_names = None

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

    def handle_run_analysis(self):
        memory_path = self.view.memory_file_path
        output_dir = self.view.output_directory

        if not memory_path or not output_dir:
            self.view.show_result("❌ Please upload a memory file and select output directory.")
            return

        try:
            csv_path = extract_features_and_convert_to_csv(memory_path, output_dir)

            self.data, self.feature_names = self.predictor.load_csv(csv_path)
            self.feature_data = self.data[:, 2:].astype(float)

            X_scaled = self.predictor.model.scaler.transform(self.feature_data)

            self.explainer = ExplainabilityService(
                model=self.predictor.model.model,
                X_train=X_scaled,
                feature_names=self.feature_names
            )

            probabilities, binary_preds, raw_X, X_scaled = self.predictor.predict(self.feature_data)

            benign_count = np.count_nonzero(binary_preds == 0)
            malicious_count = np.count_nonzero(binary_preds == 1)
            total_count = len(binary_preds)
            status = "✅ Clean" if malicious_count == 0 else "⚠️ Potential Malware Detected"

            summary_html = self.summarizer.generate_summary(
                total_count, benign_count, malicious_count, status
            )

            self.view.show_result(
                f"<b>✅ Memory file:</b> {memory_path}<br><b>📁 CSV saved at:</b> {csv_path}<br><br>{summary_html}<br><br><a href='#'>Click here for explanation</a>"
            )

            self.view.explanation_text_edit.clear()
            for idx in np.where(binary_preds == 1)[0]:
                sample = X_scaled[idx]
                shap_text = self.explainer.generate_explanation_for_sample(X_scaled, sample, idx)
                self.view.append_shap_explanation(idx + 1, shap_text)

        except Exception as e:
            self.view.show_result(f"<span style='color:red;'>❌ Error during analysis: {e}</span>")



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
