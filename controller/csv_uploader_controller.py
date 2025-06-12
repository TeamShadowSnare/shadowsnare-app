# import os
# import numpy as np
# from PyQt6.QtWidgets import QFileDialog
# from services.prediction_service import PredictionService
# from services.explainability_service import ExplainabilityService
# from services.plot_service import PlotService
# from services.summary_service import SummaryService
# from model.malware_model import MalwareDetector  


# class CSVUploaderController:
#     def __init__(self, view):
#         self.view = view
#         self.view.setup_connections(self)

#         self.model = MalwareDetector()
#         self.predictor = PredictionService()
#         self.plotter = PlotService()
#         self.summarizer = SummaryService()

#         self.data = None
#         self.dataFromINDEX2Col = None
#         self.feature_names = None
#         self.explainer = ExplainabilityService()
        
#     def upload_csv(self):
#         self.file_path, _ = QFileDialog.getOpenFileName(self.view, "Open CSV File", "", "CSV Files (*.csv)")
#         if self.file_path:
#             try:
#                 with open(self.file_path, 'r') as f:
#                     header_line = f.readline().strip()
#                     all_columns = header_line.split(',')  
#                     self.feature_names = all_columns[2:] 

#                 self.data = np.genfromtxt(self.file_path, delimiter=',', dtype=str, skip_header=1)
#                 if self.data.ndim == 1:
#                     self.data = self.data.reshape(1, -1)
#                 self.dataFromINDEX2Col = self.data[:, 2:]

#                 formatted_data = "\n\n".join([
#                     f"Process {i+1}:\n" + ", ".join(row)
#                     for i, row in enumerate(self.dataFromINDEX2Col)
#                 ])
#                 self.view.data_text_edit.setText(formatted_data)
#                 self.view.process_button.setVisible(True)

#             except Exception as e:
#                 self.view.data_display.setText(f"Error reading CSV file: {e}")
#                 self.view.process_button.setVisible(False)

#     def process_csv(self):
#         if self.dataFromINDEX2Col is None:
#             self.view.data_display.setText("No data loaded.")
#             return

#         try:
#             raw_X = self.dataFromINDEX2Col.astype(float)
#             X_scaled = self.model.scaler.transform(raw_X)

#             probabilities = self.model.model.predict(X_scaled)
#             binary_preds = (probabilities > 0.5).astype(int).flatten()

#             benign_count = np.count_nonzero(binary_preds == 0)
#             malicious_count = np.count_nonzero(binary_preds == 1)
#             total_count = len(binary_preds)
#             status = "Potential Malware Detected" if malicious_count > 0 else "Device Clean"

#             summary_html = self.summarizer.generate_summary(
#                 total_count, benign_count, malicious_count, status
#             )
#             self.view.data_display.setHtml(summary_html)
#             self.view.tab_widget.setVisible(True)

#             # ✅ Initialize SHAP explainer through the service
#             self.explainer.initialize_explainer(
#                 model=self.model.model,
#                 X_train=X_scaled,
#                 feature_names=self.feature_names
#             )

#             # 🔍 Show explanation for each malicious process
#             malicious_indices = np.where(binary_preds == 1)[0]
#             for idx in malicious_indices:
#                 sample = X_scaled[idx]
#                 shap_text = self.explainer.generate_explanation_for_sample(X_scaled, sample, idx)
#                 self.view.append_shap_explanation(idx + 1, shap_text)

#             self.update_plots(probabilities)

#         except Exception as e:
#             self.view.data_display.setText(f"Error processing CSV file: {e}")

#     def update_plots(self, probabilities):
#         self.view.confusion_graphics_scene.clear()

#         formatted_data = "\n\n".join([
#             f"Process {i+1}:\n" + ", ".join(row)
#             for i, row in enumerate(self.dataFromINDEX2Col)
#         ])
#         self.view.data_text_edit.setText(formatted_data)

#         pixmap = self.plotter.generate_confusion_matrix_pixmap(probabilities, self.data)
#         self.view.update_confusion_plot(pixmap)

#         mis_text = self.plotter.generate_misclassified_text(probabilities, self.data)
#         self.view.misclassified_text_edit.setPlainText(mis_text)


import pandas as pd
from PyQt6.QtWidgets import QFileDialog
from services.prediction_service import PredictionService
from services.explainability_service import ExplainabilityService
from services.plot_service import PlotService
from services.summary_service import SummaryService
from model.malware_model import MalwareDetector

class CSVUploaderController:
    def __init__(self, view):
        self.view = view
        self.view.setup_connections(self)

        self.model = MalwareDetector()
        self.predictor = PredictionService()
        self.plotter = PlotService()
        self.summarizer = SummaryService()

        self.data = None
        self.feature_names = None
        self.explainer = ExplainabilityService()

    def upload_csv(self):
        self.file_path, _ = QFileDialog.getOpenFileName(self.view, "Open CSV File", "", "CSV Files (*.csv)")
        if self.file_path:
            try:
                self.data = pd.read_csv(self.file_path)
                self.feature_names = list(self.data.columns[1:])  # Skip label

                formatted_data = "\n\n".join([
                    f"Dump file {i+1}:\n" + ", ".join(map(str, row[1:]))
                    for i, row in self.data.iterrows()
                ])
                self.view.data_text_edit.setText(formatted_data)
                self.view.process_button.setVisible(True)
            except Exception as e:
                self.view.data_display.setText(f"Error reading CSV file: {e}")
                self.view.process_button.setVisible(False)

    def process_csv(self):
        if self.data is None:
            self.view.data_display.setText("No data loaded.")
            return

        try:
            probabilities, binary_preds, labels, features_df = self.model.predict(self.data)

            benign_count = (binary_preds == 0).sum()
            malicious_count = (binary_preds == 1).sum()
            total_count = len(binary_preds)
            status = "Potential Malware Detected" if malicious_count > 0 else "Device Clean"

            summary_html = self.summarizer.generate_summary(total_count, benign_count, malicious_count, status)
            self.view.data_display.setHtml(summary_html)
            self.view.tab_widget.setVisible(True)

            self.explainer.initialize_explainer(self.model.model, features_df, self.model.selected_features)

            for idx in (binary_preds == 1).nonzero()[0]:
                sample = features_df.iloc[idx]
                shap_text = self.explainer.generate_explanation_for_sample(features_df, sample, idx)
                self.view.append_shap_explanation(idx + 1, shap_text)

            self.update_plots(probabilities)

        except Exception as e:
            self.view.data_display.setText(f"Error processing CSV file: {e}")

    def update_plots(self, probabilities):
        self.view.confusion_graphics_scene.clear()

        formatted_data = "\n\n".join([
            f"Dump file {i+1}:\n" + ", ".join(map(str, row[1:]))
            for i, row in self.data.iterrows()
        ])
        self.view.data_text_edit.setText(formatted_data)

        pixmap = self.plotter.generate_confusion_matrix_pixmap(probabilities, self.data)
        self.view.update_confusion_plot(pixmap)

        mis_text = self.plotter.generate_misclassified_text(probabilities, self.data)
        self.view.misclassified_text_edit.setPlainText(mis_text)
