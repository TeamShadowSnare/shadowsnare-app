import os
import numpy as np
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
        self.dataFromINDEX2Col = None
        self.feature_names = None
        self.explainer = None

    def upload_csv(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self.view, "Open CSV File", "", "CSV Files (*.csv)"
        )
        if not file_path:
            return

        try:
            # 1) Load header + data as strings
            self.data, self.feature_names = self.predictor.load_csv(file_path)
            if self.data.ndim == 1:
                self.data = self.data.reshape(1, -1)

            # 2) Extract only the columns from index 2 onward (strings)
            self.dataFromINDEX2Col = self.data[:, 2:]

            # 3) Format the “Process #: …” lines exactly as before
            formatted_data = "\n\n".join([
                f"Process {i+1}:\n" + ", ".join(row)
                for i, row in enumerate(self.dataFromINDEX2Col)
            ])

            # → Show that text in your view’s QTextEdit
            #   (change data_text_edit to match your actual attribute name)
            self.view.data_text_edit.setPlainText(formatted_data)

            # → Make the “Process CSV” button visible
            #   (change process_button to match your actual attribute name)
            self.view.process_button.setVisible(True)

            # 4) Prepare the SHAP explainer with scaled floats:
            raw_X = self.dataFromINDEX2Col.astype(float)
            X_scaled = self.model.scaler.transform(raw_X)

            self.explainer = ExplainabilityService(
                model=self.model.model,
                X_train=X_scaled,
                feature_names=self.feature_names
            )

        except Exception as e:
            # ← Here was the problem: use data_display, not data_display_ref
            #   (change data_display to match your actual attribute name)
            self.view.data_display.setPlainText(f"Error reading CSV file: {e}")
            self.view.process_button.setVisible(False)

    def process_csv(self):
        if self.dataFromINDEX2Col is None:
            # (change data_display to match your actual attribute name)
            self.view.data_display.setPlainText("No data loaded.")
            return

        try:
            # 1) Predict: returns (probabilities, binary_preds, raw_X, X_scaled)
            probabilities, binary_preds, raw_X, X_scaled = self.predictor.predict(self.dataFromINDEX2Col)

            # 2) Count benign/malicious
            benign_count = np.count_nonzero(binary_preds == 0)
            malicious_count = np.count_nonzero(binary_preds == 1)
            total_count = len(binary_preds)
            status = "Potential Malware Detected" if malicious_count > 0 else "Device Clean"

            # 3) Build HTML via SummaryService
            summary_html = self.summarizer.generate_summary(
                total_count, benign_count, malicious_count, status
            )
            # (change data_display to match your actual attribute name)
            self.view.data_display.setHtml(summary_html)

            # 4) Reveal the tabs
            #   (change tab_widget to match your actual attribute name)
            self.view.tab_widget.setVisible(True)

            # 5) For each malicious index, call SHAP and append to view
            malicious_indices = np.where(binary_preds == 1)[0]
            for idx in malicious_indices:
                sample = X_scaled[idx]
                shap_text = self.explainer.generate_explanation_for_sample(X_scaled, sample, idx)
                # (change append_shap_explanation to match your actual method)
                self.view.append_shap_explanation(idx + 1, shap_text)

            # 6) Update confusion plot and misclassified text
            self.update_plots(probabilities, binary_preds)

        except Exception as e:
            # (change data_display to match your actual attribute name)
            self.view.data_display.setPlainText(f"Error processing CSV file: {e}")

    def update_plots(self, probabilities, binary_preds):
        # 1) Clear the QGraphicsScene for confusion matrix
        #   (change confusion_graphics_scene to match your actual attribute name)
        self.view.confusion_graphics_scene.clear()

        # 2) Re‐show the “Process #: …” listing
        formatted_data = "\n\n".join([
            f"Process {i+1}:\n" + ", ".join(row)
            for i, row in enumerate(self.dataFromINDEX2Col)
        ])
        # (change data_text_edit to match your actual attribute name)
        self.view.data_text_edit.setPlainText(formatted_data)

        # 3) Generate and display confusion matrix pixmap
        pixmap = self.plotter.generate_confusion_matrix_pixmap(probabilities, self.data)
        # (change update_confusion_plot to match your actual method)
        self.view.update_confusion_plot(pixmap)

        # 4) Generate misclassified‐text and display it
        mis_text = self.plotter.generate_misclassified_text(probabilities, self.data)
        # (change misclassified_text_edit to match your actual attribute name)
        self.view.misclassified_text_edit.setPlainText(mis_text)
