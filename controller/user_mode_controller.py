from PyQt6.QtWidgets import QFileDialog
import numpy as np
from services.prediction_service import PredictionService
from services.explainability_service import ExplainabilityService
from services.summary_service import SummaryService

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

    def handle_create_csv(self):
        print("✅ Create CSV button clicked!")
        self.view.upload_csv_button.setVisible(True)  # ✅ SHOW the button

    def handle_upload_csv(self):
        print("📂 Upload CSV button clicked!")
        self.view.continue_button.setVisible(True)  # ✅ Show analyze button after upload

        file_path, _ = QFileDialog.getOpenFileName(
            self.view, "Select CSV File", "", "CSV Files (*.csv)"
        )
        if not file_path:
            return

        try:
            self.data, self.feature_names = self.predictor.load_csv(file_path)
            self.feature_data = self.data[:, 2:].astype(float)

            X_scaled = self.predictor.model.scaler.transform(self.feature_data)
            self.explainer = ExplainabilityService(
                model=self.predictor.model.model,
                X_train=X_scaled,
                feature_names=self.feature_names
            )

            print("✅ File uploaded and SHAP explainer ready!")

        except Exception as e:
            self.view.show_summary(f"Error: {e}")

    def handle_analyze_file(self):
        print("🚀 Continue to Analyze button clicked!")

        if self.feature_data is None:
            self.view.show_summary("❌ No CSV data found.")
            return

        try:
            # Run model prediction
            probabilities, binary_preds, raw_X, X_scaled = self.predictor.predict(self.feature_data)

            # Summary
            benign_count = np.count_nonzero(binary_preds == 0)
            malicious_count = np.count_nonzero(binary_preds == 1)
            total_count = len(binary_preds)
            status = "✅ Clean" if malicious_count == 0 else "⚠️ Potential Malware Detected"

            summary_html = self.summarizer.generate_summary(
                total_count, benign_count, malicious_count, status
            )
            self.view.show_summary(summary_html)

            # SHAP explanations
            self.view.explanation_text_edit.clear()
            for idx in np.where(binary_preds == 1)[0]:
                sample = X_scaled[idx]
                shap_text = self.explainer.generate_explanation_for_sample(X_scaled, sample, idx)
                self.view.append_shap_explanation(idx + 1, shap_text)

            self.view.show_analysis_layout()  # Show result layout last

        except Exception as e:
            self.view.show_summary(f"❌ Error during analysis: {e}")

    def handle_show_popup(self):
        self.view.show_explanation_popup()

