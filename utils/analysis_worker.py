# from PyQt6.QtCore import QObject, pyqtSignal
# from services.memory_dump_service import extract_features_and_convert_to_csv
# from services.explainability_service import ExplainabilityService

# class AnalysisWorker(QObject):
#     finished = pyqtSignal(str, str)  # summary_html, explanation_text
#     error = pyqtSignal(str)

#     def __init__(self, memory_path, output_dir, predictor, summarizer):
#         super().__init__()
#         self.memory_path = memory_path
#         self.output_dir = output_dir
#         self.predictor = predictor
#         self.summarizer = summarizer

#     def run(self):
#         try:
#             csv_path = extract_features_and_convert_to_csv(self.memory_path, self.output_dir)
#             df, _ = self.predictor.load_csv(csv_path)
#             probabilities, binary_preds, labels, used_features = self.predictor.predict(df)

#             benign_count = (binary_preds == 0).sum()
#             malicious_count = (binary_preds == 1).sum()
#             total_count = len(binary_preds)
#             status = "✅ Clean" if malicious_count == 0 else "⚠️ Potential Malware Detected"
#             summary_html = self.summarizer.generate_summary(total_count, benign_count, malicious_count, status)

#             explainer = ExplainabilityService()
#             explainer.initialize_explainer(self.predictor.model, used_features, self.predictor.model.selected_features)

#             explanations = []
#             for idx in (binary_preds == 1).nonzero()[0]:
#                 sample = used_features.iloc[idx]
#                 shap_text = explainer.generate_explanation_for_sample(used_features, sample, idx)
#                 explanations.append(f"🔍 Process {idx+1} Explanation:\n{shap_text}\n\n")

#             full_explanation_text = "\n".join(explanations)
#             self.finished.emit(summary_html, full_explanation_text)

#         except Exception as e:
#             import traceback
#             traceback.print_exc()
#             self.error.emit(str(e))



from PyQt6.QtCore import QObject, pyqtSignal
from services.memory_dump_service import extract_features_and_convert_to_csv
from services.explainability_service import ExplainabilityService

class AnalysisWorker(QObject):
    finished = pyqtSignal(str, str)  # summary_html, explanation_text
    error = pyqtSignal(str)
    progress = pyqtSignal(str)  # ✅ This sends messages to the UI

    def __init__(self, memory_path, output_dir, predictor, summarizer):
        super().__init__()
        self.memory_path = memory_path
        self.output_dir = output_dir
        self.predictor = predictor
        self.summarizer = summarizer

    def run(self):
        try:
            self.progress.emit("📥 Extracting features from memory dump...")

            # ✅ Send the progress signal to the feature extractor
            csv_path = extract_features_and_convert_to_csv(
                self.memory_path,
                self.output_dir,
                progress_callback=self.progress
            )

            self.progress.emit("📊 Running predictions...")
            df, _ = self.predictor.load_csv(csv_path)
            probs, preds, _, used = self.predictor.predict(df)

            benign = (preds == 0).sum()
            malicious = (preds == 1).sum()
            total = len(preds)
            status = "✅ Clean" if malicious == 0 else "⚠️ Malware Detected"
            html = self.summarizer.generate_summary(total, benign, malicious, status)

            self.progress.emit("🧠 Generating explanations...")
            explainer = ExplainabilityService()
            explainer.initialize_explainer(self.predictor.model, used, self.predictor.model.selected_features)

            explanations = []
            for idx in (preds == 1).nonzero()[0]:
                sample = used.iloc[idx]
                shap = explainer.generate_explanation_for_sample(used, sample, idx)
                explanations.append(f"🔍 Process {idx + 1} Explanation:\n{shap}\n\n")
                self.progress.emit(f"🔎 Explained Process {idx + 1}")

            self.finished.emit(html, "\n".join(explanations))

        except Exception as e:
            import traceback
            traceback.print_exc()
            self.error.emit(str(e))
