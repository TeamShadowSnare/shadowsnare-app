from PyQt6.QtCore import QObject, pyqtSignal
import traceback
from services.explainability_service import ExplainabilityService

class CsvAnalyzeWorker(QObject):
    progress = pyqtSignal(str)
    finished = pyqtSignal(str, str)   # summary_html, explanation_text
    error    = pyqtSignal(str)

    def __init__(self, csv_path: str, predictor, summarizer):
        super().__init__()
        self.csv_path   = csv_path
        self.predictor  = predictor
        self.summarizer = summarizer

    def run(self):
        try:
            self.progress.emit("📊 Running predictions…")
            df, _ = self.predictor.load_csv(self.csv_path)
            probs, preds, _, used = self.predictor.predict(df)

            benign = (preds == 0).sum()
            malicious = (preds == 1).sum()
            total = len(preds)
            status = "✅ Clean" if malicious == 0 else "⚠️ Malware Detected"
            html = self.summarizer.generate_summary(total, benign, malicious, status)

            self.progress.emit("🧠 Generating explanations…")
            explainer = ExplainabilityService()
            explainer.initialize_explainer(
                self.predictor.model, used, self.predictor.model.selected_features)

            explanations = []
            for idx in (preds == 1).nonzero()[0]:
                sample = used.iloc[idx]
                shap = explainer.generate_explanation_for_sample(used, sample, idx)
                explanations.append(f"🔍 Process {idx + 1}:\n{shap}\n\n")
                self.progress.emit(f"🔎 Explained Process {idx + 1}")

            self.finished.emit(html, "".join(explanations))

        except Exception as e:
            traceback.print_exc()
            self.error.emit(str(e))
