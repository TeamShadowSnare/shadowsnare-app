"""
CSV analysis worker (Qt, background thread friendly).

Purpose
-------
Runs the offline analysis pipeline for a single CSV *off the UI thread*:
1) Loads CSV with the injected `predictor` (PredictionService-like).
2) Predicts probabilities/classes.
3) Builds an HTML summary with the injected `summarizer` (SummaryService).
4) Generates SHAP explanations for malicious rows.
5) Emits progress/messages via Qt signals.

Signals
-------
progress: str        - streaming log lines for the UI
finished: (html,explanations) - final HTML summary and concatenated explanations
error: str           - error message on failure

Notes
-----
- Expects `predictor.load_csv(path) -> (ndarray, feature_names)`
  and `predictor.predict(data) -> (probs, preds, raw_X, used)`.
- `used` is assumed to be a *DataFrame* aligned with model features for SHAP;
  if your predictor returns a NumPy array, make sure to convert it upstream or
  adjust ExplainabilityService to handle arrays everywhere.
"""


from PyQt6.QtCore import QObject, pyqtSignal
import traceback
from services.explainability_service import ExplainabilityService

class CsvAnalyzeWorker(QObject):
    """Background worker for CSV → predict → summarize → explain flow."""
    # Textual progress updates for the UI
    progress = pyqtSignal(str)
    # Final payload: (summary_html, explanations_text)
    finished = pyqtSignal(str, str)
    # Error string on exception
    error = pyqtSignal(str)

    def __init__(self, csv_path: str, predictor, summarizer):
        """
        Parameters
        ----------
        csv_path : str
            Path to the CSV to analyze.
        predictor : object
            Service exposing `load_csv()` and `predict()`.
        summarizer : object
            Service exposing `generate_summary(total, benign, malicious, status)`.
        """
        super().__init__()
        self.csv_path   = csv_path
        self.predictor  = predictor
        self.summarizer = summarizer

    def run(self):
        """Main worker entry: emits progress, then finished/error."""
        try:
            self.progress.emit("📊 Running predictions…")
            
            # 1) Load and predict
            df, _ = self.predictor.load_csv(self.csv_path)
            probs, preds, _, used = self.predictor.predict(df)

            # 2) Aggregate counts and build summary HTML
            benign = (preds == 0).sum()
            malicious = (preds == 1).sum()
            total = len(preds)
            status = "✅ Clean" if malicious == 0 else "⚠️ Malware Detected"
            html = self.summarizer.generate_summary(total, benign, malicious, status)

            # 3) SHAP explanations for malicious rows
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

            # 4) Done
            self.finished.emit(html, "".join(explanations))

        except Exception as e:
            # Keep a stacktrace for devs and emit a clean error for the UI
            traceback.print_exc()
            self.error.emit(str(e))
