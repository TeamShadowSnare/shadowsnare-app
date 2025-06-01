from PyQt6.QtWidgets import QFileDialog
from services.prediction_service import PredictionService
from services.explainability_service import ExplainabilityService
from services.plot_service import PlotService
from services.summary_service import SummaryService

class CSVUploaderController:
    def __init__(self, view):
        self.view = view
        self.view.setup_connections(self)
        self.predictor = PredictionService()
        self.plotter = PlotService()
        self.summarizer = SummaryService()
        self.data = None
        self.feature_names = None

    def upload_csv(self):
        file_path, _ = QFileDialog.getOpenFileName(self.view, "Open CSV File", "", "CSV Files (*.csv)")
        if file_path:
            try:
                self.data, self.feature_names = self.predictor.load_csv(file_path)
                self.feature_data = self.data[:, 2:]  # Explicitly store features only

                # Initialize ExplainabilityService here
                self.explainer = ExplainabilityService(
                    model=self.predictor.model.model,
                    X_train=self.feature_data.astype(float),
                    feature_names=self.feature_names
                )

                formatted_data = "\n\n".join([f"Process {i+1}:\n" + ", ".join(row) for i, row in enumerate(self.feature_data)])
                self.view.show_data_preview(self.data)

            except Exception as e:
                self.view.show_error(f"Error loading CSV: {e}")



    def process_csv(self):
        if self.data is None:
            self.view.show_error("No data loaded.")
            return

        try:
            predictions, summary = self.predictor.predict(self.feature_data)
            summary_html = self.summarizer.generate_summary(summary)
            self.view.show_summary(summary_html)

            explanations = self.explainer.generate_explanations(self.feature_data)
            self.view.show_explanations(explanations)

            confusion_pixmap = self.plotter.generate_confusion_matrix(predictions, self.data)
            self.view.update_confusion_plot(confusion_pixmap)

            misclassified_text = self.plotter.generate_misclassified_text(predictions, self.data)
            self.view.show_misclassified(misclassified_text)

        except Exception as e:
            self.view.show_error(f"Error processing CSV: {e}")
