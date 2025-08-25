"""
Dev Mode controller.
Coordinates the developer/testing flow: CSV upload → model inference → SHAP explainability
→ plots → HTML summary. Talks to services (model, SHAP, plots, summary) and updates the view.
"""


import pandas as pd
from PyQt6.QtWidgets import QFileDialog
from services.prediction_service import PredictionService
from services.explainability_service import ExplainabilityService
from services.plot_service import PlotService
from services.summary_service import SummaryService
from model.malware_model import MalwareDetector

class devModeController:
    """Controller bound to `view.dev_mode_view.devMode` (Dev Mode tab)."""
    def __init__(self, view):
        """
        Parameters
        ----------
        view : devMode
            The Dev Mode view. Expected API:
            - setup_connections(controller)
            - data_text_edit, process_button, data_display, tab_widget
            - confusion_graphics_scene, update_confusion_plot(QPixmap)
            - misclassified_text_edit, append_shap_explanation(index, text)
        """
        self.view = view
        self.view.setup_connections(self) # wire buttons → controller slots

        # Services / components
        self.model = MalwareDetector()
        self.predictor = PredictionService()
        self.plotter = PlotService()
        self.summarizer = SummaryService()
        
        # State
        self.data = None # pandas.DataFrame holding the loaded CSV
        self.feature_names = None  # list[str] of feature column names
        self.explainer = ExplainabilityService() # SHAP wrapper

    def upload_csv(self):
        """
        Open a file dialog and load a CSV for Dev Mode.

        Behavior
        --------
        - Reads the CSV into `self.data`.
        - Assumes first column is label; features are columns[1:].
        - Shows a compact preview in the Data tab.
        - Reveals the 'Process CSV' button on success.
        - On failure, shows an error in the right panel and hides the button.
        """
        self.file_path, _ = QFileDialog.getOpenFileName(self.view, "Open CSV File", "", "CSV Files (*.csv)")
        if self.file_path:
            try:
                # Load entire CSV
                self.data = pd.read_csv(self.file_path)
                # Heuristic: treat everything but the first column as features
                self.feature_names = list(self.data.columns[1:]) 

                # Build a readable preview (skip col0 which is the label)
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
        """
        Run prediction + summarize + explain + plot on the loaded CSV.

        Steps
        -----
        1) Validate a CSV is loaded.
        2) Predict with the keras model (probabilities/binary/labels/features_df).
        3) Compute counts and high-level status string.
        4) Render HTML summary in the right panel and reveal tabs.
        5) Initialize SHAP and append explanations for all malicious rows.
        6) Update plots (confusion matrix + misclassified list).

        Errors are shown in the right panel.
        """
        if self.data is None:
            self.view.data_display.setText("No data loaded.")
            return

        try:
            # Model inference (MalwareDetector internally selects feature columns)
            probabilities, binary_preds, labels, features_df = self.model.predict(self.data)
            
            # Aggregate counts and status
            benign_count = (binary_preds == 0).sum()
            malicious_count = (binary_preds == 1).sum()
            total_count = len(binary_preds)
            status = "Potential Malware Detected" if malicious_count > 0 else "Device Clean"

            # Summary on right panel
            summary_html = self.summarizer.generate_summary(total_count, benign_count, malicious_count, status)
            self.view.data_display.setHtml(summary_html)
            self.view.tab_widget.setVisible(True)

            # Prepare SHAP explainer (feature order must match training)
            self.explainer.initialize_explainer(self.model.model, features_df, self.model.selected_features)

            # Append per-sample SHAP only for malicious predictions
            for idx in (binary_preds == 1).nonzero()[0]:
                sample = features_df.iloc[idx]
                shap_text = self.explainer.generate_explanation_for_sample(features_df, sample, idx)
                self.view.append_shap_explanation(idx + 1, shap_text)

            # Refresh plots/tabs based on latest predictions
            self.update_plots(probabilities)

        except Exception as e:
            self.view.data_display.setText(f"Error processing CSV file: {e}")

    def update_plots(self, probabilities):
        """
        Redraw confusion matrix and misclassified list, and refresh the data preview.

        Parameters
        ----------
        probabilities : np.ndarray
            Model outputs for the positive (malware) class, shape (n, 1) or (n,).
        """
        # Clear existing confusion matrix content
        self.view.confusion_graphics_scene.clear()

        # Recreate the "Data" tab preview (omit label column)
        formatted_data = "\n\n".join([
            f"Dump file {i+1}:\n" + ", ".join(map(str, row[1:]))
            for i, row in self.data.iterrows()
        ])
        self.view.data_text_edit.setText(formatted_data)

        # Confusion matrix image
        pixmap = self.plotter.generate_confusion_matrix_pixmap(probabilities, self.data)
        self.view.update_confusion_plot(pixmap)

        # Misclassified entries text
        mis_text = self.plotter.generate_misclassified_text(probabilities, self.data)
        self.view.misclassified_text_edit.setPlainText(mis_text)
