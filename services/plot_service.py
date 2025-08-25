"""
Plot service utilities.

Provides:
- generate_confusion_matrix_pixmap: build a matplotlib confusion matrix and return it as QPixmap for the UI.
- generate_misclassified_text: produce a readable list of misclassified rows.

Assumptions:
- The first column of the provided DataFrame contains ground-truth labels as 'Benign'/'Malware'.
- `predictions`/`probabilities` are model outputs for the positive class (shape (n, 1) or (n,)).
"""


import numpy as np
import pandas as pd
from PyQt6.QtGui import QPixmap, QImage
from sklearn.metrics import confusion_matrix, ConfusionMatrixDisplay
import matplotlib.pyplot as plt
import io

class PlotService:
    """Helper to convert predictions + labels into plots/text for the Dev/User views."""
    
    def generate_confusion_matrix_pixmap(self, predictions, data: pd.DataFrame):
        """
        Build a confusion-matrix image from predictions and ground-truth labels.

        Parameters
        ----------
        predictions : np.ndarray
            Model probabilities for the positive class (malware).
        data : pd.DataFrame
            Full table whose first column holds string labels ('Benign'/'Malware').

        Returns
        -------
        QPixmap
            Rendered confusion matrix suitable for a QGraphicsView.
        """
        # Extract ground-truth labels from the first column and map them to {Benign:0, Malware:1}
        true_labels = data.iloc[:, 0].astype(str).str.strip().values
        label_mapping = {"Benign": 0, "Malware": 1}
        # Only map known labels to ints; unknown labels are skipped by the comprehension guard
        y_test = np.array([label_mapping[label] for label in true_labels if label in label_mapping])
        
        # Threshold probabilities at 0.5 to get binary predictions
        y_pred = (predictions > 0.5).astype(int).flatten()

        # Compute confusion matrix with fixed order [Benign(0), Malware(1)]
        cm = confusion_matrix(y_test, y_pred, labels=[0, 1])
        display_labels = ["Benign", "Malware"]
        
        # Plot using matplotlib; capture the figure into a PNG buffer
        plt.figure(figsize=(9, 5))
        disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=display_labels)
        disp.plot(cmap=plt.cm.Reds, ax=plt.gca())
        plt.title("Confusion Matrix")

        # Serialize figure → PNG bytes → QImage → QPixmap
        buf = io.BytesIO()
        plt.savefig(buf, format='png')
        plt.close()
        buf.seek(0)
        image = QImage.fromData(buf.getvalue())
        return QPixmap.fromImage(image)

    def generate_misclassified_text(self, probabilities, full_data: pd.DataFrame):
        """
        List misclassified rows with their true/predicted labels.

        Parameters
        ----------
        probabilities : np.ndarray
            Model probabilities for the positive class (malware).
        full_data : pd.DataFrame
            DataFrame whose first column contains string labels ('Benign'/'Malware').

        Returns
        -------
        str
            Human-readable summary of misclassifications, or a success tick if none.
        """
        # Build y_test from the first column
        true_labels = full_data.iloc[:, 0].astype(str).str.strip().values
        label_mapping = {"Benign": 0, "Malware": 1}
        y_test = np.array([label_mapping[label] for label in true_labels if label in label_mapping])
        
        # Threshold model outputs
        y_pred = (probabilities > 0.5).astype(int).flatten()

        # Indices where prediction != truth
        misclassified_indices = np.where(y_test != y_pred)[0]
        if len(misclassified_indices) == 0:
            return "✅ No misclassified processes found."

        # Compose a per-row summary
        mis_text = ""
        for idx in misclassified_indices:
            process_number = idx + 1
            true_label = "Malware" if y_test[idx] == 1 else "Benign"
            pred_label = "Malware" if y_pred[idx] == 1 else "Benign"
            mis_text += f"Dump file {process_number}:\n  True Label: {true_label}, Predicted: {pred_label}\n"
        return mis_text
