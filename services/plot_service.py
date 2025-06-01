import numpy as np
from sklearn.metrics import confusion_matrix, ConfusionMatrixDisplay
from PyQt6.QtGui import QPixmap, QImage
import matplotlib.pyplot as plt
import io

class PlotService:
    def generate_confusion_matrix(self, predictions, data):
        true_labels = np.array([str(label).strip() for label in data[:, 0]])
        label_mapping = {"Benign": 0, "Malware": 1}
        y_test = np.array([label_mapping[label] for label in true_labels if label in label_mapping])
        y_pred = (predictions > 0.5).astype(int)

        cm = confusion_matrix(y_test, y_pred, labels=[0, 1])
        plt.figure(figsize=(9, 5))
        disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=["Benign", "Malware"])
        disp.plot(cmap=plt.cm.Reds, ax=plt.gca())
        plt.title("Confusion Matrix")
        buf = io.BytesIO()
        plt.savefig(buf, format='png')
        plt.close()

        buf.seek(0)
        image = QImage.fromData(buf.getvalue())
        return QPixmap.fromImage(image)

    def generate_misclassified_text(self, predictions, data):
        true_labels = np.array([str(label).strip() for label in data[:, 0]])
        label_mapping = {"Benign": 0, "Malware": 1}
        y_test = np.array([label_mapping[label] for label in true_labels if label in label_mapping])
        y_pred = (predictions > 0.5).astype(int).flatten()

        misclassified_indices = np.where(y_test != y_pred)[0]
        if len(misclassified_indices) == 0:
            return "✅ No misclassified processes found."

        result = ""
        for idx in misclassified_indices:
            result += f"Process {idx+1}: True Label: {'Malware' if y_test[idx] else 'Benign'}, Predicted: {'Malware' if y_pred[idx] else 'Benign'}\n"
        return result
