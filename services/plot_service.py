# import numpy as np
# from PyQt6.QtGui import QPixmap, QImage
# from sklearn.metrics import confusion_matrix, ConfusionMatrixDisplay
# import matplotlib.pyplot as plt
# import io

# class PlotService:
#     def generate_confusion_matrix_pixmap(self, predictions, data):
#         true_labels = np.array([str(label).strip() for label in data[:, 0]])
#         label_mapping = {"Benign": 0, "Malware": 1}
#         y_test = np.array([label_mapping[label] for label in true_labels if label in label_mapping])
#         y_pred = (predictions > 0.5).astype(int)

#         cm = confusion_matrix(y_test, y_pred, labels=[0, 1])
#         display_labels = ["Benign", "Malware"]
#         plt.figure(figsize=(9, 5))
#         disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=display_labels)
#         disp.plot(cmap=plt.cm.Reds, ax=plt.gca())
#         plt.title("Confusion Matrix")

#         buf = io.BytesIO()
#         plt.savefig(buf, format='png')
#         plt.close()
#         buf.seek(0)
#         image = QImage.fromData(buf.getvalue())
#         return QPixmap.fromImage(image)


#     def generate_misclassified_text(self, probabilities, full_data):
#         """
#         Build exactly the same “Process i: True Label vs Predicted Label” text as your old version.
#         """
#         # 1) Extract the true labels from full_data[:,0], strip spaces, map to {0,1}:
#         true_labels = np.array([str(label).strip() for label in full_data[:, 0]])
#         label_mapping = {"Benign": 0, "Malware": 1}
#         y_test = np.array([label_mapping[label] for label in true_labels if label in label_mapping])

#         # 2) Convert probabilities → binary predictions:
#         y_pred = (probabilities > 0.5).astype(int).flatten()

#         # 3) Find misclassified indices:
#         misclassified_indices = np.where(y_test != y_pred)[0]
#         if len(misclassified_indices) == 0:
#             return "✅ No misclassified processes found."

#         # 4) Otherwise, build per‐process text exactly as you did before:
#         mis_text = ""
#         for idx in misclassified_indices:
#             process_number = idx + 1
#             true_label = "Malware" if y_test[idx] == 1 else "Benign"
#             pred_label = "Malware" if y_pred[idx] == 1 else "Benign"
#             mis_text += f"Process {process_number}:\n  True Label: {true_label}, Predicted: {pred_label}\n"
#         return mis_text


import numpy as np
import pandas as pd
from PyQt6.QtGui import QPixmap, QImage
from sklearn.metrics import confusion_matrix, ConfusionMatrixDisplay
import matplotlib.pyplot as plt
import io

class PlotService:
    def generate_confusion_matrix_pixmap(self, predictions, data: pd.DataFrame):
        true_labels = data.iloc[:, 0].astype(str).str.strip().values
        label_mapping = {"Benign": 0, "Malware": 1}
        y_test = np.array([label_mapping[label] for label in true_labels if label in label_mapping])
        y_pred = (predictions > 0.5).astype(int).flatten()

        cm = confusion_matrix(y_test, y_pred, labels=[0, 1])
        display_labels = ["Benign", "Malware"]
        plt.figure(figsize=(9, 5))
        disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=display_labels)
        disp.plot(cmap=plt.cm.Reds, ax=plt.gca())
        plt.title("Confusion Matrix")

        buf = io.BytesIO()
        plt.savefig(buf, format='png')
        plt.close()
        buf.seek(0)
        image = QImage.fromData(buf.getvalue())
        return QPixmap.fromImage(image)

    def generate_misclassified_text(self, probabilities, full_data: pd.DataFrame):
        true_labels = full_data.iloc[:, 0].astype(str).str.strip().values
        label_mapping = {"Benign": 0, "Malware": 1}
        y_test = np.array([label_mapping[label] for label in true_labels if label in label_mapping])
        y_pred = (probabilities > 0.5).astype(int).flatten()

        misclassified_indices = np.where(y_test != y_pred)[0]
        if len(misclassified_indices) == 0:
            return "✅ No misclassified processes found."

        mis_text = ""
        for idx in misclassified_indices:
            process_number = idx + 1
            true_label = "Malware" if y_test[idx] == 1 else "Benign"
            pred_label = "Malware" if y_pred[idx] == 1 else "Benign"
            mis_text += f"Dump file {process_number}:\n  True Label: {true_label}, Predicted: {pred_label}\n"
        return mis_text
