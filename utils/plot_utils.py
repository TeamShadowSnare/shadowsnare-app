import numpy as np
from PyQt6.QtGui import QPixmap, QImage
from sklearn.metrics import confusion_matrix, ConfusionMatrixDisplay
import matplotlib.pyplot as plt
import io


def generate_confusion_matrix_pixmap(predictions, data):
    true_labels = np.array([str(label).strip() for label in data[:, 0]])
    label_mapping = {"Benign": 0, "Malware": 1}
    y_test = np.array([label_mapping[label] for label in true_labels if label in label_mapping])
    y_pred = (predictions > 0.5).astype(int)

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