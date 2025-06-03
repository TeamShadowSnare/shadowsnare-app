import numpy as np
from PyQt6.QtGui import QPixmap, QImage
from sklearn.metrics import confusion_matrix, ConfusionMatrixDisplay
import matplotlib.pyplot as plt
import io
import shap

_shap_explainer = None

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


def generate_shap_explanation(model, X_train, sample, feature_names):
    global _shap_explainer
    if _shap_explainer is None:
        _shap_explainer = shap.Explainer(model, X_train, feature_names=feature_names)

    sample = sample.reshape(1, -1)
    shap_values = _shap_explainer(sample)

    values = shap_values[0].values
    effects = sorted(zip(values, feature_names), key=lambda x: abs(x[0]), reverse=True)
    arrows = ["🟥 ↑" if val > 0 else "🟦 ↓" for val, _ in effects[:3]]
    explanation = "\n".join(f"{arrow} {name}" for arrow, (_, name) in zip(arrows, effects[:3]))
    final_score = (shap_values[0].base_values + sum(values)).item()
    summary = (
        f"This file is {'malicious' if final_score > 0.5 else 'benign'}.\n\n"
        f"Top factors:\n{explanation}\n\nFinal risk score: {final_score:.2f}"
    )
    return summary


def load_template(template_path):
    with open(template_path, 'r', encoding='utf-8') as f:
        return f.read()
