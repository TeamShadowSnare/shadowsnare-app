import os
import numpy as np
from PyQt6.QtWidgets import QFileDialog
from PyQt6.QtCore import QDate, QTime, Qt
from model.malware_model import MalwareDetector
from utils.plot_utils import generate_confusion_matrix_pixmap, load_template
from utils.plot_utils import generate_shap_explanation

class CSVUploaderController:
    def __init__(self, view):
        self.view = view
        self.view.setup_connections(self)
        self.model = MalwareDetector()
        self.file_path = None
        self.data = None
        self.dataFromINDEX2Col = None
        self.predictions = None

    def upload_csv(self):
        self.file_path, _ = QFileDialog.getOpenFileName(self.view, "Open CSV File", "", "CSV Files (*.csv)")
        if self.file_path:
            try:
                with open(self.file_path, 'r') as f:
                    header_line = f.readline().strip()
                    all_columns = header_line.split(',')  
                    self.feature_names = all_columns[2:] 

                self.data = np.genfromtxt(self.file_path, delimiter=',', dtype=str, skip_header=1)
                if self.data.ndim == 1:
                    self.data = self.data.reshape(1, -1)
                self.dataFromINDEX2Col = self.data[:, 2:]

                formatted_data = "\n\n".join([f"Process {i+1}:\n" + ", ".join(row) for i, row in enumerate(self.dataFromINDEX2Col)])
                self.view.data_text_edit_ref.setText(formatted_data)
                self.view.process_button_ref.setVisible(True)
            except Exception as e:
                self.view.data_display_ref.setText(f"Error reading CSV file: {e}")
                self.view.process_button_ref.setVisible(False)

    def process_csv(self):
        if self.dataFromINDEX2Col is not None:
            try:
                self.predictions, binary_preds, labels = self.model.predict(self.dataFromINDEX2Col)
                benign_count = np.count_nonzero(binary_preds == 0)
                malicious_count = np.count_nonzero(binary_preds == 1)
                total_count = len(binary_preds)
                status = "Potential Malware Detected" if malicious_count > 0 else "Device Clean"

                template_path = os.path.join("templates", "scan_summary_template.html")
                template = load_template(template_path)

                result_message = template.format(
                    total_count=total_count,
                    benign_count=benign_count,
                    malicious_count=malicious_count,
                    status=status,
                    date_str=QDate.currentDate().toString(Qt.DateFormat.ISODate),
                    time_str=QTime.currentTime().toString(Qt.DateFormat.ISODate)
                    
                )

                self.view.data_display_ref.setText(result_message)
                self.view.tab_widget_ref.setVisible(True)

                try:
                    raw_X = self.dataFromINDEX2Col.astype(float)
                    X_scaled = self.model.scaler.transform(raw_X)
                    probabilities = self.model.model.predict(X_scaled)
                    binary_preds = (probabilities > 0.5).astype(int).flatten()
                    malicious_indices = np.where(binary_preds == 1)[0]

                    for idx in malicious_indices:
                        print(f"Explaining Process {idx+1}")
                        print("Raw values for process:", raw_X[idx])
                        sample = X_scaled[idx]

                        shap_text = generate_shap_explanation(
                            self.model.model,
                            X_scaled,
                            sample,
                            self.feature_names
                        )
                        self.view.append_shap_explanation(idx + 1, shap_text)
                        
                except Exception as e:
                    print(f"Error generating SHAP explanation: {e}")

                self.update_plots()

            except Exception as e:
                self.view.data_display_ref.setText(f"Error processing CSV file: {e}")

    def update_plots(self):
        self.view.confusion_graphics_scene_ref.clear()
        self.view.data_text_edit_ref.setText("\n\n".join([f"Process {i+1}:\n" + ", ".join(row) for i, row in enumerate(self.dataFromINDEX2Col)]))
        self.update_confusion_plot()
        self.update_misclassified_processes()

    def update_confusion_plot(self):
        pixmap = generate_confusion_matrix_pixmap(self.predictions, self.data)
        self.view.update_confusion_plot(pixmap)

    def update_misclassified_processes(self):
        true_labels = np.array([str(label).strip() for label in self.data[:, 0]])
        label_mapping = {"Benign": 0, "Malware": 1}
        y_test = np.array([label_mapping[label] for label in true_labels if label in label_mapping])
        y_pred = (self.predictions > 0.5).astype(int).flatten()

        misclassified_indices = np.where(y_test != y_pred)[0]
        if len(misclassified_indices) == 0:
            self.view.misclassified_text_edit_ref.setText("✅ No misclassified processes found.")
            return

        misclassified_text = ""
        for idx in misclassified_indices:
            process_number = idx + 1
            true_label = "Malware" if y_test[idx] == 1 else "Benign"
            pred_label = "Malware" if y_pred[idx] == 1 else "Benign"
            misclassified_text += f"Process {process_number}:\n  True Label: {true_label}, Predicted: {pred_label}\n"

        self.view.misclassified_text_edit_ref.setText(misclassified_text)
