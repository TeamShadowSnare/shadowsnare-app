import sys
import joblib
from sklearn.preprocessing import MinMaxScaler
import numpy as np
from PyQt6.QtWidgets import QApplication, QFileDialog
from PyQt6.QtCore import Qt, QDate, QTime, QRectF
from PyQt6.QtGui import QPixmap, QImage
from tensorflow.keras.models import load_model
import os
import io
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import confusion_matrix, ConfusionMatrixDisplay
from PyQt6.QtGui import QPixmap, QImage
from csv_uploader_ui import CSVUploaderUI


model_path = os.path.join(os.getcwd(), "binary_classification_model.keras")

try:
    model = load_model(model_path)
except Exception as e:
    print(f"Error loading the model: {e}")
    model = None

class CSVUploaderApp(CSVUploaderUI):
    def __init__(self):
        super().__init__()
        self.file_path = None
        self.data = None
        self.predictions = None
        self.dataFromINDEX2Col = None
        self.setup_connections(self)

    def upload_csv(self):
        file_dialog = QFileDialog()
        self.file_path, _ = file_dialog.getOpenFileName(self, "Open CSV File", "", "CSV Files (*.csv)")

        if self.file_path:
            try:
                #NOTE: We assume that first row is headers, and is according to our convention
                #TODO: Add handling for improper CSV files.
                self.data = np.genfromtxt(self.file_path, delimiter=',', dtype=str, skip_header=1)
                if self.data.ndim == 1:
                    self.data = self.data.reshape(1, -1)  # Handle single row case
            
                self.dataFromINDEX2Col = self.data[:, 2:]

                formatted_data = "\n\n".join([f"Process {i+1}:\n" + ", ".join(row) for i, row in enumerate(self.dataFromINDEX2Col)])
                self.data_text_edit_ref.setText(formatted_data)
                self.process_button_ref.setVisible(True)

            except Exception as e:
                self.data_display_ref.setText(f"Error reading CSV file: {e}")
                self.process_button_ref.setVisible(False)

    def process_csv(self):
        if self.dataFromINDEX2Col is not None and model is not None:
            try:
                features = np.char.strip(self.dataFromINDEX2Col).astype(float)
                scaler = joblib.load("scaler.pkl")
                normalized_features = scaler.transform(features)
                self.predictions = model.predict(normalized_features)
                binary_predictions = (self.predictions > 0.5).astype(int).flatten()
                labels = np.where(binary_predictions == 1, "Malicious", "Benign")
                processed_data = np.column_stack((self.dataFromINDEX2Col, labels))
                
                benign_count = np.count_nonzero(binary_predictions == 0)
                malicious_count = np.count_nonzero(binary_predictions == 1)
                total_count = len(binary_predictions)
                status = "Potential Malware Detected" if malicious_count > 0 else "Device Clean"

                result_message = f"""
                    <div style='text-align: center; font-size: 22px; font-weight: bold; margin-bottom: 20px;'>Scan Results Summary:</div>

                    <div style='line-height: 1.8; font-size: 18px; margin-bottom: 45px;'>
                        - Total Processes Scanned: {total_count}<br>
                        - Benign Processes: {benign_count}<br>
                        - Malware Processes: <span style='color: red;'>{malicious_count}</span><br><br><br><br>

                        <span style='font-size: 22px;'>Device Status: </span>
                        <span style='color: red;'>{status}</span> ({malicious_count} out of {total_count} processes flagged as malicious).
                    </div>

                    <br><br><br><br><br><br><br><br> """

                date_str = QDate.currentDate().toString(Qt.DateFormat.ISODate)
                time_str = QTime.currentTime().toString(Qt.DateFormat.ISODate)
                datetime_str = f"""
                    <div style='position: absolute; right: 10px; font-size: 16px; text-align: right;'>
                        Scan Date: {date_str} {time_str}
                    </div>
                """

                self.data_display_ref.setText(f"{result_message}{datetime_str}")

                self.tab_widget_ref.setVisible(True)
                self.update_plots()

            except Exception as e:
                self.data_display_ref.setText(f"Error processing CSV file: {e}")
                print("ERROR IS: ", e)
        elif model is None:
            self.data_display_ref.setText("Error: Model not loaded. Please ensure 'binary_classification_model.keras' is in the correct location.")

    def update_plots(self):
        self.confusion_graphics_scene_ref.clear()
        self.graph_graphics_scene_ref.clear()
        self.data_text_edit_ref.setText("\n\n".join([f"Process {i+1}:\n" + ", ".join(row) for i, row in enumerate(self.dataFromINDEX2Col)]))

        self.update_confusion_plot()
        self.update_graph_plot()


    def update_confusion_plot(self):
        if self.predictions is not None:
            pixmap = self.generate_confusion_matrix_plot()
            self.update_confusion_plot_in_ui(pixmap)

    def update_confusion_plot_in_ui(self, pixmap):
        self.confusion_graphics_scene_ref.clear()
        self.confusion_graphics_scene_ref.addPixmap(pixmap)
        self.confusion_graphics_view_ref.setSceneRect(QRectF(pixmap.rect()))
        self.confusion_graphics_view_ref.update()
        self.confusion_graphics_view_ref.viewport().update()

    def update_graph_plot(self):
        if self.predictions is not None:
            pixmap = self.generate_graph_plot()
            self.update_graph_plot_in_ui(pixmap)

    def update_graph_plot_in_ui(self, pixmap):
        self.graph_graphics_scene_ref.clear()
        self.graph_graphics_scene_ref.addPixmap(pixmap)
        self.graph_graphics_view_ref.setSceneRect(QRectF(pixmap.rect()))
        self.graph_graphics_view_ref.update()
        self.graph_graphics_view_ref.viewport().update()




    def generate_confusion_matrix_plot(self):
        if self.predictions is not None and self.data is not None:
            true_labels = np.array([str(label).strip() for label in self.data[:, 0]])
 
            label_mapping = {"Benign": 0, "Malware": 1}
            
            # Filter out unknown labels to avoid errors
            y_test = np.array([label_mapping[label] for label in true_labels if label in label_mapping])

            y_pred = (self.predictions > 0.5).astype(int)

            if len(y_test) != len(y_pred):
                raise ValueError(f"Mismatch in label lengths: y_test={len(y_test)}, y_pred={len(y_pred)}")

            cm = confusion_matrix(y_test, y_pred, labels=[0, 1])
            display_labels = ["Benign", "Malicious"]
            # Display confusion matrix
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





    def generate_graph_plot(self):
        if self.predictions is not None:
            plt.figure(figsize=(9, 5))
            sns.histplot(self.predictions, bins=20, color='#e74c3c', kde=True)
            plt.title("Prediction Distribution", fontsize=16)
            plt.xlabel("Prediction Probability", fontsize=14)
            plt.ylabel("Frequency", fontsize=14)
            buf = io.BytesIO()
            plt.savefig(buf, format='png')
            plt.close()
            buf.seek(0)
            image = QImage.fromData(buf.getvalue())
            return QPixmap.fromImage(image)
        return QPixmap() # Return an empty QPixmap if predictions are None


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = CSVUploaderApp()
    window.show()
    sys.exit(app.exec())