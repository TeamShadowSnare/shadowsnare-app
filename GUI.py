import sys
import joblib
from sklearn.preprocessing import MinMaxScaler
import numpy as np
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QPushButton, QLabel, QFileDialog, QTextEdit
)
import os
from tensorflow.keras.models import load_model

# Construct the path in a cross-platform way
model_path = os.path.join(os.getcwd(), "binary_classification_model.keras")

# Load the model
model = load_model(model_path)

class CSVUploaderApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CSV Uploader")
        self.setGeometry(100, 100, 600, 400)

        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)

        self.layout = QVBoxLayout()
        self.central_widget.setLayout(self.layout)

        self.label = QLabel("No file uploaded")
        self.layout.addWidget(self.label)

        self.upload_button = QPushButton("Upload CSV")
        self.upload_button.clicked.connect(self.upload_csv)
        self.layout.addWidget(self.upload_button)

        self.text_area = QTextEdit()
        self.text_area.setReadOnly(True)
        self.layout.addWidget(self.text_area)

        self.process_button = QPushButton("Process CSV")
        self.process_button.clicked.connect(self.process_csv)
        self.process_button.setEnabled(False)
        self.layout.addWidget(self.process_button)

        self.file_path = None
        self.data = None

    def upload_csv(self):
        file_dialog = QFileDialog()
        self.file_path, _ = file_dialog.getOpenFileName(self, "Open CSV File", "", "CSV Files (*.csv)")

        if self.file_path:
            self.label.setText(f"Uploaded File: {self.file_path}")
            try:
                # Read CSV as strings using NumPy
                self.data = np.genfromtxt(self.file_path, delimiter=',', dtype=str)
                
                # Remove the first row (header) and first two columns
                self.data = self.data[1:, 2:]
                # Display the first few rows
                self.text_area.setText("\n".join([", ".join(row) for row in self.data[:5]]))
                self.process_button.setEnabled(True)
            except Exception as e:
                self.text_area.setText(f"Error reading CSV file: {e}")
                self.process_button.setEnabled(False)
        else:
            self.label.setText("No file uploaded")


    def process_csv(self):
        if self.data is not None:
            try:
                # Convert to float (strip whitespace first)
                features = np.char.strip(self.data).astype(float)

                # Load the pre-trained scaler
                scaler = joblib.load("scaler.pkl")

                # Normalize using the same scaler
                normalized_features = scaler.transform(features)

                # Predict using the model
                predictions = model.predict(normalized_features)

                # Convert probabilities to binary labels
                binary_predictions = (predictions > 0.5).astype(int).flatten()

                # Map predictions to labels
                labels = np.where(binary_predictions == 1, "Malicious", "Benign")

                # Combine with original data
                processed_data = np.column_stack((self.data, labels))

                # Format text output more clearly
                formatted_output = "\n".join(["\t".join(row) for row in processed_data])  # Show first 10 rows

                # Display in the GUI
                self.text_area.setText(f"Predictions:\n{formatted_output}")
                self.label.setText("CSV processed: Predictions added.")

                # Save output file
                output_path = self.file_path.replace(".csv", "_predictions.csv")
                np.savetxt(output_path, processed_data, delimiter=',', fmt='%s')
                self.label.setText(f"Processed file saved as: {output_path}")

            except Exception as e:
                self.text_area.setText(f"Error processing CSV file: {e}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = CSVUploaderApp()
    window.show()
    sys.exit(app.exec())
