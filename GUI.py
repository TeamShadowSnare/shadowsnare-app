import sys
import pandas as pd
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QPushButton, QLabel, QFileDialog, QTextEdit
)

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
        self.dataframe = None

    def upload_csv(self):
        file_dialog = QFileDialog()
        self.file_path, _ = file_dialog.getOpenFileName(self, "Open CSV File", "", "CSV Files (*.csv)")

        if self.file_path:
            self.label.setText(f"Uploaded File: {self.file_path}")
            try:
                self.dataframe = pd.read_csv(self.file_path)
                self.text_area.setText(self.dataframe.head().to_string(index=False))
                self.process_button.setEnabled(True)
            except Exception as e:
                self.text_area.setText(f"Error reading CSV file: {e}")
                self.process_button.setEnabled(False)
        else:
            self.label.setText("No file uploaded")

    def process_csv(self):
        if self.dataframe is not None:
            # Example operation: Adding a new column with row indices
            try:
                self.dataframe['Row Index'] = range(len(self.dataframe))
                self.text_area.setText(self.dataframe.head().to_string(index=False))
                self.label.setText("CSV processed: Added 'Row Index' column.")

                # Save the processed file (optional)
                output_path = self.file_path.replace(".csv", "_processed.csv")
                self.dataframe.to_csv(output_path, index=False)
                self.label.setText(f"Processed file saved as: {output_path}")

            except Exception as e:
                self.text_area.setText(f"Error processing CSV file: {e}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = CSVUploaderApp()
    window.show()
    sys.exit(app.exec())
