from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QPushButton, QLabel, QTextEdit, QHBoxLayout,
    QSpacerItem, QSizePolicy, QTabWidget, QGraphicsView, QGraphicsScene, QSplitter
)
from PyQt6.QtCore import Qt, QRectF

class devMode(QWidget):
    def __init__(self):
        super().__init__()

        self.main_layout = QVBoxLayout()
        self.setLayout(self.main_layout)

        self.splitter = QSplitter(Qt.Orientation.Horizontal)
        self.main_layout.addWidget(self.splitter)

        # Left panel
        self.left_widget = QWidget()
        self.left_layout = QVBoxLayout()
        self.left_widget.setLayout(self.left_layout)
        self.splitter.addWidget(self.left_widget)

        self.label = QLabel("Malware Dump File Detection")
        self.left_layout.addWidget(self.label, alignment=Qt.AlignmentFlag.AlignCenter)

        self.upload_process_layout = QHBoxLayout()
        self.left_layout.addLayout(self.upload_process_layout)

        self.upload_button = QPushButton("Upload CSV")
        self.upload_button.setStyleSheet("""
            QPushButton {
                background-color: #3498db;   /* Blue */
                color: white;
                font-size: 18px;
                border-radius: 8px;
                padding: 8px 20px;
            }
            QPushButton:hover {
                background-color: #217dbb;   /* Darker blue */
            }
        """)
        self.upload_process_layout.addWidget(self.upload_button)

        self.process_button = QPushButton("Process CSV")
        self.process_button.setVisible(False)
        self.process_button.setStyleSheet("""
            QPushButton {
                background-color: #e74c3c;   /* Red */
                color: white;
                font-size: 18px;
                border-radius: 8px;
                padding: 8px 20px;
            }
            QPushButton:hover {
                background-color: #c0392b;   /* Darker red */
            }
        """)
        self.upload_process_layout.addWidget(self.process_button)

        self.left_layout.addItem(QSpacerItem(20, 40, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding))

        self.tab_widget = QTabWidget()
        self.tab_widget.setMinimumSize(300, 300)
        self.left_layout.addWidget(self.tab_widget, 1)

        self.confusion_tab = QWidget()
        self.data_tab = QWidget()
        self.misclassified_tab = QWidget()
        self.explanation_tab = QWidget()

        self.tab_widget.addTab(self.confusion_tab, "Confusion Matrix")
        self.tab_widget.addTab(self.data_tab, "Data")
        self.tab_widget.addTab(self.misclassified_tab, "Misclassified")
        self.tab_widget.addTab(self.explanation_tab, "Explainability")

        self.confusion_layout = QVBoxLayout(self.confusion_tab)
        self.confusion_graphics_view = QGraphicsView()
        self.confusion_graphics_scene = QGraphicsScene()
        self.confusion_graphics_view.setScene(self.confusion_graphics_scene)
        self.confusion_layout.addWidget(self.confusion_graphics_view)

        self.data_layout = QVBoxLayout(self.data_tab)
        self.data_text_edit = QTextEdit()
        self.data_text_edit.setReadOnly(True)
        self.data_layout.addWidget(self.data_text_edit)

        self.misclassified_layout = QVBoxLayout(self.misclassified_tab)
        self.misclassified_text_edit = QTextEdit()
        self.misclassified_text_edit.setReadOnly(True)
        self.misclassified_layout.addWidget(self.misclassified_text_edit)

        self.explanation_layout = QVBoxLayout(self.explanation_tab)
        self.explanation_text_edit = QTextEdit()
        self.explanation_text_edit.setReadOnly(True)
        self.explanation_layout.addWidget(self.explanation_text_edit)

        self.tab_widget.setVisible(False)

        # Right panel
        self.right_widget = QWidget()
        self.right_layout = QVBoxLayout()
        self.right_widget.setLayout(self.right_layout)
        self.splitter.addWidget(self.right_widget)
        self.right_widget.setMinimumWidth(600)
        self.right_widget.setMaximumWidth(600)

        self.data_display = QTextEdit()
        self.data_display.setReadOnly(True)
        self.right_layout.addWidget(self.data_display)
        self.data_display.setText("No file uploaded.")

    def setup_connections(self, controller):
        self.upload_button.clicked.connect(controller.upload_csv)
        self.process_button.clicked.connect(controller.process_csv)

    # New view methods for the refactored controller
    def show_data_preview(self, data):
        text = "\n\n".join([f"Dump file {i+1}:\n" + ", ".join(row) for i, row in enumerate(data[:, 2:])])
        self.data_text_edit.setText(text)
        self.process_button.setVisible(True)

    def show_summary(self, summary_html):
        self.tab_widget.setVisible(True)
        self.data_display.setText(summary_html)

    def show_explanations(self, explanations_text):
        self.explanation_text_edit.setText(explanations_text)

    def update_confusion_plot(self, pixmap):
        self.confusion_graphics_scene.clear()
        self.confusion_graphics_scene.addPixmap(pixmap)
        self.confusion_graphics_view.setSceneRect(QRectF(pixmap.rect()))
        self.confusion_graphics_view.update()
        self.confusion_graphics_view.viewport().update()

    def show_misclassified(self, text):
        self.misclassified_text_edit.setText(text)

    def show_error(self, message):
        self.data_display.setText(f"❌ {message}")

    def show_message(self, message):
        self.data_display.setText(message)

    def append_shap_explanation(self, process_index: int, text: str):
        current = self.explanation_text_edit.toPlainText()
        new_text = f"🔍 Dump file {process_index} Explanation:\n{text}\n\n"
        self.explanation_text_edit.setPlainText(current + new_text)

