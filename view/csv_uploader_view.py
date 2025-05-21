from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QPushButton, QLabel, QTextEdit, QHBoxLayout,
    QSpacerItem, QSizePolicy, QTabWidget, QGraphicsView, QGraphicsScene, QSplitter
)
from PyQt6.QtCore import Qt, QRectF

class CSVUploaderView(QWidget):
    def __init__(self):
        super().__init__()

        self.main_layout = QVBoxLayout()
        self.setLayout(self.main_layout)

        self.splitter = QSplitter(Qt.Orientation.Horizontal)
        self.main_layout.addWidget(self.splitter)

        self.left_widget = QWidget()
        self.left_layout = QVBoxLayout()
        self.left_widget.setLayout(self.left_layout)
        self.splitter.addWidget(self.left_widget)

        self.label = QLabel("Malware Process Detection")
        self.left_layout.addWidget(self.label, alignment=Qt.AlignmentFlag.AlignCenter)

        self.upload_process_layout = QHBoxLayout()
        self.left_layout.addLayout(self.upload_process_layout)

        self.upload_button = QPushButton("Upload CSV")
        self.upload_button.setObjectName("upload_button")
        self.upload_process_layout.addWidget(self.upload_button)

        self.process_button = QPushButton("Process CSV")
        self.process_button.setObjectName("process_button")
        self.process_button.setVisible(False)
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
        self.tab_widget.addTab(self.misclassified_tab, "Misclassified Processes")
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

        self.tab_widget.setVisible(False)
        self.left_layout.addStretch()

        self.right_widget = QWidget()
        self.right_layout = QVBoxLayout()
        self.right_widget.setLayout(self.right_layout)
        self.splitter.addWidget(self.right_widget)
        self.right_widget.setMinimumWidth(600)
        self.right_widget.setMaximumWidth(600)

        self.data_display = QTextEdit()
        self.data_display.setReadOnly(True)
        self.right_layout.addWidget(self.data_display)
        self.data_display.setText("No file uploaded")

  # 👉 SHAP Explanation section
        self.explanation_layout = QVBoxLayout(self.explanation_tab)

        self.explanation_text = QTextEdit()
        self.explanation_text.setReadOnly(True)
        self.explanation_layout.addWidget(self.explanation_text)
      
        self.process_button_ref = self.process_button
        self.tab_widget_ref = self.tab_widget
        self.data_display_ref = self.data_display
        self.confusion_graphics_scene_ref = self.confusion_graphics_scene
        self.confusion_graphics_view_ref = self.confusion_graphics_view
        self.data_text_edit_ref = self.data_text_edit
        self.misclassified_text_edit_ref = self.misclassified_text_edit

    def setup_connections(self, controller):
        self.upload_button.clicked.connect(controller.upload_csv)
        self.process_button.clicked.connect(controller.process_csv)

    def update_confusion_plot(self, pixmap):
        self.confusion_graphics_scene_ref.clear()
        self.confusion_graphics_scene_ref.addPixmap(pixmap)
        self.confusion_graphics_view_ref.setSceneRect(QRectF(pixmap.rect()))
        self.confusion_graphics_view_ref.update()
        self.confusion_graphics_view_ref.viewport().update()

    def update_shap_explanation(self, pixmap, explanation):
        self.explanation_graphics_scene.clear()
        self.explanation_graphics_scene.addPixmap(pixmap)
        self.explanation_graphics_view.setSceneRect(QRectF(pixmap.rect()))
        self.explanation_graphics_view.update()
        self.explanation_graphics_view.viewport().update()
        self.explanation_text.setPlainText(explanation)


    def append_shap_explanation(self, process_number, pixmap, explanation):
        header = f"🔍 Process {process_number} - Explanation:\n"
        separator = "-" * 60 + "\n"

        # Append explanation text
        existing_text = self.explanation_text.toPlainText()
        new_text = f"{existing_text}\n{header}{explanation}\n{separator}"
        self.explanation_text.setPlainText(new_text)