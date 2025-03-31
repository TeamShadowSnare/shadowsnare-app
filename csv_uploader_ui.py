from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QPushButton, QLabel, QFileDialog, QTextEdit, QHBoxLayout,
    QSpacerItem, QSizePolicy, QTabWidget, QGridLayout, QGraphicsView, QGraphicsScene, QSplitter
)
from PyQt6.QtCore import Qt, QRectF
from PyQt6.QtGui import QPixmap, QImage

class CSVUploaderUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Malware Process Detection")
        self.setGeometry(100, 100, 1200, 900)
        # Load the QSS file
        self.load_stylesheet("style.qss")

        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)

        self.main_layout = QVBoxLayout()
        self.central_widget.setLayout(self.main_layout)

        self.splitter = QSplitter(Qt.Orientation.Horizontal)
        self.main_layout.addWidget(self.splitter)

        self.left_widget = QWidget()
        self.left_layout = QVBoxLayout()
        self.left_widget.setLayout(self.left_layout)
        self.splitter.addWidget(self.left_widget)

        self.label = QLabel("Malware Detecting Process")
        self.left_layout.addWidget(self.label, alignment=Qt.AlignmentFlag.AlignCenter)

        self.upload_process_layout = QHBoxLayout()
        self.left_layout.addLayout(self.upload_process_layout)

        self.upload_button = QPushButton("Upload CSV")
        self.upload_button.setObjectName("upload_button")  # Set object name for QSS
        self.upload_process_layout.addWidget(self.upload_button)

        self.process_button = QPushButton("Process CSV")
        self.process_button.setObjectName("process_button")  # Set object name for QSS
        self.process_button.setVisible(False)
        self.upload_process_layout.addWidget(self.process_button)

        self.left_layout.addItem(QSpacerItem(20, 40, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding))

        self.tab_widget = QTabWidget()
        self.tab_widget.setMinimumSize(300, 300)
        self.left_layout.addWidget(self.tab_widget, 1)

        self.confusion_tab = QWidget()
        self.graph_tab = QWidget()
        self.data_tab = QWidget()

        self.tab_widget.addTab(self.confusion_tab, "Confusion Matrix")
        self.tab_widget.addTab(self.graph_tab, "Graph")
        self.tab_widget.addTab(self.data_tab, "Data")

        self.confusion_layout = QVBoxLayout(self.confusion_tab)
        self.graph_layout = QVBoxLayout(self.graph_tab)
        self.data_layout = QVBoxLayout(self.data_tab)

        self.confusion_graphics_view = QGraphicsView()
        self.confusion_graphics_scene = QGraphicsScene()
        self.confusion_graphics_view.setScene(self.confusion_graphics_scene)
        self.confusion_graphics_view.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.confusion_layout.addWidget(self.confusion_graphics_view)

        self.graph_graphics_view = QGraphicsView()
        self.graph_graphics_scene = QGraphicsScene()
        self.graph_graphics_view.setScene(self.graph_graphics_scene)
        self.graph_graphics_view.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.graph_layout.addWidget(self.graph_graphics_view)

        self.data_text_edit = QTextEdit()
        self.data_text_edit.setReadOnly(True)
        self.data_text_edit.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.data_layout.addWidget(self.data_text_edit)

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

        # Store references to UI elements that will be updated from the logic
        self.process_button_ref = self.process_button
        self.tab_widget_ref = self.tab_widget
        self.data_display_ref = self.data_display
        self.confusion_graphics_scene_ref = self.confusion_graphics_scene
        self.confusion_graphics_view_ref = self.confusion_graphics_view
        self.graph_graphics_scene_ref = self.graph_graphics_scene
        self.graph_graphics_view_ref = self.graph_graphics_view
        self.data_text_edit_ref = self.data_text_edit

        self.original_geometry = self.geometry()

    def setup_connections(self, controller):
        self.upload_button.clicked.connect(controller.upload_csv)
        self.process_button.clicked.connect(controller.process_csv)

    def update_confusion_plot(self, pixmap):
        self.confusion_graphics_scene_ref.clear()
        self.confusion_graphics_scene_ref.addPixmap(pixmap)
        self.confusion_graphics_view_ref.setSceneRect(QRectF(pixmap.rect()))
        self.confusion_graphics_view_ref.update()
        self.confusion_graphics_view_ref.viewport().update()

    def update_graph_plot(self, pixmap):
        self.graph_graphics_scene_ref.clear()
        self.graph_graphics_scene_ref.addPixmap(pixmap)
        self.graph_graphics_view_ref.setSceneRect(QRectF(pixmap.rect()))
        self.graph_graphics_view_ref.update()
        self.graph_graphics_view_ref.viewport().update()

    def load_stylesheet(self, file_name):
        try:
            with open(file_name, "r") as file:
                stylesheet = file.read()
                self.setStyleSheet(stylesheet)
        except Exception as e:
            print(f"Error loading stylesheet: {e}")