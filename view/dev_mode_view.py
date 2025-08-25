"""
Dev Mode view (PyQt6).
Left pane: actions (Upload/Process) + result tabs (Confusion/Data/Misclassified/Explainability).
Right pane: read-only summary panel. Pure UI; no business logic.
"""


from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QPushButton, QLabel, QTextEdit, QHBoxLayout,
    QSpacerItem, QSizePolicy, QTabWidget, QGraphicsView, QGraphicsScene, QSplitter
)
from PyQt6.QtCore import Qt, QRectF

class devMode(QWidget):
    """Compact UI for the developer CSV workflow."""
    def __init__(self):
        super().__init__()

        # Root layout + horizontal split (left workflow | right summary)
        self.main_layout = QVBoxLayout()
        self.setLayout(self.main_layout)
        self.splitter = QSplitter(Qt.Orientation.Horizontal)
        self.main_layout.addWidget(self.splitter)

        # ---------- Left: actions + tabs ----------
        self.left_widget = QWidget()
        self.left_layout = QVBoxLayout()
        self.left_widget.setLayout(self.left_layout)
        self.splitter.addWidget(self.left_widget)

        # Title
        self.label = QLabel("Malware Dump File Detection")
        self.left_layout.addWidget(self.label, alignment=Qt.AlignmentFlag.AlignCenter)

        # Action row (Upload / Process)
        self.upload_process_layout = QHBoxLayout()
        self.left_layout.addLayout(self.upload_process_layout)

        # Upload CSV button
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

        # Process CSV button (hidden until a file is loaded)
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

        # Spacer before tabs
        self.left_layout.addItem(QSpacerItem(20, 40, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding))

        # Results tabs (hidden until results are ready)
        self.tab_widget = QTabWidget()
        self.tab_widget.setMinimumSize(300, 300)
        self.left_layout.addWidget(self.tab_widget, 1)

        # Tabs
        self.confusion_tab = QWidget()
        self.data_tab = QWidget()
        self.misclassified_tab = QWidget()
        self.explanation_tab = QWidget()

        self.tab_widget.addTab(self.confusion_tab, "Confusion Matrix")
        self.tab_widget.addTab(self.data_tab, "Data")
        self.tab_widget.addTab(self.misclassified_tab, "Misclassified")
        self.tab_widget.addTab(self.explanation_tab, "Explainability")

        # Confusion Matrix tab content
        self.confusion_layout = QVBoxLayout(self.confusion_tab)
        self.confusion_graphics_view = QGraphicsView()
        self.confusion_graphics_scene = QGraphicsScene()
        self.confusion_graphics_view.setScene(self.confusion_graphics_scene)
        self.confusion_layout.addWidget(self.confusion_graphics_view)

        # Data tab content
        self.data_layout = QVBoxLayout(self.data_tab)
        self.data_text_edit = QTextEdit()
        self.data_text_edit.setReadOnly(True)
        self.data_layout.addWidget(self.data_text_edit)

        # Misclassified tab content
        self.misclassified_layout = QVBoxLayout(self.misclassified_tab)
        self.misclassified_text_edit = QTextEdit()
        self.misclassified_text_edit.setReadOnly(True)
        self.misclassified_layout.addWidget(self.misclassified_text_edit)

        # Explainability tab content
        self.explanation_layout = QVBoxLayout(self.explanation_tab)
        self.explanation_text_edit = QTextEdit()
        self.explanation_text_edit.setReadOnly(True)
        self.explanation_layout.addWidget(self.explanation_text_edit)

        self.tab_widget.setVisible(False) # hide tabs until processing

        # ---------- Right: summary panel ----------
        self.right_widget = QWidget()
        self.right_layout = QVBoxLayout()
        self.right_widget.setLayout(self.right_layout) # keep explicit setLayout
        self.splitter.addWidget(self.right_widget)
        self.right_widget.setMinimumWidth(600)
        self.right_widget.setMaximumWidth(600)

        self.data_display = QTextEdit() # accepts setText/setHtml
        self.data_display.setReadOnly(True)
        self.right_layout.addWidget(self.data_display)
        self.data_display.setText("No file uploaded.")

    def setup_connections(self, controller):
        """Connect buttons to controller slots (no business logic here)."""
        self.upload_button.clicked.connect(controller.upload_csv)
        self.process_button.clicked.connect(controller.process_csv)

    def show_data_preview(self, data):
        """Render a compact CSV preview (columns from index 2 onward) and enable 'Process'."""
        text = "\n\n".join([f"Dump file {i+1}:\n" + ", ".join(row) for i, row in enumerate(data[:, 2:])])
        self.data_text_edit.setText(text)
        self.process_button.setVisible(True)

    def show_summary(self, summary_html):
        """Show HTML summary on the right and reveal tabs."""
        self.tab_widget.setVisible(True)
        self.data_display.setText(summary_html)

    def show_explanations(self, explanations_text):
        """Fill the Explainability tab."""
        self.explanation_text_edit.setText(explanations_text)

    def update_confusion_plot(self, pixmap):
        """Replace the confusion matrix image."""
        self.confusion_graphics_scene.clear()
        self.confusion_graphics_scene.addPixmap(pixmap)
        self.confusion_graphics_view.setSceneRect(QRectF(pixmap.rect()))
        self.confusion_graphics_view.update()
        self.confusion_graphics_view.viewport().update()

    def show_misclassified(self, text):
        """List misclassified rows."""
        self.misclassified_text_edit.setText(text)

    def show_error(self, message):
        """Display an error in the summary panel."""
        self.data_display.setText(f"❌ {message}")

    def show_message(self, message):
        """Display a neutral message in the summary panel."""
        self.data_display.setText(message)

    def append_shap_explanation(self, process_index: int, text: str):
        """Append one SHAP explanation block (1-based index for display)."""
        current = self.explanation_text_edit.toPlainText()
        new_text = f"🔍 Dump file {process_index} Explanation:\n{text}\n\n"
        self.explanation_text_edit.setPlainText(current + new_text)

