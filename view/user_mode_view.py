from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QPushButton, QTextEdit,
    QFileDialog, QDialog, QTextBrowser, QFrame, QTabWidget
)
from PyQt6.QtCore import Qt

class UserMode(QWidget):
    def __init__(self):
        super().__init__()

        # Paths
        self.memory_file_path = None
        self.output_directory = None

        # Layout
        self.main_layout = QVBoxLayout(self)
        self.main_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        self.main_layout.setSpacing(24)
        self.main_layout.setContentsMargins(50, 50, 50, 50)

        # Title
        self.title = QLabel("ShadowSnare")
        self.title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.title.setStyleSheet("font-size: 48px; font-weight: bold; color: #6dd5fa;")
        self.main_layout.addWidget(self.title)

        # Instructions
        self.instructions = QLabel("""
            <div style='text-align: center; color: white;'>
                <h2 style='font-size: 26px; color: #00bcd4;'>How to Use:</h2>
                <p style='font-size: 20px;'>
                1. Upload a memory dump file (.raw/.vmem).<br>
                2. Choose where to save the CSV.<br>
                3. Run analysis to detect malware.
                </p>
            </div>
        """)
        self.instructions.setWordWrap(True)
        self.main_layout.addWidget(self.instructions)

        # # Upload memory dump
        # self.upload_mem_button = QPushButton("📤 Upload memory dump file (.raw/.vmem)")
        # self.upload_mem_button.setStyleSheet(self._button_style("#8e44ad", "#9b59b6"))
        # self.main_layout.addWidget(self.upload_mem_button, alignment=Qt.AlignmentFlag.AlignCenter)

        # # Choose output directory
        # self.choose_dir_button = QPushButton("📁 Choose output directory")
        # self.choose_dir_button.setStyleSheet(self._button_style("#3498db", "#5dade2"))
        # self.main_layout.addWidget(self.choose_dir_button, alignment=Qt.AlignmentFlag.AlignCenter)

        # # Run analysis
        # self.run_button = QPushButton("🚀 Run Analysis")
        # self.run_button.setStyleSheet(self._button_style("#27ae60", "#52be80"))
        # self.run_button.setEnabled(False)
        # self.main_layout.addWidget(self.run_button, alignment=Qt.AlignmentFlag.AlignCenter)

        # Create Dump button
        self.create_dump_button = QPushButton("🧠 Create Memory Dump")
        self.create_dump_button.setStyleSheet(self._button_style("#16a085", "#1abc9c"))
        self.main_layout.addWidget(self.create_dump_button, alignment=Qt.AlignmentFlag.AlignCenter)

        # Extract CSV from memory file only
        self.extract_csv_button = QPushButton("📑 Extract Features to CSV")
        self.extract_csv_button.setStyleSheet(self._button_style("#d35400", "#e67e22"))
        self.main_layout.addWidget(self.extract_csv_button, alignment=Qt.AlignmentFlag.AlignCenter)

        self.upload_csv_button = QPushButton("📄 Upload and Analyze CSV")
        self.upload_csv_button.setStyleSheet(self._button_style("#f39c12", "#f1c40f"))
        self.main_layout.addWidget(self.upload_csv_button, alignment=Qt.AlignmentFlag.AlignCenter)

        # Results view
        self.analysis_widget = QWidget()
        self.analysis_layout = QVBoxLayout()
        self.analysis_widget.setLayout(self.analysis_layout)
        self.analysis_widget.setVisible(False)
        self.main_layout.addWidget(self.analysis_widget)

        # Summary output (top box)
        self.summary_container = QFrame()
        self.summary_layout = QVBoxLayout(self.summary_container)

        self.data_display = QTextBrowser()
        self.data_display.setReadOnly(True)

        # 👇 Add this:
        self.data_display.setOpenExternalLinks(False)
        self.data_display.anchorClicked.connect(self._handle_anchor_click)

        self.summary_layout.addWidget(self.data_display)
        self.analysis_layout.addWidget(self.summary_container)

        # SHAP explanation text (only for popup, NOT shown in main layout)
        self.explanation_text_edit = QTextEdit()
        self.explanation_text_edit.setReadOnly(True)

        # Raw CSV data text (optional — not shown in layout)
        self.data_text_edit = QTextEdit()
        self.data_text_edit.setReadOnly(True)

        # SHAP popup
        self.setup_explanation_popup()

    def _button_style(self, color, hover_color):
        return f"""
            QPushButton {{
                font-size: 20px;
                padding: 12px 28px;
                background-color: {color};
                color: white;
                border-radius: 8px;
            }}
            QPushButton:hover {{
                background-color: {hover_color};
            }}
        """

    def setup_connections(self, controller):
        # self.upload_mem_button.clicked.connect(controller.handle_upload_memory_file)
        # self.choose_dir_button.clicked.connect(controller.handle_choose_output_directory)
        # self.run_button.clicked.connect(controller.handle_run_analysis)
        self.create_dump_button.clicked.connect(controller.handle_create_dump)
        self.extract_csv_button.clicked.connect(controller.handle_raw_to_csv)
        self.upload_csv_button.clicked.connect(controller.handle_upload_csv_directly)


    def try_enable_run_button(self):
        if self.memory_file_path and self.output_directory:
            self.run_button.setEnabled(True)

    def show_result(self, html):
        self.analysis_widget.setVisible(True)
        self.data_display.setHtml(html)

    def setup_explanation_popup(self):
        self.explanation_dialog = QDialog(self)
        self.explanation_dialog.setWindowTitle("Explainability")
        self.explanation_dialog.setMinimumSize(600, 400)
        layout = QVBoxLayout(self.explanation_dialog)
        self.explanation_text_edit_popup = QTextEdit()
        self.explanation_text_edit_popup.setReadOnly(True)
        layout.addWidget(self.explanation_text_edit_popup)

    def show_explanation_popup(self):
        self.explanation_text_edit_popup.setPlainText(self.explanation_text_edit.toPlainText())
        self.explanation_dialog.exec()

    def append_shap_explanation(self, process_index: int, text: str):
        current = self.explanation_text_edit.toPlainText()
        new_text = f"🔍 Dump file {process_index} Explanation:\n{text}\n\n"
        self.explanation_text_edit.setPlainText(current + new_text)

    def _handle_anchor_click(self, link):
        print("✅ Anchor clicked:", link.toString())  # <-- add this line
        if link.toString() == "#":
            self.show_explanation_popup()
