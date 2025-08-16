from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QPushButton, QTextEdit,
    QDialog, QTextBrowser, QFrame, QHBoxLayout
)
from PyQt6.QtCore import Qt

class UserMode(QWidget):
    def __init__(self):
        super().__init__()

        self.memory_file_path = None
        self.output_directory = None

        self.main_layout = QVBoxLayout(self)
        self.main_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        self.main_layout.setSpacing(24)
        self.main_layout.setContentsMargins(50, 50, 50, 50)

        self.arrow_labels = []


        self.instructions = QLabel(
    """
    <div style='text-align:center; color:white;'>
        <h2 style='font-size:26px; color:#6dd5fa; margin-bottom:30px;'>How to Use:</h2>
        <p style="font-size:20px; color:white; line-height:2;">
           1. <strong>Create a memory-dump file (.raw/.vmem) — requires Administrator privileges.</strong><br>
           2. <strong>Extract features to a CSV file.</strong><br>
           3. <strong>Run analysis to detect malware.</strong>
        </p>
    </div>
    """
)
        self.instructions.setWordWrap(True)
        self.main_layout.addWidget(self.instructions)


        self.create_dump_button = QPushButton("🧠 Create Memory Dump")

        self.create_dump_button.setStyleSheet(self._button_style("#3c5060", "#536b7d"))

        self.extract_csv_button = QPushButton("📑 Extract Features to CSV")
        self.extract_csv_button.setStyleSheet(self._button_style("#3c5060", "#536b7d"))

        self.upload_csv_button = QPushButton("📄 Upload and Analyze CSV")
        self.upload_csv_button.setStyleSheet(self._button_style("#3c5060", "#536b7d"))

        row = QHBoxLayout()
        row.setSpacing(16)
        row.setAlignment(Qt.AlignmentFlag.AlignCenter)

        def add_flow_button(btn, is_last=False):
            row.addWidget(btn)
            if not is_last:
                arrow = QLabel("➜")
                arrow.setStyleSheet("font-size:32px; color:#6dd5fa;")
                arrow.setAlignment(Qt.AlignmentFlag.AlignCenter)
                row.addWidget(arrow)
                self.arrow_labels.append(arrow)  

        add_flow_button(self.create_dump_button)
        add_flow_button(self.extract_csv_button)
        add_flow_button(self.upload_csv_button, is_last=True)

        self.main_layout.addLayout(row)

        self.analysis_widget = QWidget()
        self.analysis_layout = QVBoxLayout()
        self.analysis_widget.setLayout(self.analysis_layout)
        self.analysis_widget.setVisible(False)
        self.main_layout.addWidget(self.analysis_widget)

        self.summary_container = QFrame()
        self.summary_layout = QVBoxLayout(self.summary_container)

        self.data_display = QTextBrowser()
        self.data_display.setReadOnly(True)

        self.data_display.setOpenExternalLinks(False)
        self.data_display.anchorClicked.connect(self._handle_anchor_click)

        self.summary_layout.addWidget(self.data_display)
        self.analysis_layout.addWidget(self.summary_container)

        self.explanation_text_edit = QTextEdit()
        self.explanation_text_edit.setReadOnly(True)

        self.data_text_edit = QTextEdit()
        self.data_text_edit.setReadOnly(True)

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
        self.create_dump_button.clicked.connect(controller.handle_create_dump)
        self.extract_csv_button.clicked.connect(controller.handle_raw_to_csv)
        self.upload_csv_button.clicked.connect(controller.handle_analyze_csv)


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
        print("✅ Anchor clicked:", link.toString()) 
        if link.toString() == "#":
            self.show_explanation_popup()
