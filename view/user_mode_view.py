from PyQt6.QtWidgets import QFrame, QTextEdit , QWidget, QDialog, QVBoxLayout, QLabel, QPushButton, QTextBrowser, QTabWidget, QSplitter
from PyQt6.QtCore import Qt, QRectF

class UserMode(QWidget):
    def __init__(self):
        super().__init__()

        self.main_layout = QVBoxLayout(self)
        self.main_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        self.main_layout.setSpacing(24)
        self.main_layout.setContentsMargins(50, 50, 50, 50)

        # Intro title
        self.title = QLabel("ShadowSnare")
        self.title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.title.setStyleSheet("""
            font-size: 48px;
            font-weight: bold;
            color: #6dd5fa;
            letter-spacing: 1.5px;
        """)
        self.main_layout.addWidget(self.title)

        # Instructions
        self.instructions = QLabel("""
            <div style="text-align: center; color: white;">
                <h2 style="font-size: 26px; color: #00bcd4; margin-bottom: 12px;">How to Use:</h2>
                <p style="font-size: 20px; line-height: 1.8; margin: 0;">
                1. <b>Click the button below</b> to create a CSV file.<br>
                2. <b>Upload the CSV file</b> when ready.<br>
                3. <b>Click 'Continue to Analyze'</b> to view results.
                </p>
            </div>
        """)
        self.instructions.setWordWrap(True)
        self.main_layout.addWidget(self.instructions)

        # Buttons
        self.create_csv_button = QPushButton("📄 Create CSV File")
        self.create_csv_button.setStyleSheet(self._button_style("#2196f3", "#42a5f5"))
        self.main_layout.addWidget(self.create_csv_button, alignment=Qt.AlignmentFlag.AlignCenter)

        self.upload_csv_button = QPushButton("📂 Upload CSV File")
        self.upload_csv_button.setStyleSheet(self._button_style("#f39c12", "#f5b041"))
        self.upload_csv_button.setVisible(False)
        self.main_layout.addWidget(self.upload_csv_button, alignment=Qt.AlignmentFlag.AlignCenter)

        self.continue_button = QPushButton("🚀 Continue to Analyze")
        self.continue_button.setStyleSheet(self._button_style("#4caf50", "#66bb6a"))
        self.continue_button.setVisible(False)
        self.main_layout.addWidget(self.continue_button, alignment=Qt.AlignmentFlag.AlignCenter)

        # ✅ REPLACE with just the right widget directly:
        self.analysis_widget = QWidget()
        self.analysis_layout = QVBoxLayout()
        self.analysis_widget.setLayout(self.analysis_layout)
        self.analysis_widget.setVisible(False)
        self.main_layout.addWidget(self.analysis_widget)

        # 📋 Summary
        self.summary_container = QFrame()
        self.summary_layout = QVBoxLayout(self.summary_container)
        self.summary_layout.setContentsMargins(0, 0, 0, 0)

        # 📊 Explanation: no button — just a clickable text link in HTML
        self.data_display = QTextBrowser()
        self.data_display.setReadOnly(True)
        self.data_display.setOpenExternalLinks(False)  # Required to detect clicks
        self.data_display.setAcceptRichText(True)
        self.data_display.anchorClicked.connect(lambda _: self.show_explanation_popup())
        self.summary_layout.addWidget(self.data_display)

        self.analysis_layout.addWidget(self.summary_container)

        self.explanation_text_edit = QTextEdit()
        self.explanation_text_edit.setReadOnly(True)


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
        self.create_csv_button.clicked.connect(controller.handle_create_csv)
        self.upload_csv_button.clicked.connect(controller.handle_upload_csv)
        self.continue_button.clicked.connect(controller.handle_analyze_file)

    def show_analysis_layout(self):
        self.title.setVisible(False)
        self.instructions.setVisible(False)
        self.create_csv_button.setVisible(False)
        self.upload_csv_button.setVisible(False)
        self.continue_button.setVisible(False)

        self.analysis_widget.setVisible(True)

    def show_summary(self, summary_html):
        full_html = summary_html + "<br><a href='#'> Click here for explanation</a>"
        self.data_display.setHtml(full_html)


    def show_explanations(self, explanations_text):
        self.explanation_text_edit.setText(explanations_text)

    def append_shap_explanation(self, process_index: int, text: str):
        current = self.explanation_text_edit.toPlainText()
        new_text = f"🔍 Process {process_index} Explanation:\n{text}\n\n"
        self.explanation_text_edit.setPlainText(current + new_text)


    def setup_explanation_popup(self):
        self.explanation_dialog = QDialog(self)
        self.explanation_dialog.setWindowTitle("Explainability")
        self.explanation_dialog.setMinimumSize(600, 400)

        self.explanation_popup_layout = QVBoxLayout(self.explanation_dialog)
        self.explanation_text_edit_popup = QTextEdit()
        self.explanation_text_edit_popup.setReadOnly(True)
        self.explanation_popup_layout.addWidget(self.explanation_text_edit_popup)

    def show_explanation_popup(self):
        self.explanation_text_edit_popup.setPlainText(self.explanation_text_edit.toPlainText())
        self.explanation_dialog.exec()
