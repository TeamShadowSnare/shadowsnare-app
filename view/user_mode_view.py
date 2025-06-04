from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel, QPushButton, QTextEdit, QTabWidget, QSplitter
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

        # Analysis Layout (hidden initially)
        self.analysis_splitter = QSplitter(Qt.Orientation.Horizontal)
        self.main_layout.addWidget(self.analysis_splitter)
        self.analysis_splitter.setVisible(False)

        # Left: Tabs
        self.left_widget = QWidget()
        self.left_layout = QVBoxLayout()
        self.left_widget.setLayout(self.left_layout)
        self.analysis_splitter.addWidget(self.left_widget)

        self.tab_widget = QTabWidget()
        self.left_layout.addWidget(self.tab_widget)

        self.data_tab = QWidget()
        self.explanation_tab = QWidget()

        self.tab_widget.addTab(self.data_tab, "Data")
        self.tab_widget.addTab(self.explanation_tab, "Explainability")

        self.data_layout = QVBoxLayout(self.data_tab)
        self.data_text_edit = QTextEdit()
        self.data_text_edit.setReadOnly(True)
        self.data_layout.addWidget(self.data_text_edit)

        self.explanation_layout = QVBoxLayout(self.explanation_tab)
        self.explanation_text_edit = QTextEdit()
        self.explanation_text_edit.setReadOnly(True)
        self.explanation_layout.addWidget(self.explanation_text_edit)

        # Right: Summary Panel
        self.right_widget = QWidget()
        self.right_layout = QVBoxLayout()
        self.right_widget.setLayout(self.right_layout)
        self.analysis_splitter.addWidget(self.right_widget)
        self.analysis_splitter.setStretchFactor(0, 3)  # Left panel (tabs)
        self.analysis_splitter.setStretchFactor(1, 2)  # Right panel (summary)

        self.right_widget.setMinimumWidth(600)
        self.right_widget.setMaximumWidth(600)

        self.data_display = QTextEdit()
        self.data_display.setReadOnly(True)
        self.data_display.setText("No file uploaded.")
        self.right_layout.addWidget(self.data_display)

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
        # Hide intro
        self.title.setVisible(False)
        self.instructions.setVisible(False)
        self.create_csv_button.setVisible(False)
        self.upload_csv_button.setVisible(False)
        self.continue_button.setVisible(False)
        # Show analysis view
        self.analysis_splitter.setVisible(True)
        self.analysis_splitter.setSizes([850, 600])
        self.analysis_splitter.setMinimumHeight(600)  # or try 800 for more height

    # Data display methods
    def show_summary(self, summary_html):
        self.data_display.setText(summary_html)

    def show_data(self, data_text):
        self.data_text_edit.setPlainText(data_text)

    def show_explanations(self, explanations_text):
        self.explanation_text_edit.setText(explanations_text)

    def append_shap_explanation(self, process_index: int, text: str):
        current = self.explanation_text_edit.toPlainText()
        new_text = f"🔍 Process {process_index} Explanation:\n{text}\n\n"
        self.explanation_text_edit.setPlainText(current + new_text)
