"""
Settings view (PyQt6).
Lets the user set default directories for: dump, CSV, and analysis.
Uses QSettings("ShadowSnare", "Paths") to persist values.
Pure UI/presentation; no business logic.
"""


from PyQt6.QtCore import QSettings, Qt
from PyQt6.QtWidgets import (
    QWidget, QLineEdit, QPushButton, QFileDialog,
    QHBoxLayout, QVBoxLayout, QMessageBox, QLabel, QSizePolicy, QApplication
)

class SettingsView(QWidget):
    """Form to edit and save default paths used by the app."""
    def __init__(self):
        """Build the form UI and load existing settings into the fields."""
        super().__init__()

        # Persistent store under HKCU (Windows) or platform equivalent
        self.config = QSettings("ShadowSnare", "Paths")

        # Title
        title = QLabel("Settings")
        title.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        title.setStyleSheet("font-size: 32px; font-weight: 700; color: #f1f1f1;")

        # Inputs prefilled from QSettings (empty string if none)
        self.dump_edit     = self._edit(self.config.value("dump_path", ""))
        self.csv_edit      = self._edit(self.config.value("csv_path", ""))
        self.analysis_edit = self._edit(self.config.value("analysis_path", ""))

        # Hints
        self.dump_edit.setPlaceholderText("Enter dump directory path")
        self.csv_edit.setPlaceholderText("Enter CSV directory path")
        self.analysis_edit.setPlaceholderText("Enter analysis directory path")

        def styled_label(text):
            """Small helper for consistent label style (kept local to __init__)."""
            label = QLabel(text)
            label.setStyleSheet("font-size: 22px; color: #f1f1f1;")
            return label

        # Main form layout (stack of labeled rows)
        form_layout = QVBoxLayout()
        form_layout.setSpacing(16)

        form_layout.addLayout(self._labeled_row("Default dump directory to save the memory file:", self.dump_edit))
        form_layout.addLayout(self._labeled_row("Default CSV directory to save the extracted features:", self.csv_edit))
        form_layout.addLayout(self._labeled_row("Default analysis directory where the suspect CSV file is located:", self.analysis_edit))
        
        # Save button
        save_btn = QPushButton("💾  Save")
        save_btn.setFixedWidth(160)
        save_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        save_btn.setStyleSheet("""
            QPushButton {
                font-size: 18px;
                padding: 10px 20px;
                background-color: #3c5060;
                color: #f1f1f1;
                border-radius: 6px;
            }
            QPushButton:hover { background-color: #536b7d; }
        """)
        save_btn.clicked.connect(self._save)

         # Outer centering wrapper
        outer_wrapper = QVBoxLayout(self)
        outer_wrapper.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignHCenter)
        outer_wrapper.setContentsMargins(0, 40, 0, 40)
        outer_wrapper.setSpacing(30)

        # Inner container (fixes max width and padding)
        container = QWidget()
        container.setMaximumWidth(1200)
        inner_layout = QVBoxLayout(container)
        inner_layout.setSpacing(30)
        inner_layout.setContentsMargins(50, 0, 50, 0)

        inner_layout.addWidget(title)
        inner_layout.addLayout(form_layout)
        inner_layout.addStretch()
        inner_layout.addWidget(save_btn, 0, Qt.AlignmentFlag.AlignHCenter)

        outer_wrapper.addWidget(container)

    def _edit(self, text: str) -> QLineEdit:
        """Create a styled QLineEdit with default text."""
        edit = QLineEdit(text)
        edit.setFixedHeight(42)
        edit.setFixedWidth(360)
        edit.setStyleSheet("""
            QLineEdit {
                font-size: 18px;
                padding-left: 12px;
                border: 2px solid #c6c6c6;
                border-radius: 6px;
                background: #ffffff;
                color: #000;
            }
            QLineEdit:focus { border: 2px solid #00bcd4; }
        """)
        return edit

    def _row(self, line_edit: QLineEdit) -> QWidget:
        """
        Build a compact row with a line edit and a small 'browse' button
        that opens a directory picker and writes the chosen path back.
        """
        browse = QPushButton("📂")
        browse.setFixedSize(40, 36)
        browse.setCursor(Qt.CursorShape.PointingHandCursor)
        browse.setStyleSheet("""
            QPushButton {
                font-size: 18px;
                background-color: #ffbf00;
                color: #000;
                border-radius: 6px;
            }
            QPushButton:hover { background-color: #e6aa00; }
        """)
        browse.clicked.connect(lambda: self._browse(line_edit))

        # Slightly smaller edit in row for balance with the button
        line_edit.setFixedHeight(36)
        line_edit.setStyleSheet("""
            QLineEdit {
                font-size: 16px;
                padding-left: 10px;
                border: 2px solid #c6c6c6;
                border-radius: 6px;
                background: #ffffff;
                color: #000;
            }
            QLineEdit:focus { border: 2px solid #00bcd4; }
        """)

        # Tight container to keep widgets snug
        tight_container = QWidget()
        hbox = QHBoxLayout(tight_container)
        hbox.setContentsMargins(0, 0, 0, 0)
        hbox.setSpacing(6)
        hbox.addWidget(line_edit)
        hbox.addWidget(browse)

        tight_container.setSizePolicy(
            QSizePolicy.Policy.Maximum,
            QSizePolicy.Policy.Fixed
        )

        return tight_container
    
    def _labeled_row(self, label_text: str, line_edit: QLineEdit) -> QHBoxLayout:
        """Create a row with a descriptive label and the (edit+browse) composite."""
        label = QLabel(label_text)
        label.setStyleSheet("font-size: 18px; color: #f1f1f1;")
        label.setFixedWidth(700)
        label.setTextInteractionFlags(Qt.TextInteractionFlag.NoTextInteraction)
        label.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)

        row = QHBoxLayout()
        row.setSpacing(12)
        row.setContentsMargins(0, 0, 0, 0)
        row.addWidget(label)
        row.addWidget(self._row(line_edit))
        return row



    def _browse(self, edit: QLineEdit):
        """Open a folder picker and write the chosen path into the given QLineEdit."""
        path = QFileDialog.getExistingDirectory(self, "Choose directory")
        if path:
            edit.setText(path)

    def _save(self):
        """
        Persist edits to QSettings and show a confirmation dialog.
        Non-fatal errors are printed to stdout.
        """
        try:
            # Persist to OS-specific store
            self.config.setValue("dump_path",     self.dump_edit.text())
            self.config.setValue("csv_path",      self.csv_edit.text())
            self.config.setValue("analysis_path", self.analysis_edit.text())
            
            # Reset any app-wide stylesheet side-effects (optional)
            QApplication.instance().setStyleSheet("")
            
            # Feedback dialog
            msg_box = QMessageBox(self)
            msg_box.setIcon(QMessageBox.Icon.Information)
            msg_box.setWindowTitle("ShadowSnare - message")
            msg_box.setText("Default paths saved successfully!")
            msg_box.setStandardButtons(QMessageBox.StandardButton.Ok)
            msg_box.setStyleSheet("QLabel{ color: black; }")
            msg_box.exec()

            print("✅ Paths saved")
            
        except Exception as e:
            # Do not crash settings page on UI/storage error
            print(f"❌ Error saving paths: {e}")
