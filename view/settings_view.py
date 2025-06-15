from PyQt6.QtCore import QSettings
from PyQt6.QtWidgets import (
    QWidget, QLineEdit, QPushButton, QFileDialog,
    QHBoxLayout, QVBoxLayout, QFormLayout, QMessageBox
)

class SettingsView(QWidget):
    def __init__(self):
        super().__init__()

        self.config = QSettings("ShadowSnare", "Paths")

        form = QFormLayout()
        self.dump_edit   = QLineEdit(self.config.value("dump_path",   "C:/Dumps"))
        self.csv_edit    = QLineEdit(self.config.value("csv_path",    "C:/CSVs"))
        self.analysis_edit = QLineEdit(self.config.value("analysis_path", "C:/CSVs"))

        form.addRow("Default dump directory:",     self._row(self.dump_edit))
        form.addRow("Default CSV directory:",      self._row(self.csv_edit))
        form.addRow("Default analysis directory:", self._row(self.analysis_edit))

        save_btn = QPushButton("💾 Save")
        save_btn.clicked.connect(self._save)
        wrapper = QVBoxLayout(self)
        wrapper.addLayout(form)
        wrapper.addWidget(save_btn)

    # helper to make a line-edit + browse button
    def _row(self, line_edit):
        browse = QPushButton("📂…")
        browse.setFixedWidth(32)
        browse.clicked.connect(lambda: self._browse(line_edit))
        w = QWidget()
        h = QHBoxLayout(w); h.setContentsMargins(0,0,0,0)
        h.addWidget(line_edit); h.addWidget(browse)
        return w

    def _browse(self, edit):
        path = QFileDialog.getExistingDirectory(self, "Choose directory")
        if path:
            edit.setText(path)

    def _save(self):
        try:
            self.config.setValue("dump_path",    self.dump_edit.text())
            self.config.setValue("csv_path",     self.csv_edit.text())
            self.config.setValue("analysis_path", self.analysis_edit.text())
            QMessageBox.information(self, "Saved", "Default paths saved!", QMessageBox.StandardButton.Ok)
            print("✅ Paths saved")
        except Exception as e:
            print(f"❌ Error saving paths: {e}")
