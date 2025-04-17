from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel
from PyQt6.QtGui import QPixmap
from PyQt6.QtCore import Qt
import os

class HomeView(QWidget):
    def __init__(self):
        super().__init__()

        layout = QVBoxLayout()
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        # Logo
        logo_path = os.path.join("assets", "logo.png")  # Path to logo
        logo_label = QLabel()
        logo_pixmap = QPixmap(logo_path)

        if not logo_pixmap.isNull():
            # Resize logo to 200x200 (preserve aspect ratio, fit within bounds)
            resized_logo = logo_pixmap.scaled(500, 500, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)
            logo_label.setPixmap(resized_logo)
            logo_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            layout.addWidget(logo_label)
        else:
            print(f"⚠️ Logo not found at: {logo_path}")

        # Welcome Text
        # welcome_label = QLabel("Welcome to ShadowSnare!")
        # welcome_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        # welcome_label.setStyleSheet("font-size: 28px; color: white;")
        # layout.addWidget(welcome_label)

        self.setLayout(layout)
