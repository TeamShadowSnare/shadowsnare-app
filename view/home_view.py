"""
Home view (PyQt6).
Shows the logo and a 'Get Started' button. When clicked, replaces the logo with
a short HTML guide explaining prerequisites and basic workflow steps.
Pure UI/presentation; no business logic here.
"""


from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel, QPushButton
from PyQt6.QtGui import QPixmap
from PyQt6.QtCore import Qt
import os

class HomeView(QWidget):
    """Landing screen for the app."""
    def __init__(self):
        super().__init__()

        # Root vertical layout centered on the page
        self.layout = QVBoxLayout()
        self.layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setLayout(self.layout)

        # --- Logo section ---
        logo_path = os.path.join("assets", "logo.png")  
        self.logo_label = QLabel()
        logo_pixmap = QPixmap(logo_path)

        if not logo_pixmap.isNull():
            # Keep aspect ratio; smooth scale for nicer rendering
            resized_logo = logo_pixmap.scaled(500, 500, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)
            self.logo_label.setPixmap(resized_logo)
            self.logo_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.layout.addWidget(self.logo_label)
        else:
            # Non-fatal: keep going without the image
            print(f"⚠️ Logo not found at: {logo_path}")

        # --- Call-to-action button ---
        self.start_button = QPushButton("Get Started")
        self.start_button.setStyleSheet("""
            QPushButton {
                font-size: 40px;
                padding: 12px 30px;
                color: white;
                border-radius: 10px;
                margin-bottom: 5px;           
            }
          
        """)
        self.start_button.clicked.connect(self.show_instructions) # swap to instructions view
        self.layout.addWidget(self.start_button)

        # --- Instructions block (hidden by default) ---
        # RichText HTML: links enabled, centered title, step list for onboarding
        self.instructions_label = QLabel("""
            <div style="color: white; text-align: left; margin-top: 10px; width: 90%; margin-left: auto; margin-right: auto;">
                <h1 style="color: #6dd5fa; text-align: center; margin-top: 0; margin-bottom: 100px;">Getting Started</h1>
                <ol style="font-size: 20px; color: white; line-height: 2; padding-left: 24px;">
                    <li style="margin-bottom: 16px;">
                        <strong>Download WinPmem:</strong> <a href="https://github.com/Velocidex/WinPmem/releases" style="color: #00bcd4; text-decoration: none;">Download here</a>
                    </li>
                    <li style="margin-bottom: 16px;">
                        <strong>Rename the file winpmem_xxx_xxx_xxx.exe to winpmem.exe, then place it in:</strong> <code>c:/winpmem/</code>
                    </li>
                    <li style="margin-bottom: 16px;">
                        Go into the Settings tab to choose your default paths
                    </li>
                    <li style="margin-bottom: 16px;">
                        In User Mode you can:
                        <ul style="margin-top: 10px; padding-left: 20px;">
                            <li>🧠 <strong>Create a memory dump</strong></li>
                            <li>📑 <strong>Extract features to CSV</strong></li>
                            <li>📄 <strong>Analyze the CSV for threats</strong></li>
                        </ul>
                    </li>
                </ol>
            </div>
        """)



        self.instructions_label.setTextFormat(Qt.TextFormat.RichText) # render HTML
        self.instructions_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.instructions_label.setOpenExternalLinks(True) # allow clicking links
        self.instructions_label.setWordWrap(True) # wrap long lines
        self.instructions_label.setVisible(False) # hidden until button press
        self.layout.addWidget(self.instructions_label)

    def show_instructions(self):
        """CTA handler: hide logo/button and reveal the instructions HTML."""
        self.logo_label.hide()
        self.start_button.hide()
        self.instructions_label.setVisible(True)
