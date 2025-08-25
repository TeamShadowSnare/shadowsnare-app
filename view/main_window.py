"""
Main application window (PyQt6).
Hosts navigation (left list) and a stacked content area (right).
Owns all views and their controllers (User Mode + Dev Mode).
"""


from PyQt6.QtWidgets import QMainWindow, QWidget, QHBoxLayout, QListWidget, QStackedWidget
from controller.user_mode_controller import UserModeController
from controller.dev_mode_controller import devModeController
from view.home_view import HomeView
from view.dev_mode_view import devMode
from view.user_mode_view import UserMode
from view.settings_view import SettingsView

class MainWindow(QMainWindow):
    """Top-level window: sets up UI shell, views stack, and controllers."""
    def __init__(self):
        super().__init__()
        self.setWindowTitle("ShadowSnare")
        self.setGeometry(100, 100, 1400, 900)
        self.load_stylesheet("view/style.qss") # Load global QSS

        # Central container + horizontal layout: [nav list] | [stacked pages]
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QHBoxLayout(central_widget)

        # --- Left: navigation list controlling the stacked widget index ---
        self.nav_list = QListWidget()
        self.nav_list.addItem("Home")
        self.nav_list.addItem("User Mode")
        self.nav_list.addItem("Dev Mode")
        self.nav_list.addItem("Settings")

        self.nav_list.setFixedWidth(200)
        self.nav_list.setStyleSheet("font-size: 20px; color: white; background-color: #2c3e50;")
        layout.addWidget(self.nav_list)

        # --- Right: stacked pages (one widget per section) ---
        self.stack = QStackedWidget()
        layout.addWidget(self.stack)

        # Create views
        self.home_view = HomeView()
        self.dev_mode_view = devMode()
        self.settings_view = SettingsView() 
        self.user_mode_view = UserMode()
        
        # Create controllers and attach to their views-
        self.user_mode_controller = UserModeController(self.user_mode_view)
        self.dev_mode_controller  = devModeController(self.dev_mode_view)

        # Register views in the stacked widget (order must match nav list order)
        self.stack.addWidget(self.home_view) # index 0
        self.stack.addWidget(self.user_mode_view) # index 1
        self.stack.addWidget(self.dev_mode_view) # index 2
        self.stack.addWidget(self.settings_view) # index 3

        # Default selection: Home
        self.nav_list.setCurrentRow(0)
        self.stack.setCurrentIndex(0)

        # Keep stack page in sync with selected row in the nav list
        self.nav_list.currentRowChanged.connect(self.stack.setCurrentIndex)

    def load_stylesheet(self, file_path):
        try:
            with open(file_path, "r") as file:
                self.setStyleSheet(file.read())
        except Exception as e:
            print(f"Error loading stylesheet: {e}")
