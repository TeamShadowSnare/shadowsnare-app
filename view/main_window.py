from PyQt6.QtWidgets import QMainWindow, QWidget, QHBoxLayout, QListWidget, QStackedWidget
from controller.user_mode_controller import UserModeController
from view.home_view import HomeView
from view.dev_mode_view import devMode
from view.user_mode_view import UserMode
from view.settings_view import SettingsView

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("ShadowSnare")
        self.setGeometry(100, 100, 1400, 900)
        self.load_stylesheet("view/style.qss")

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QHBoxLayout(central_widget)

        self.nav_list = QListWidget()
        self.nav_list.addItem("Home")         # index 0
        self.nav_list.addItem("User Mode")    # index 1
        self.nav_list.addItem("Dev Mode")     # index 2
        self.nav_list.addItem("Settings")     # index 3


        self.nav_list.setFixedWidth(200)
        self.nav_list.setStyleSheet("font-size: 20px; color: white; background-color: #2c3e50;")
        layout.addWidget(self.nav_list)

        self.stack = QStackedWidget()
        layout.addWidget(self.stack)

        self.home_view = HomeView()
        self.dev_mode_view = devMode()
        self.settings_view = SettingsView() 
        self.user_mode_view = UserMode()
        
        self.user_mode_controller = UserModeController(self.user_mode_view)

        self.stack.addWidget(self.home_view)        # index 0
        self.stack.addWidget(self.user_mode_view)   # index 1
        self.stack.addWidget(self.dev_mode_view)    # index 2
        self.stack.addWidget(self.settings_view)    # index 3


        self.nav_list.setCurrentRow(0)
        self.stack.setCurrentIndex(0)

        self.nav_list.currentRowChanged.connect(self.stack.setCurrentIndex)

    def load_stylesheet(self, file_path):
        try:
            with open(file_path, "r") as file:
                self.setStyleSheet(file.read())
        except Exception as e:
            print(f"Error loading stylesheet: {e}")
