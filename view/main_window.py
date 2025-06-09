from PyQt6.QtWidgets import QMainWindow, QWidget, QHBoxLayout, QListWidget, QStackedWidget
from controller.user_mode_controller import UserModeController
from view.home_view import HomeView
from view.csv_uploader_view import CSVUploaderView
from view.user_mode_view import UserMode

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
        self.nav_list.addItem("Home")
        self.nav_list.addItem("CSV Uploader")
        self.nav_list.addItem("User Mode")

        self.nav_list.setFixedWidth(200)
        self.nav_list.setStyleSheet("font-size: 20px; color: white; background-color: #2c3e50;")
        layout.addWidget(self.nav_list)

        self.stack = QStackedWidget()
        layout.addWidget(self.stack)

        self.home_view = HomeView()
        self.csv_uploader_view = CSVUploaderView()
        self.user_mode_view = UserMode()
        
        self.user_mode_controller = UserModeController(self.user_mode_view)
        
        self.stack.addWidget(self.home_view)           # index 0
        self.stack.addWidget(self.csv_uploader_view)   # index 1
        self.stack.addWidget(self.user_mode_view)      # index 2

        self.nav_list.setCurrentRow(0)
        self.stack.setCurrentIndex(0)

        self.nav_list.currentRowChanged.connect(self.stack.setCurrentIndex)

    def load_stylesheet(self, file_path):
        try:
            with open(file_path, "r") as file:
                self.setStyleSheet(file.read())
        except Exception as e:
            print(f"Error loading stylesheet: {e}")
