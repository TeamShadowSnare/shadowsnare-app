import sys
from PyQt6.QtWidgets import QApplication
from view.main_window import MainWindow
from controller.dev_mode_controller import devModeController

if __name__ == "__main__":
    print("main.py launched with args:", sys.argv)

    app = QApplication(sys.argv)
    window = MainWindow()

    dev_controller = devModeController(window.dev_mode_view)

    window.show()
    sys.exit(app.exec())
