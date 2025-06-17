from PyQt6.QtWidgets import QApplication
import sys
from view.main_window import MainWindow
from controller.csv_uploader_controller import CSVUploaderController

if __name__ == '__main__':
    print("main.py launched with args:", sys.argv)

    # Case: Called after elevation for creating dump
    if "--create-dump" in sys.argv:
        print("🛡 Relaunched with --create-dump")

        from view.user_mode_view import UserMode
        from controller.user_mode_controller import UserModeController

        app = QApplication(sys.argv)
        view = UserMode()
        controller = UserModeController(view)
        view.show()

        controller.handle_create_dump()

        sys.exit(app.exec())

    # Regular app launch
    app = QApplication(sys.argv)
    window = MainWindow()
    window.load_stylesheet("view/style.qss")
    controller = CSVUploaderController(window.csv_uploader_view)
    window.show()
    sys.exit(app.exec())
