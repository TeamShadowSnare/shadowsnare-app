import sys
from PyQt6.QtWidgets import QApplication
from view.main_window import MainWindow


if __name__ == "__main__":
    print("main.py launched with args:", sys.argv)

    app = QApplication(sys.argv)
    window = MainWindow()
    
    from controller.dev_mode_controller import devModeController
    dev_controller = devModeController(window.dev_mode_view)

    # ✅ Switch to User Mode if flag is present
    if "--user-mode" in sys.argv:
        window.nav_list.setCurrentRow(1)  # User Mode index
        window.stack.setCurrentIndex(1)

    window.show()

    if "--create-dump" in sys.argv:
        from controller.user_mode_controller import UserModeController
        controller = UserModeController(window.user_mode_view)
        controller.handle_create_dump()

    sys.exit(app.exec())
