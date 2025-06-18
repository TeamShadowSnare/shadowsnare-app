# from PyQt6.QtWidgets import QApplication
# import sys
# from view.main_window import MainWindow
# from controller.dev_mode_controller import devModeController

# if __name__ == '__main__':
#     print("main.py launched with args:", sys.argv)

#     # Case: Called after elevation for creating dump
#     if "--create-dump" in sys.argv:
#         print("🛡 Relaunched with --create-dump")

#         from view.user_mode_view import UserMode
#         from controller.user_mode_controller import UserModeController

#         app = QApplication(sys.argv)
#         view = UserMode()
#         controller = UserModeController(view)
#         view.show()

#         controller.handle_create_dump()

#         sys.exit(app.exec())

#     # Regular app launch
#     app = QApplication(sys.argv)
#     window = MainWindow()
#     window.load_stylesheet("view/style.qss")
#     controller = devModeController(window.dev_mode_view)
#     window.show()
#     sys.exit(app.exec())


# import sys
# from PyQt6.QtWidgets import QApplication
# from view.main_window import MainWindow

# if __name__ == "__main__":
#     print("main.py launched with args:", sys.argv)

#     app = QApplication(sys.argv)
#     window = MainWindow()
#     window.show()

#     # ✅ Auto-trigger dump creation if elevated via --create-dump
#     if "--create-dump" in sys.argv:
#         from controller.user_mode_controller import UserModeController
#         controller = UserModeController(window.user_mode_view)
#         controller.handle_create_dump()

#     sys.exit(app.exec())

import sys
from PyQt6.QtWidgets import QApplication
from view.main_window import MainWindow

if __name__ == "__main__":
    print("main.py launched with args:", sys.argv)

    app = QApplication(sys.argv)
    window = MainWindow()

    # ✅ Switch to User Mode if flag is present
    if "--user-mode" in sys.argv:
        window.nav_list.setCurrentRow(3)  # User Mode index
        window.stack.setCurrentIndex(3)

    window.show()

    if "--create-dump" in sys.argv:
        from controller.user_mode_controller import UserModeController
        controller = UserModeController(window.user_mode_view)
        controller.handle_create_dump()

    sys.exit(app.exec())
