"""
main.py
--------

Entry point for the application.

Responsibilities:
- Create the QApplication (manages widgets, events, and the main loop).
- Instantiate and show the MainWindow (which wires up views/controllers).
- Start the Qt event loop and exit with its return code.
"""


import sys
from PyQt6.QtWidgets import QApplication
from view.main_window import MainWindow

if __name__ == "__main__":
    print("main.py launched with args:", sys.argv)

    app = QApplication(sys.argv)
    window = MainWindow()

    window.show()
    sys.exit(app.exec())
