from PyQt6.QtWidgets import QApplication
import sys
from view.main_view import CSVUploaderUI
from controller.main_controller import CSVUploaderController

if __name__ == '__main__':
    app = QApplication(sys.argv)
    view = CSVUploaderUI()
    controller = CSVUploaderController(view)
    view.show()
    sys.exit(app.exec())