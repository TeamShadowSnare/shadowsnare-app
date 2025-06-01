from PyQt6.QtWidgets import QApplication
import sys
from view.main_window import MainWindow
from controller.csv_uploader_controller import CSVUploaderController

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = MainWindow()
    window.load_stylesheet("view/style.qss")
    controller = CSVUploaderController(window.csv_uploader_view)
    window.show()
    sys.exit(app.exec())
    