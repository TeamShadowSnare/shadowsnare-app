from utils.template_loader import load_template
from PyQt6.QtCore import QDate, QTime, Qt
import os

class SummaryService:
    def generate_summary(self, summary_data):
        template_path = os.path.join("templates", "scan_summary_template.html")
        template = load_template(template_path)
        return template.format(
            total_count=summary_data["total"],
            benign_count=summary_data["benign"],
            malicious_count=summary_data["malicious"],
            status=summary_data["status"],
            date_str=QDate.currentDate().toString(Qt.DateFormat.ISODate),
            time_str=QTime.currentTime().toString(Qt.DateFormat.ISODate)
        )
