import os
from PyQt6.QtCore import QDate, QTime, Qt
from utils.plot_utils import load_template

class SummaryService:
    def generate_summary(self, total_count, benign_count, malicious_count, status):
      
        template_path = os.path.join("templates", "scan_summary_template.html")
        template = load_template(template_path)

        return template.format(
            total_count=total_count,
            benign_count=benign_count,
            malicious_count=malicious_count,
            status=status,
            date_str=QDate.currentDate().toString(Qt.DateFormat.ISODate),
            time_str=QTime.currentTime().toString(Qt.DateFormat.ISODate)
        )
