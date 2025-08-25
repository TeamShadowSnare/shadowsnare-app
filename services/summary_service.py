"""
Summary service.

Loads an HTML template and fills it with scan stats and the current date/time.
Intended to produce the right-panel summary shown after analysis.
"""


import os
from PyQt6.QtCore import QDate, QTime, Qt
from utils.template_loader import load_template

class SummaryService:
    """Generates HTML summaries for scan results using a template."""
    def generate_summary(self, total_count, benign_count, malicious_count, status, explanation_link=""):
        """
        Build an HTML snippet from a template.

        Parameters
        ----------
        total_count : int
            Number of analyzed items (rows/samples).
        benign_count : int
            Items predicted as benign.
        malicious_count : int
            Items predicted as malware.
        status : str
            High-level status string (e.g., "Device Clean" / "Potential Malware Detected").
        explanation_link : str, optional
            Optional HTML anchor inserted in the template (e.g., 'View explanation').

        Returns
        -------
        str
            HTML string ready to be displayed in a QTextBrowser.
        """
        # Resolve and load the HTML template (raises if missing)
        template_path = os.path.join("templates", "scan_summary_template.html")
        template = load_template(template_path)

        # Fill template with runtime values (date/time in ISO format)
        return template.format(
            total_count=total_count,
            benign_count=benign_count,
            malicious_count=malicious_count,
            status=status,
            date_str=QDate.currentDate().toString(Qt.DateFormat.ISODate),
            time_str=QTime.currentTime().toString(Qt.DateFormat.ISODate),
            explanation_link=explanation_link
        )
