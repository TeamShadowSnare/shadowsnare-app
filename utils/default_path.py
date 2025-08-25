"""
Default path helpers.

Stores/retrieves user-selected directories in QSettings("ShadowSnare", "Paths"),
using keys like "<kind>_path" (e.g., "dump_path", "csv_path", "analysis_path").
"""


from PyQt6.QtCore import QSettings

# App-scoped settings object (persists under the OS's standard store)
_settings = QSettings("ShadowSnare", "Paths")

def get_default(kind: str) -> str:
    """Return the saved path for the given kind (e.g., 'dump', 'csv', 'analysis'); empty string if unset."""
    return _settings.value(f"{kind}_path", "")

def set_default(kind: str, value: str):
    """Persist a path for the given kind (e.g., set_default('csv', 'C:/data/csv'))."""
    _settings.setValue(f"{kind}_path", value)
