from PyQt6.QtCore import QSettings

_settings = QSettings("ShadowSnare", "Paths")

def get_default(kind: str) -> str:
    return _settings.value(f"{kind}_path", "")

def set_default(kind: str, value: str):
    _settings.setValue(f"{kind}_path", value)
