import numpy as np
from model.malware_model import MalwareDetector

class PredictionService:
    def __init__(self):
        self.model = MalwareDetector()

    def load_csv(self, file_path):
        with open(file_path, 'r') as f:
            header_line = f.readline().strip()
            all_columns = header_line.split(',')
            feature_names = all_columns[2:]
        data = np.genfromtxt(file_path, delimiter=',', dtype=str, skip_header=1)
        if data.ndim == 1:
            data = data.reshape(1, -1)
        return data, feature_names

    def predict(self, feature_data):

        predictions, binary_preds, labels = self.model.predict(feature_data)
        benign_count = np.count_nonzero(binary_preds == 0)
        malicious_count = np.count_nonzero(binary_preds == 1)
        total_count = len(binary_preds)
        status = "Potential Malware Detected" if malicious_count > 0 else "Device Clean"
        summary = {
            "total": total_count,
            "benign": benign_count,
            "malicious": malicious_count,
            "status": status
        }
        return predictions, summary


