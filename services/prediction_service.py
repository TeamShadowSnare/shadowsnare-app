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

    def predict(self, dataFromINDEX2Col):
    
        raw_X = dataFromINDEX2Col.astype(float)

        # 2) Scale exactly as in your old code:
        X_scaled = self.model.scaler.transform(raw_X)

        # 3) Get probabilities from the underlying model:
        probabilities = self.model.model.predict(X_scaled)

        # 4) Threshold at 0.5 for binary (0=benign, 1=malicious):
        binary_preds = (probabilities > 0.5).astype(int).flatten()

        return probabilities, binary_preds, raw_X, X_scaled

