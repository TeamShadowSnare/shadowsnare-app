"""
Prediction service.

Thin wrapper around the malware model that:
- Loads a CSV (header used to infer feature names from column index 2 onward),
- Runs preprocessing (cast to float, optional scaling via `self.model.scaler`),
- Predicts probabilities and binary class using the wrapped Keras model.

Assumptions:
- The first two columns in the CSV are metadata (e.g., label/filename),
  and the actual features start at index 2.
- `MalwareDetector` exposes `.model` (Keras model) and `.scaler` (fitted scaler).
"""


import numpy as np
from model.malware_model import MalwareDetector

class PredictionService:
    """Service object that owns a `MalwareDetector` and provides CSV→predict helpers."""
    def __init__(self):
        # Wrap the underlying model (and, by convention, a fitted scaler if available)
        self.model = MalwareDetector()

    def load_csv(self, file_path):
        """
        Load CSV data and infer feature names from the header.

        Parameters
        ----------
        file_path : str
            Path to the CSV file.

        Returns
        -------
        tuple[np.ndarray, list[str]]
            - data: ndarray of the raw CSV rows (as strings), excluding header.
            - feature_names: list of column names starting from index 2.
        """
        # Read the first line (header) to get all column names
        with open(file_path, 'r') as f:
            header_line = f.readline().strip()
            all_columns = header_line.split(',')
            feature_names = all_columns[2:] # assume first two columns are not features

        # Load remaining lines as a string array (skip the header row)
        data = np.genfromtxt(file_path, delimiter=',', dtype=str, skip_header=1)
        
        # Ensure a 2D shape even if there is only one row
        if data.ndim == 1:
            data = data.reshape(1, -1)
        return data, feature_names

    def predict(self, dataFromINDEX2Col):
        """
        Run model prediction on pre-sliced features (columns 2..end).

        Parameters
        ----------
        dataFromINDEX2Col : np.ndarray
            Raw feature matrix (strings/numeric) starting at column index 2.

        Returns
        -------
        tuple
            probabilities : np.ndarray
                Model output probabilities for the positive (malware) class.
            binary_preds : np.ndarray
                0/1 predictions using a 0.5 threshold.
            raw_X : np.ndarray
                Input cast to float (pre-scaling).
            X_scaled : np.ndarray
                Scaled features (requires `self.model.scaler` to exist).
        """
        # Cast to float for downstream preprocessing/model
        raw_X = dataFromINDEX2Col.astype(float)
        
        # Apply the model's fitted scaler (assumes `self.model.scaler` exists)
        X_scaled = self.model.scaler.transform(raw_X)
        
        # Forward pass through the Keras model
        probabilities = self.model.model.predict(X_scaled)
        
        # Convert probabilities to binary predictions at threshold 0.5
        binary_preds = (probabilities > 0.5).astype(int).flatten()

        return probabilities, binary_preds, raw_X, X_scaled

