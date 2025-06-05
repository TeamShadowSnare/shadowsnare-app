import os
from utils.extract_features import extract_all_features_from_memdump

def extract_features_and_convert_to_csv(memory_path: str, output_dir: str) -> str:
    volatility_path = "volatility3/vol.py"  # Update if needed

    extract_all_features_from_memdump(memory_path, output_dir, volatility_path)

    csv_path = os.path.join(output_dir, "output.csv")
    return csv_path
