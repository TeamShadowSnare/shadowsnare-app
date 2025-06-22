import os
from utils.internal_extract import extract_all_features_from_memdump

def extract_features_and_convert_to_csv(memory_path: str, output_dir: str, progress_callback=None) -> str:
    extract_all_features_from_memdump(memory_path, output_dir, progress_callback=progress_callback)
    csv_path = os.path.join(output_dir, "output.csv")
    return csv_path
