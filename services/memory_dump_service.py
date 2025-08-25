"""
CSV extraction helper.

Thin wrapper that runs Volatility3-based feature extraction on a memory dump
and returns the expected CSV path (<output_dir>/output.csv). Progress updates
can be streamed via an optional callback.
"""


import os
from utils.internal_extract import extract_all_features_from_memdump

def extract_features_and_convert_to_csv(memory_path: str, output_dir: str, progress_callback=None) -> str:
    """
    Run feature extraction on a memory dump and point to the resulting CSV.

    Parameters
    ----------
    memory_path : str
        Path to the memory dump file (.raw/.vmem/.mem).
    output_dir : str
        Directory where the CSV will be written.
    progress_callback : callable | None
        Optional function (or Qt signal) to receive progress strings.

    Returns
    -------
    str
        Absolute/relative path to "<output_dir>/output.csv".
    """
    # Invoke the extractor (handles running multiple Volatility plugins)
    extract_all_features_from_memdump(memory_path, output_dir, progress_callback=progress_callback)
    
    # Convention: extractor writes 'output.csv' in the given directory
    csv_path = os.path.join(output_dir, "output.csv")
    return csv_path
