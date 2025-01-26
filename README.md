# ShadowSnare

ShadowSnare is a stealthy malware detection tool designed for cybersecurity specialists. It leverages deep learning to analyze memory dump files for obfuscated malware detection, providing an efficient and reliable solution for identifying stealthy threats.

## Features

- **Memory Dump Analysis**: Extracts features from memory dump files and analyzes them for malware detection.
- **Deep Learning Integration**: Employs state-of-the-art machine learning models trained on the CIC-MalMem-2022 dataset.
- **User-Friendly Interface**: Built using PyQt6 for a seamless desktop application experience.
- **Local Processing**: Operates entirely locally without the need for a server.
- **Specialist-Oriented**: Focused on providing actionable insights for cybersecurity experts.

## Tech Stack

- **Frontend/UI**: PyQt6 (Python)
- **Machine Learning**: TensorFlow or PyTorch (Deep Learning Framework)
- **Dataset**: CIC-MalMem-2022

## Installation

### Prerequisites

- Python 3.x
- pip (Python package installer)

### Steps

1. Clone the repository:

   ```bash
   git clone https://github.com/yourusername/ShadowSnare.git
   cd ShadowSnare
   ```

2. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

3. Run the application:
   ```bash
   python main.py
   ```

## Usage

1. Launch the application.
2. Upload a memory dump file using the interface.
3. The tool extracts features, runs the malware detection model, and provides the results.

## Roadmap

- **Phase 1**: Develop the proof-of-concept (by end of March 2025)
- **Phase 2**: Enhance feature extraction and model performance
- **Phase 3**: Add real-time analysis capabilities

## Team

- **[Rani Izsack]** - Project Lead
- **[Amos Zohar]** - Data aqcuisition and feature extraction, UI developer
- **[Gal Havshush]** - Machine learning Specialist, UI developer
- **[Ortal Nissim]** - Machine learning Specialist, UI developer

## Acknowledgements

- [CIC-MalMem-2022 Dataset](https://www.unb.ca/cic/datasets/malmem-2022.html)
- OpenAI for assistance in brainstorming ideas and technical implementation
