## 🛡️ ShadowSnare

**ShadowSnare** is a stealthy, deep learning–powered malware detection tool designed for cybersecurity professionals. It analyzes memory dump files to detect obfuscated threats using state-of-the-art neural networks, all within a streamlined and intuitive desktop interface.

---

### 🚀 Features

- 🧠 **Memory Dump Analysis** – Extracts behavioral features from raw memory dumps and detects malicious activity.
- 🤖 **Deep Learning Integration** – Utilizes advanced neural networks trained on the [CIC-MalMem-2022](https://www.unb.ca/cic/datasets/malmem-2022.html) dataset for high-accuracy detection.
- 🖥️ **Modern UI** – Built with PyQt6 for a clean and responsive user experience.
- 🔒 **Offline Operation** – All detection runs locally with no external dependencies or cloud connections.
- 🧩 **Expert-Focused Insights** – Displays confusion matrices, SHAP explanations, and misclassified entries for advanced interpretation.

---

### 🧰 Tech Stack

| Layer        | Technology              |
|--------------|-------------------------|
| UI/Frontend  | PyQt6                   |
| ML Framework | TensorFlow              |
| Dataset      | CIC-MalMem-2022         |
| Packaging    | Python 3.x + pip        |

---

### 🛠️ Installation

#### Prerequisites

- Python 3.9+
- `pip`

#### Steps

```bash
# 1. Clone the repository
git clone https://github.com/TeamShadowSnare/ShadowSnare-app.git
cd ShadowSnare

# 2. Install required packages
pip install -r requirements.txt

# 3. Run the app
python main.py
```

---

### 🧪 Usage

1. Launch the ShadowSnare application.
2. Navigate to **User Mode** via the sidebar.
3. Choose from the following options:
   - 🧠 Create a memory dump
   - 📑 Extract features from the dump
   - 📄 Analyze the resulting CSV for malware presence
4. View results including:
   - Detection labels
   - Misclassified samples
   - Confusion matrix
   - SHAP explanations

---

### 👥 Team

- **Rani Izsack** – Project Supervisor  
- **Amos Zohar** – Data Acquisition, Feature Extraction, UI Development  
- **Gal Havshush** – Machine Learning Specialist, UI Development  
- **Ortal Nissim** – Machine Learning Specialist, UI Development  

---

### 🙏 Acknowledgements

- [CIC-MalMem-2022 Dataset](https://www.unb.ca/cic/datasets/malmem-2022.html)  
- [WinPmem](https://github.com/Velocidex/WinPmem) – Memory acquisition tool used in the dump creation process  
- [Volatility](https://www.volatilityfoundation.org/) – Framework used for memory dump analysis and feature extraction
