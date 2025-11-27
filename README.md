## 🛡️ ShadowSnare

**ShadowSnare** brings state-of-the-art neural detection to Windows memory forensics, scanning dump files offline to find hidden malware and explaining each verdict through a streamlined PyQt6 interface.

---

### 🚀 Features

- 🧠 Memory Dump Pipeline – Acquire with WinPmem, extract behavioral features via Volatility3, and detect malicious activity directly from RAM images.
- 🤖 Deep Learning Integration – TensorFlow/Keras model trained with the [CIC-MalMem-2022](https://www.unb.ca/cic/datasets/malmem-2022.html)
dataset for high-accuracy, on-device inference.
- 🔍 Explainability for Analysts – SHAP per-sample factors, plus confusion matrix and misclassified entries for deeper validation.
- 🖥️ Modern Windows UI – PyQt6 desktop app for Windows 10+ with clean, responsive views (Home · User · Dev · Settings).
- 🔒 Offline by Design – All analysis runs locally; no cloud services or data egress.

### 🎥 Full Demo Playlist

[Full ShadowSnare Demo Playlist](https://www.youtube.com/playlist?list=PLk-_UXQL-Nwte7AGKwrZDx_hQ5JgOw3lt)

---

### 🧰 Tech Stack

#### 🖥️ Platform
[![Windows](https://img.shields.io/badge/Windows-10%2B-0078D6?style=flat&logo=windows&logoColor=white)](https://www.microsoft.com/windows)

#### 🎨 UI / Frontend
[![PyQt6](https://img.shields.io/badge/PyQt6-41CD52?style=flat&logo=qt&logoColor=white)](https://www.riverbankcomputing.com/software/pyqt/)

#### 🧠 Machine Learning
[![TensorFlow](https://img.shields.io/badge/TensorFlow-FF6F00?style=flat&logo=tensorflow&logoColor=white)](https://www.tensorflow.org/)
[![Keras](https://img.shields.io/badge/Keras-D00000?style=flat&logo=keras&logoColor=white)](https://keras.io/)

#### 🔍 Memory Forensics & Acquisition
[![WinPmem](https://img.shields.io/badge/WinPmem-333333?style=flat)](https://github.com/Velocidex/WinPmem)
[![Volatility3](https://img.shields.io/badge/Volatility3-CC0000?style=flat)](https://www.volatilityfoundation.org/)

#### 🧪 Explainability & Evaluation
[![SHAP](https://img.shields.io/badge/SHAP-5A67D8?style=flat)](https://shap.readthedocs.io/)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-F7931E?style=flat&logo=scikit-learn&logoColor=white)](https://scikit-learn.org/)
[![Matplotlib](https://img.shields.io/badge/Matplotlib-11557C?style=flat)](https://matplotlib.org/)

#### 📊 Data Handling
[![pandas](https://img.shields.io/badge/pandas-150458?style=flat&logo=pandas&logoColor=white)](https://pandas.pydata.org/)
[![NumPy](https://img.shields.io/badge/NumPy-013243?style=flat&logo=numpy&logoColor=white)](https://numpy.org/)

#### 🗂️ Dataset
[![CIC-MalMem-2022](https://img.shields.io/badge/Dataset-CIC--MalMem--2022-6A5ACD?style=flat)](https://www.unb.ca/cic/datasets/malmem-2022.html)

#### 🐍 Runtime Environment
[![Python](https://img.shields.io/badge/Python-3.10.X-3776AB?style=flat&logo=python&logoColor=white)](https://www.python.org/)
[![pip](https://img.shields.io/badge/pip-package%20installer-00529B?style=flat)](https://pip.pypa.io/)

---

### 🛠️ Installation

#### Prerequisites

- Windows 10+ (64-bit)
- Python 3.10.x (64-bit)
- pip
- (For dump creation) WinPmem at C:\winpmem\winpmem.exe

#### Steps

```bash
# 1) Clone the repository
git clone https://github.com/TeamShadowSnare/ShadowSnare-app.git
cd ShadowSnare

# 2) Create & activate a virtual environment
python -m venv .venv
.\.venv\Scripts\activate

# 3) Install dependencies
pip install -r requirements.txt

# 4) (Once) Place WinPmem for memory acquisition
#    Download → rename to winpmem.exe → put at C:\winpmem\winpmem.exe

# 5) Run the app (use an elevated terminal if you’ll create a dump)
python main.py
```

---

### 🧪 Usage

1. **Launch ShadowSnare**
- If you plan to create a memory dump, open your terminal/IDE **as Administrator**.

2. **(Recommended) Set default paths**
- Go to **Settings** and choose directories for **Dump**, **CSV**, and **Analysis**.

3. **Open _User Mode_** from the sidebar and follow the flow:
- 🧠 **Create Memory Dump** *(Admin + WinPmem required)*
- 📑 **Extract Features to CSV** *(runs Volatility3; produces `output.csv`)*
- 📄 **Upload & Analyze CSV** *(use the new CSV or pick an existing one)*

4. **Review results**
- **Summary & status** (clean / malware found)
- **SHAP explanations** (click “View explanation” to open the popup)

> ℹ️ **Deeper analysis (optional):**
> Switch to **Dev Mode** to see a **Confusion Matrix**, **Misclassified samples**, raw **Data** preview, and detailed **Explainability** for labeled CSVs (`Benign`/`Malware` in the first column).

---

### 🔍 Feature Walkthroughs

#### 🧠 Memory Dump Creation
[![Dump Creation](https://img.youtube.com/vi/YyrqTADMirM/0.jpg)](https://youtu.be/YyrqTADMirM)

#### 📑 Feature Extraction
[![Feature Extraction](https://img.youtube.com/vi/uoOw9Q6zqsc/0.jpg)](https://youtu.be/uoOw9Q6zqsc)

#### 📄 Analyze CSV
[![Analyze CSV](https://img.youtube.com/vi/O8UTEVn9PC8/0.jpg)](https://youtu.be/O8UTEVn9PC8)

#### 🧪 Dev Mode Analytics
[![Dev Mode](https://img.youtube.com/vi/qp7GPrOR50s/0.jpg)](https://youtu.be/qp7GPrOR50s)

---

### 👥 Team

- **Rani Izsack** – Project Supervisor  
- **Amos Zohar** – Data Acquisition, Feature Extraction, UI Development  
- **Gal Havshush** – Machine Learning Specialist, UI Development  
- **Ortal Nissim** – Machine Learning Specialist, UI Development  

---

### 🙏 Acknowledgements

- [CIC-MalMem-2022 Dataset](https://www.unb.ca/cic/datasets/malmem-2022.html) - Benchmark dataset used for model training and evaluation.
- [WinPmem](https://github.com/Velocidex/WinPmem) – Memory acquisition tool used for dump creation.
- [Volatility](https://www.volatilityfoundation.org/) – Memory forensics framework used for feature extraction.
- [CIC-MalMem-2022 Dataset](https://github.com/ahlashkari/VolMemLyzer) - reference for how several memory-forensics features were originally derived.creation.

