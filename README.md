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

---

| Layer              | Technology                |
|--------------------|---------------------------|
| OS Target	         | Windows 10+               | 
| UI/Frontend	     | PyQt6                     |
| Memory Acquisition | WinPmem                   |
| Memory Forensics	 | Volatility3               | 
| ML Framework	     | TensorFlow / Keras        | 
| Explainability     | SHAP                      |
| Metrics / Plotting | scikit-learn, Matplotlib  |
| Data Handling	     | pandas, NumPy             |
| Dataset	         | CIC-MalMem-2022           |
| Runtime	         | Python 3.10.X , pip       |

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

