

---

# Excalibur: AI Enhanced Cybersecurity Threat Detector

Welcome to **Excalibur**, the cutting-edge AI-powered cybersecurity tool that helps detect and classify phishing, malicious URLs, and files with a combination of VirusTotal and machine learning algorithms.

This project leverages **machine learning** models and **VirusTotal API** for enhanced malware detection and URL safety analysis.

---

## 🔥 Features

- **URL Scanning**: Scan URLs against VirusTotal’s database to detect phishing, malicious, or safe URLs.
- **File Hash Scanning**: Scan files by their hash to detect malicious behavior using VirusTotal's API.
- **AI Prediction**: A machine learning model analyzes URLs and classifies them as safe or malicious.
- **Interactive CLI**: The program features an interactive command-line interface that guides users through the process.
- **AI Enhanced Security**: Leverages machine learning to predict URL safety beyond VirusTotal’s reports.

---

## ⚙️ Installation and Setup

### Step 1: Clone the Repository

```bash
git clone https://github.com/Dawn-Fighter/excalibur.git
cd excalibur
```

### Step 2: Create a Virtual Environment (Optional but recommended)

```bash
python -m venv venv
source venv/bin/activate  # For Linux/MacOS
venv\Scripts\activate     # For Windows
```

### Step 3: Install Dependencies

Install the necessary dependencies using pip:

```bash
pip install -r requirements.txt
```

**Dependencies**:

- `aiohttp`: Asynchronous HTTP client to interact with the VirusTotal API.
- `pandas`: For handling and processing data.
- `scikit-learn`: Machine learning library for training the URL safety prediction model.
- `pyfiglet`: For ASCII art in the terminal UI.
- `hashlib`: For generating file hashes.

You can install them manually as well:

```bash
pip install aiohttp pandas scikit-learn pyfiglet
```

### Step 4: Get the VirusTotal API Key

Sign up on [VirusTotal](https://www.virustotal.com/) to get your API Key. Replace `API_KEY` in the script with your actual key.

---

## 🚀 Usage

Once you've set up the environment and installed dependencies, you can run the script to start scanning URLs or files.

### Start the Application

Run the following command to start the interactive CLI:

```bash
python excalibur.py
```

### Commands:

1. **Scan a URL:**
    ```bash
    scan_url <url>
    ```
    Example:
    ```bash
    scan_url http://example.com
    ```

2. **Scan a file:**
    ```bash
    scan_file <file_path>
    ```
    Example:
    ```bash
    scan_file /path/to/file.exe
    ```

3. **Exit the Program:**
    ```bash
    exit
    ```

---

## 🔒 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🤝 Contributing

Contributions are what make the open-source community such an amazing place to learn, inspire, and create. If you have suggestions or want to contribute to the project, feel free to fork this repository, submit an issue, or create a pull request!

---

## 👀 Demo

For the full experience, run the application as described in the Usage section. The AI-enhanced prediction of URLs and files will guide you through identifying potential threats.

---

## 📝 Acknowledgments

- **VirusTotal API**: Provides scanning services for URLs and files.
- **scikit-learn**: Used for the machine learning model that classifies URLs.
- **pyfiglet**: For creating ASCII art banners.
