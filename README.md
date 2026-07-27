# StaticAnalyst
StaticAnalyst is a Python script that reads executable files to find possibly malicious URLs/IPs connections and suspicious DLL loads. It also computes the hash of the executable to cross reference it with VirusTotal's database.

## Requirements

To run StaticAnalist successfully, you need:

* **Operating System:** Windows 10 or 11.
* **Python:** Version 3.8 or higher installed on your system (make sure to check **"Add Python to PATH"** during installation).
* **Python Library:** 
  * `requests` (automatically checked and installed when using the `.bat` launcher).

## How to run

### Easy way
Double click on StaticAnalist.bat, this native windows script will automatically check your dependencies and will run the python script itself

### Hard way
1. Make sure you have **Python** installed on your system.
2. Clone this repository or download the source code:
   ```bash
   git clone https://github.com/MM-Manuel/StaticAnalyst.git
   cd StaticAnalist
   ```

3. Install the required dependencies:
   ```bash
   pip install requests
   ```
4. Run the script:
   ```bash
   python main.py
   ```

## What is VirusTotal API and how to get an API Key?

### What is VirusTotal API?
**VirusTotal** is a free online service that analyzes files and URLs for viruses, malware, and other security risks using over 70 antivirus engines and domain blocklists. 

The **VirusTotal API** allows developers to query their massive threat intelligence database programmatically. In this tool, the API is used to send the calculated SHA-256 hash of a file to check if it has already been flagged as malicious by the global cybersecurity community—without needing to upload the actual file.

---

### How to Get Your Free API Key (Step-by-Step)

Getting a VirusTotal API key is completely free and takes less than 2 minutes:

1. **Create an Account:**
   Go to [VirusTotal.com](https://www.virustotal.com/) and click on **Sign Up** in the top right corner to create a free account.

2. **Confirm Your Email:**
   Check your inbox and verify your email address to activate your account.

3. **Find Your API Key:**
   * Log in to VirusTotal.
   * Click on your **profile icon/username** in the top-right corner.
   * Select **API Key** from the dropdown menu.

4. **Copy Your Key:**
   You will see a long alphanumeric string (e.g., `65ea4c7c3d83j25k2...`). Copy this string—this is your personal API key.

---

### How to Use It with This Script

When you run `main.py`, the script will prompt you in the console:

```text
If you want a VirusTotal filehash analysis paste your API key and press enter.
If not, leave empty and press enter.
> API Key:
```
---

## Credits, Limitations, and VirusTotal API Usage

This project integrates the **VirusTotal Public API** to cross-reference the hashes (SHA256) obtained during the static analysis. By using this tool, the user must be aware of the following conditions and limitations established by VirusTotal's policies:

* **Non-Commercial Use:** This script has been developed exclusively for educational purposes and personal research. The use of the VirusTotal Public API is strictly prohibited for commercial purposes or integration into paid products.
* **Rate Limits:** The Public API imposes strict technical restrictions. Currently, it allows a maximum of **4 requests per minute** and **500 requests per day**. If multiple files are analyzed in bulk, the script may experience temporary pauses or errors (HTTP 429) to comply with these limits.
* **Data Privacy:** When querying a hash using this script, the search information is sent to VirusTotal's servers. VirusTotal shares this telemetry and analysis results with the global cybersecurity community. It is highly advised not to use this tool to analyze proprietary or confidential software, or files containing personally identifiable information.
* **Intellectual Property:** All information regarding reputation, antivirus detections, and verdicts displayed by this script over the network belongs to VirusTotal and its respective partner scanning engines. 

For more information, please refer to the [VirusTotal Terms of Service](https://docs.virustotal.com/docs/terms-of-service).

**Apart from the optional VirusTotal API integration, everything else in StaticAnalyst is 100% free to use anywhere, including for commercial, profitable, or enterprise environments.**

## Show Your Support!

If you find **StaticAnalyst** useful, please consider giving it a **Star** on GitHub! It helps the project gain visibility and motivates further development.

Feel free to open an **Issue** if you find a bug or have a feature request!