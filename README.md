# StaticAnalyst
This is a Python script that reads executable files to find possibly malicious URLs/IPs and suspicious DLL loads

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