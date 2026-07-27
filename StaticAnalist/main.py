import hashlib
import ipaddress
import re
import tkinter as tk
from tkinter import filedialog

import requests


def main():

    # Initialize Tkinter
    root = tk.Tk()
    # Hide tkinter's deafult empty screen 
    root.withdraw() 

    print("\nOpening file selection screen...")
    # Launch the file selector
    filepath = filedialog.askopenfilename(
        title="Select the suspicious file",
        filetypes=[("PE files", "*.exe *.dll"), ("All files", "*.*")] 
    )

    if filepath:
        print(f"Selected file path: {filepath}\n")
        file_hash = compute_file_hash(filepath)
        print(f"File hash: {file_hash}\n")
        vt_key = input("If you want a VirusTotal filehash analysis paste your API and press enter, if not, leave empty and press enter. \n" \
        "If you don't know what a VirusTotal API key is or how to get it go to readme.md \n" \
        "Enter your API Key: ").strip()
        if vt_key:
            print(" [+] Connecting to VirusTotal...")
            Virustotal_hash_analysis(file_hash, vt_key)
        else:
            print(" [-] VirusTotal analysis skipped.")
    
        print("\n" + "="*40)
        print("\nStatic analysis starting...\n")
        extracted_text = text_extractor(filepath)
        regex_analysis(extracted_text)

    else:
        print("Analysis cancelled: no file selected.")


# This method calculates the hash of the file, very useful as a first check
def compute_file_hash(filepath, algorithm='sha256'):
    hash_func = hashlib.new(algorithm)

    # Open the file safely in binary mode
    with open(filepath, 'rb') as file:

        # Read the file in chunks of 8Kb
        while chunk := file.read(8192):

            # Update the hash object with each chunk of data
            hash_func.update(chunk)

    # Return the final hash value as a hexadecimal string
    return hash_func.hexdigest()

#This method uses VirusTotal's public api to cross reference the file hash and give a report based on it
def Virustotal_hash_analysis(hash, api_key):
    url = f"https://www.virustotal.com/api/v3/files/{hash}"
    headers = {"accept": "application/json", "x-apikey": api_key}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        deserialized_vt_response = response.json()
        # This is just the most important data of the VirusTotal api response
        stats = deserialized_vt_response["data"]["attributes"]["last_analysis_stats"]
        print("\n" + "="*40)
        print("VIRUSTOTAL REPORT")
        print("="*40)
        # \033[91m is red text, \033[93m yellow, \033[92m green and \033[0m is to take it back to normal
        print(f"\033[91mEngines that flag the file as malware: {stats['malicious']}\033[0m")
        print(f"\033[93mEngines that flag the file as suspecious: {stats['suspicious']}\033[0m")
        print(f"\033[92mEngines that flag the file as safe: {stats['undetected']}\033[0m")
        print("="*40 + "\n")

    elif response.status_code == 404:
        print("\n[-] The file is so new that VirusTotal doesn't have it in its database yet.")

    elif response.status_code == 401:
        print("\n[-] Error: Your VirusTotal API Key is invalid or has expired.")

    else:
        print(f"\n[-] An unexpected error occurred. HTTP Code: {response.status_code}")

# This method extracts the raw text from the .exe file and filters invisible characters
def text_extractor(filepath):
    extracted_tmp = ""
    extracted_text = ""

    # Read file in binary mode
    with open(filepath, 'rb') as file:
        # Divide the file in 8Kb chunks
        while chunk := file.read(8192):
            for byte in chunk:
                # This checks if a byte is an ascii printable character to avoid
                # unnecesary checks and errors in weird invisible chararacters
                if(32 <= byte <= 126):
                    extracted_tmp += chr(byte)
                else:
                    # If the current set of chars is less than 4 chars long is probably irrelevant
                    if(len(extracted_tmp) < 4):
                        extracted_tmp = ""
                    else:
                        extracted_text += extracted_tmp + "\n"
                        extracted_tmp = ""                
        return extracted_text

# This method filters out IP addresses that look like software version numbers or noise
def check_ip_false_positive(ip):
    # List of the most likely false positive IPs
    false_positives = ['0.0.0.0', '0.0.0.1', '1.0.0.0', '1.1.0.0', '1.1.1.0', '1.1.1.1', '2.0.0.0', '3.0.0.0', '4.0.0.0', '5.0.0.0', '6.0.0.0', '7.0.0.0', '8.0.0.0', '9.0.0.0']
    
    if ip in false_positives:
        return True
        
    parts = ip.split('.')
    
    # Version-like combinations, like X.Y.0.0 or X.0.0.0
    if parts[2] == '0' and parts[3] == '0':
        return True  # Ex. 1.3.0.0
    if parts[1] == '0' and parts[2] == '0' and parts[3] == '0':
        return True  # Ex. 2.0.0.0
    if parts[1] == '0' and parts[2] == '0' and (0 <= int(parts[0]) <= 10) and (0 <= int(parts[3]) <= 10):
        return True  # Ex. 1.0.0.1, 2.0.0.5, etc.
    if parts[0] == '0': #Ex. 0.2.5.1 # noqa: SIM103
        return True  # All invalid IPs that start with 0
    
    return False

# This method analyzes the extracted text to find relevant info throgh regular expressions
def regex_analysis(extracted_text):

    ip_format = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    # Some versioning in apps could be detected as IP adresses, here is a list of the most common
    clean_ips = []
    url_format = r"https?://[a-zA-Z0-9\-\.\/\_\?\=\&]+"
    dll_format = r"[a-zA-Z0-9\-_]+\.dll"

    print("To avoid fatal missclicks all URLs and IPs we will be defanged (dots as * and hxxp instead of http) \n")
    print("WARNING: This script can mistake versions of apps with IPs, for example 1.3.5.4 is likely a version, however it will be detected as an IP because IT COULD BE a real IP\n")

    # regex detection of IPs trying to avoid false positives + defang
    ips = re.findall(ip_format, extracted_text, re.IGNORECASE)
    for ip in ips:
        try:
            # Check whether the IP mathematically exists (numbers don't exceed 255)
            ipaddress.IPv4Address(ip)
            if not check_ip_false_positive(ip):
                clean_ips.append(ip)
        except ipaddress.AddressValueError:
            pass
    defanged_ips = [ip.replace(".", "*") for ip in clean_ips]

    # regex detection of URL + defang
    urls = re.findall(url_format, extracted_text, re.IGNORECASE)
    defanged_urls = [url.replace("http", "hxxp").replace(".", "*") for url in urls]

    # regex detection of DLLs
    dlls = re.findall(dll_format, extracted_text, re.IGNORECASE)

    print("=" * 40)
    print()
    print("\033[1mThis file possibly connects to the IP(s):\033[0m")
    for ip in sorted(set(defanged_ips)):
        print(f"  • {ip}")
    print()

    print("\033[1mThis file possibly connects to the URL(s):\033[0m")
    for url in sorted(set(defanged_urls)):
        print(f"  • {url}")
    print()

    print("\033[1mThis file possibly uses the DLL(s):\033[0m")
    for dll in sorted(set(dlls)):
        print(f"  • {dll}")
    print()
    print("=" * 40)

if __name__ == "__main__":
    main()