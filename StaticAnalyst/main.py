import hashlib
import ipaddress
import json
import os
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
        behavioural_assesment(extracted_text)
        

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

    # IPs regular expressions
    ip_format = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    clean_ips = []

    # URLs regular expressions
    url_format = r"https?://[a-zA-Z0-9\-\.\/\_\?\=\&]+"

    # DLLs regular expressions
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

# This methods loads the JSON containing the signatures
def load_signatures():
    signatures_path = os.path.join(os.path.dirname(__file__), "signatures.json")

    if not os.path.exists(signatures_path):
        print("\n [ERROR] The file signature.json does not exists or it is not inside the folder 'StaticAnalyst'")
        return

    try:
        with open(signatures_path, "r", encoding="utf-8") as file:
            return json.load(file)
    except (json.JSONDecodeError, OSError, UnicodeError) as e:
        # JSON parsing errors, file I/O errors or encoding issues
        print(f"The file exists but could not be opened/read: {e}")
        return None

def colorize_risk(risk_level):
    # Diccionario con los colores ANSI
    colors = {
        "HIGH": "\033[91mHIGH\033[0m",                 # Texto rojo
        "MEDIUM": "\033[93mMEDIUM\033[0m",             # Texto amarillo
        "LOW": "\033[92mLOW\033[0m",                   # Texto verde
    }
    # Si el nivel no está en el diccionario, lo devuelve en blanco por defecto
    return colors.get(risk_level.upper(), f"\033[97m{risk_level}\033[0m")

def behavioural_assesment(extracted_text):

    signatures = load_signatures()

    if not signatures:
        print("No signatures found")
        return

    text_lower = extracted_text.lower()
    detected_flags = []
    detected_combos = []

    # Here we check what suspicious windows APIs are being called in the executable
    winapis = signatures.get("winapis", {})
    for api_name, details in winapis.items():
        if api_name in extracted_text:
            risk = details.get("risk", "No risk level provided")
            desc = details.get("description", "No description provided")
            detected_flags.append((risk,f"API: {api_name}",desc))

    # Here we check what suspicious commands are present in the executable
    cmds = signatures.get("suspicious_commands", {})
    for command_name, details in cmds.items():
        if command_name in extracted_text:
            risk = details.get("risk", "No risk level provided")
            desc = details.get("description", "No description provided")
            detected_flags.append((risk,f"API: {command_name}",desc))

    combos = signatures.get("threat_combos", [])
    for combo in combos:
        reqs = combo.get("requires", [])
        reqanyof = combo.get("requires_any_of", [])

        # Check if all required items are present
        has_all_reqs = True
        if reqs:
            has_all_reqs = all(req in extracted_text or req.lower() in text_lower for req in reqs)
            
        # Check if at least one of the 'any of' items is present (only if the list is not empty)
        has_any_req = True
        if reqanyof:
            has_any_req = any(req in extracted_text or req.lower() in text_lower for req in reqanyof)
            
        # If both conditions are met, we have a match!
        if has_all_reqs and has_any_req:
            # Use 'verdict' instead of 'assesment' to match JSON
            detected_combos.append((combo["risk"], combo["name"], combo["verdict"], reqs, reqanyof))
        
    # Print all the results
    print("\n\033[1mBehavioral Assessment & Red Flags:\033[0m")
    print("\n\033[93m[!] WARNING: This assessment is based on static string extraction and signature matching. The presence of these APIs or commands in the binary does not guarantee they are actually executed and legitimate software may also use them. Consider this a triage/informative tool, not a definitive verdict. \033[1m(NOTE: THE FILE COULD BE PACKED OR OBFUSCATED). \033[0m\n")

    if not detected_flags and not detected_combos:
        print("\033[92m[+] No suspicious behavioural patterns or combinations found and no individual red flags were found.\033[0m\n")
        return

    # Print the suspicious combinations of behaviours
    if detected_combos:
        print("  \033[91m[!] SUSPICIOUS BEHAVIOUR DETECTED:\033[0m\n")
        for risk, name, verdict, reqs, reqanyof in detected_combos:
            c_risk = colorize_risk(risk)
            print(f"  • Risk level: [{c_risk}] Name: {name}")
            print(f"    Verdict: {verdict}")
            # Format requirements beautifully 
            req_str = ", ".join(reqs) if reqs else "None"
            any_str = ", ".join(reqanyof) if reqanyof else "None"
            print(f"    Matched triggers: Requires({req_str}) | Requires Any({any_str})\n")
    else:
        print("\033[92m[+] No suspicious behavioural patterns or combinations found.\033[0m\n")

    # Print the individual suspicious commands or api calls
    print("Potentially Suspicious Individual Calls:\n")
    for risk, flag, desc in detected_flags:
        c_risk = colorize_risk(risk)
        print(f"  • Risk level: [{c_risk}] {flag}\n    Description: {desc}\n")
    print("\n\033[90m* NOTE: These can be abused by malware, but are also commonly used by legitimate harmless software. *\033[0m")
    print()
    print("=" * 40)

if __name__ == "__main__":
    main()