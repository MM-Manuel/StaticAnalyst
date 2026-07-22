import hashlib
import requests
import tkinter as tk
from tkinter import filedialog


def main():

    # Initialize Tkinter
    root = tk.Tk()
    # Hide tkinter's deafult empty screen 
    root.withdraw() 

    print("Opening file selection screen...")
    # Launch the file selector
    filepath = filedialog.askopenfilename(
        title="Select the suspecious file",
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
        print(f"\033[91mEngines that flag it as malware: {stats['malicious']}\033[0m")
        print(f"\033[92mEngines that flag it as safe: {stats['undetected']}\033[0m")
        print(f"\033[93mEngines that flag it as suspecious: {stats['suspicious']}\033[0m")
        print("="*40 + "\n")

    elif response.status_code == 404:
        print("\n[-] The file is so new that VirusTotal doesn't have it in its database yet.")

    elif response.status_code == 401:
        print("\n[-] Error: Your VirusTotal API Key is invalid or has expired.")

    else:
        print(f"\n[-] An unexpected error occurred. HTTP Code: {response.status_code}")

    


if __name__ == "__main__":
    main()