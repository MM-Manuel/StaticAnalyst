import hashlib
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
        print(f"Selected file path: {filepath}")
        print(f"File hash:{compute_file_hash(filepath)}")

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

if __name__ == "__main__":
    main()