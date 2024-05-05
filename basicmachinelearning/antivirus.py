import sklearn
import json
import sys
import joblib
import os
import numpy as np
import pandas as pd
import pefile
from sklearn.ensemble import RandomForestClassifier
import subprocess
sys.modules["sklearn.tree.tree"] = sklearn.tree
sys.modules["sklearn.ensemble.weight_boosting"] = sklearn.ensemble
sys.modules["sklearn.ensemble.forest"] = sklearn.ensemble
sys.modules["sklearn.svm.classes"] = sklearn.svm
sys.modules["sklearn.neighbors.classification"] = sklearn.neighbors
sys.modules['sklearn.externals.joblib'] = joblib

def extract_infos(file_path, rank=None):
    """Extract information about file"""
    file_name = os.path.basename(file_path)
    if rank is not None:
        return {'file_name': file_name, 'numeric_tag': rank}
    else:
        return {'file_name': file_name}

def extract_numeric_features(file_path, rank=None):
    """Extract numeric features of a file using pefile"""
    res = {}
    try:
        pe = pefile.PE(file_path)
        res['SizeOfOptionalHeader'] = pe.FILE_HEADER.SizeOfOptionalHeader
        res['MajorLinkerVersion'] = pe.OPTIONAL_HEADER.MajorLinkerVersion
        res['MinorLinkerVersion'] = pe.OPTIONAL_HEADER.MinorLinkerVersion
        res['SizeOfCode'] = pe.OPTIONAL_HEADER.SizeOfCode
        res['SizeOfInitializedData'] = pe.OPTIONAL_HEADER.SizeOfInitializedData
        res['SizeOfUninitializedData'] = pe.OPTIONAL_HEADER.SizeOfUninitializedData
        res['AddressOfEntryPoint'] = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        res['BaseOfCode'] = pe.OPTIONAL_HEADER.BaseOfCode
        res['BaseOfData'] = pe.OPTIONAL_HEADER.BaseOfData if hasattr(pe.OPTIONAL_HEADER, 'BaseOfData') else 0
        res['ImageBase'] = pe.OPTIONAL_HEADER.ImageBase
        res['SectionAlignment'] = pe.OPTIONAL_HEADER.SectionAlignment
        res['FileAlignment'] = pe.OPTIONAL_HEADER.FileAlignment
        res['MajorOperatingSystemVersion'] = pe.OPTIONAL_HEADER.MajorOperatingSystemVersion
        res['MinorOperatingSystemVersion'] = pe.OPTIONAL_HEADER.MinorOperatingSystemVersion
        res['MajorImageVersion'] = pe.OPTIONAL_HEADER.MajorImageVersion
        res['MinorImageVersion'] = pe.OPTIONAL_HEADER.MinorImageVersion
        res['MajorSubsystemVersion'] = pe.OPTIONAL_HEADER.MajorSubsystemVersion
        res['MinorSubsystemVersion'] = pe.OPTIONAL_HEADER.MinorSubsystemVersion
        res['SizeOfImage'] = pe.OPTIONAL_HEADER.SizeOfImage
        res['SizeOfHeaders'] = pe.OPTIONAL_HEADER.SizeOfHeaders
        res['CheckSum'] = pe.OPTIONAL_HEADER.CheckSum
        res['Subsystem'] = pe.OPTIONAL_HEADER.Subsystem
        res['DllCharacteristics'] = pe.OPTIONAL_HEADER.DllCharacteristics
        res['SizeOfStackReserve'] = pe.OPTIONAL_HEADER.SizeOfStackReserve
        res['SizeOfStackCommit'] = pe.OPTIONAL_HEADER.SizeOfStackCommit
        res['SizeOfHeapReserve'] = pe.OPTIONAL_HEADER.SizeOfHeapReserve
        res['SizeOfHeapCommit'] = pe.OPTIONAL_HEADER.SizeOfHeapCommit
        res['LoaderFlags'] = pe.OPTIONAL_HEADER.LoaderFlags
        res['NumberOfRvaAndSizes'] = pe.OPTIONAL_HEADER.NumberOfRvaAndSizes
        if rank is not None:
            res['numeric_tag'] = rank
    except Exception as e:
        print(f"An error occurred while processing {file_path}: {e}")
        
    return res
def calculate_similarity(features1, features2, threshold=0.8):
    """Calculate similarity between two dictionaries of features"""
    common_keys = set(features1.keys()) & set(features2.keys())
    matching_keys = sum(1 for key in common_keys if features1[key] == features2[key])
    similarity = matching_keys / max(len(features1), len(features2))
    return similarity
def load_malicious_data(json_file, numeric_file):
    """Load malicious file names and numeric features from JSON and pickle files"""
    with open(json_file, 'r') as f:
        malicious_file_names = json.load(f)
    
    malicious_numeric_features = joblib.load(numeric_file)
    
    return malicious_file_names, malicious_numeric_features
def check_signature(file_path):
    """Check if a file has a valid digital signature using PowerShell"""
    try:
        result = subprocess.run(['powershell', 'Get-AuthenticodeSignature', '-FilePath', file_path], capture_output=True, text=True)
        output = result.stdout
        if 'NotSigned' in output:
            return 'NotSigned'
        elif 'NotTrusted' in output or 'HashMismatch' in output or 'UnknownError' in output:
            return 'Malicious'
        else:
            return 'Valid'
    except Exception as e:
        print(f"An error occurred while checking signature for {file_path}: {e}")
        return 'NotSigned'
def scan_folder(folder_path, malicious_file_names, malicious_numeric_features, threshold=0.8):
    """Scan a folder for malicious activity"""
    try:
        print(f"Scanning folder: {folder_path}")

        for root, _, files in os.walk(folder_path):
            for file in files:
                file_path = os.path.join(root, file)
                if os.path.isfile(file_path):
                    try:
                        # Check if the file is a PE file
                        pe = pefile.PE(file_path)
                        if not pe:
                            print(f"File {file_path} is not a valid PE file. Skipping.")
                            continue

                        file_info = extract_infos(file_path)
                        file_numeric_features = extract_numeric_features(file_path)
                        
                        if not file_info:
                            print(f"Cannot extract info from the file {file_path}.")
                            continue

                        is_malicious = False
                        malware_rank = None
                        malware_definition = "Benign"  # Default

                        nearest_similarity = 0

                        for features, info in zip(malicious_numeric_features, malicious_file_names):
                            rank = info['numeric_tag']
                            definition = info.get('malware_definition', "Unknown")
                            similarity = calculate_similarity(file_numeric_features, features)
                            if similarity > nearest_similarity:
                                nearest_similarity = similarity
                            if similarity >= threshold:
                                is_malicious = True
                                malware_rank = rank
                                malware_definition = info['file_name']
                                break

                        print(f"File: {file_path}")
                        if is_malicious:
                            print("Malicious activity detected.")
                            print("Malware Rank:", malware_rank)
                            print("Malware Name:", malware_definition)
                        else:
                            print("Clean file.")
                        
                        print(f"Nearest similarity: {nearest_similarity}")
                        print()

                        # Flag files with similarity equal to or above the threshold as malicious
                        if nearest_similarity >= threshold:
                            print("File similarity is equal to or above the threshold. Flagging as malicious.")
                            print()
                            is_malicious = True

                    except pefile.PEFormatError:
                        print(f"File {file_path} is not a valid PE file.")

        print("Scan completed.")

    except Exception as e:
        print(f"An error occurred while scanning folder {folder_path}: {e}")
def main():
    try:
        print("Loading data...")
        
        json_file = 'malicious_file_names.json'
        numeric_file = 'malicious_numeric.pkl'
        
        folder_path = input("Enter the path of the folder to scan: ").strip()
        if not os.path.exists(folder_path):
            print("Error: Folder does not exist.")
            return
        
        malicious_file_names, malicious_numeric_features = load_malicious_data(json_file, numeric_file)

        print("Malicious file information loaded successfully.")

        print("Scanning folder...")
        scan_folder(folder_path, malicious_file_names, malicious_numeric_features)

    except FileNotFoundError:
        print("Error: Could not find required files for scanning.")
    except Exception as e:
        print(f"An error occurred: {e}")
if __name__ == "__main__":
    main()