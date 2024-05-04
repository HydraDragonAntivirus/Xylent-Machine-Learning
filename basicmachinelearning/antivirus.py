import sklearn
import json
import sys
import joblib
import os
import numpy as np
import pandas as pd
import pefile
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics.pairwise import cosine_similarity
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
        return {'file_name': file_name, 'numeric_tag': rank, 'malware_definition': f"Malware definition for file {file_name}"}
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
def scan_folder(folder_path, numeric_features, malicious_file_names):
    """Scan a folder for malicious activity"""
    try:
        print(f"Scanning folder: {folder_path}")
        scan_results = []

        for root, _, files in os.walk(folder_path):
            for file in files:
                file_path = os.path.join(root, file)
                if os.path.isfile(file_path):
                    print(f"Scanning file: {file_path}")
                    try:
                        file_numeric_features = extract_numeric_features(file_path)
                        if not file_numeric_features:
                            print(f"Cannot extract numeric features from the file {file_path}.")
                            continue

                        print("Extracted Features:", file_numeric_features)

                        # Ensure consistent feature dimensions
                        file_features = {key: file_numeric_features.get(key, 0) for key in numeric_features[0].keys()}

                        max_similarity = 0
                        malware_rank = None
                        for features in numeric_features:
                            similarity = cosine_similarity([list(features.values())], [list(file_features.values())])[0][0]
                            if similarity > max_similarity:
                                max_similarity = similarity
                                if 'numeric_tag' in features:
                                    malware_rank = features['numeric_tag']

                        if max_similarity > 0.9 and malware_rank is not None:  # Adjust this threshold as needed
                            # Find the info associated with the rank from the JSON file
                            malware_info = next((info for info in malicious_file_names if info['numeric_tag'] == malware_rank), None)
                            if malware_info:
                                malware_definition = malware_info.get('malware_definition', f"Malware with rank {malware_rank}")
                                scan_results.append((file_path, True, malware_definition))
                            else:
                                scan_results.append((file_path, True, f"Malware with rank {malware_rank}"))
                        else:
                            scan_results.append((file_path, False, None))

                    except Exception as e:
                        print(f"An error occurred while scanning file {file_path}: {e}")

        print("Scan completed.")
        
        # Print results after the loop
        for file_path, result, malware_definition in scan_results:
            if result:
                print(f"Malicious activity detected in: {file_path}")
                print("Malware Definition:", malware_definition)
            else:
                print(f"No malicious activity detected in: {file_path}")

    except Exception as e:
        print(f"An error occurred while scanning folder {folder_path}: {e}")
def load_data():
    """Load malicious file names and numeric features"""
    try:
        with open('malicious_file_names.json', 'r') as f:
            malicious_files_info = json.load(f)
        with open('numeric_features.pkl', 'rb') as f:
            numeric_features = joblib.load(f)
        return malicious_files_info, numeric_features
    except Exception as e:
        print(f"An error occurred while loading data: {e}")
        return None, None

def validate_folder(folder_path):
    """Validate if the provided folder path exists"""
    return os.path.exists(folder_path)

def main():
    try:
        print("Loading data...")
        malicious_files_info, numeric_features = load_data()
        if malicious_files_info is None or numeric_features is None:
            print("Error: Failed to load data.")
            return

        print("Data loaded successfully.")

        folder_path = input("Enter the path of the folder to scan: ").strip()
        if not validate_folder(folder_path):
            print("Error: Invalid folder path.")
            return

        print("Scanning folder...")
        scan_folder(folder_path, numeric_features, malicious_files_info)

    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()