import sklearn
import sklearn.tree
import sklearn.ensemble
import sklearn.svm
import sklearn.neighbors
import sklearn.neural_network
import json
import sys
import joblib
sys.modules["sklearn.tree.tree"] = sklearn.tree
sys.modules["sklearn.ensemble.weight_boosting"] = sklearn.ensemble
sys.modules["sklearn.ensemble.forest"] = sklearn.ensemble
sys.modules["sklearn.svm.classes"] = sklearn.svm
sys.modules["sklearn.neighbors.classification"] = sklearn.neighbors
sys.modules["sklearn.neural_network.multilayer_perceptron"] = sklearn.neural_network
sys.modules['sklearn.externals.joblib'] = joblib
import os
import pandas as pd
import numpy as np
import pefile

# Define functions for feature extraction
def get_entropy(data):
    """Get entropy of data"""
    if len(data) == 0:
        return 0.0
    occurences = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    probabilities = occurences[np.nonzero(occurences)] / len(data)
    entropy = -np.sum(probabilities * np.log2(probabilities))
    return entropy

def get_hex_string(file_path):
    """Get hexadecimal string representation of file"""
    with open(file_path, "rb") as f:
        data = f.read()
        hex_string = data.hex()
    return hex_string

def extract_infos(file_path):
    """Extract information about file"""
    res = {}
    try:
        pe = pefile.PE(file_path)
        res['Machine'] = pe.FILE_HEADER.Machine
        res['SizeOfOptionalHeader'] = pe.FILE_HEADER.SizeOfOptionalHeader
        res['Characteristics'] = pe.FILE_HEADER.Characteristics
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

        # Sections
        res['SectionsNb'] = len(pe.sections)
        entropy = [section.get_entropy() for section in pe.sections]
        res['SectionsMeanEntropy'] = np.mean(entropy)
        res['SectionsMinEntropy'] = np.min(entropy)
        res['SectionsMaxEntropy'] = np.max(entropy)
        raw_sizes = [section.SizeOfRawData for section in pe.sections]
        res['SectionsMeanRawsize'] = np.mean(raw_sizes)
        res['SectionsMinRawsize'] = np.min(raw_sizes)
        res['SectionsMaxRawsize'] = np.max(raw_sizes)
        virtual_sizes = [section.Misc_VirtualSize for section in pe.sections]
        res['SectionsMeanVirtualsize'] = np.mean(virtual_sizes)
        res['SectionsMinVirtualsize'] = np.min(virtual_sizes)
        res['SectionMaxVirtualsize'] = np.max(virtual_sizes)

        # Hex string
        res['HexString'] = get_hex_string(file_path)

    except Exception as e:
        print(f"An error occurred while processing {file_path}: {e}")

    return res

def load_files(folder):
    files_info = []
    for root, _, files in os.walk(folder):
        for file in files:
            file_path = os.path.join(root, file)
            file_info = extract_infos(file_path)
            file_info['FilePath'] = file_path  # Add file path to the info
            files_info.append(file_info)
    return files_info

# Load the saved model
model = joblib.load('malware_classifier.pkl')

# Get folder path from the user
folder_path = input("Enter the path to the folder containing files to scan: ")

# Load data for scanning
files_info = load_files(folder_path)

if files_info:
    # Create DataFrame
    df = pd.DataFrame(files_info)

    # Drop NaN values
    df.dropna(inplace=True)

    # Convert non-numeric values to numeric or drop the columns
    non_numeric_cols = df.select_dtypes(exclude=[np.number]).columns.tolist()
    for col in non_numeric_cols:
        try:
            df[col] = pd.to_numeric(df[col], errors='coerce')
        except ValueError:
            df.drop(columns=[col], inplace=True)

    if 'FilePath' in df.columns:  # Check if 'FilePath' column exists
        # Predict using the model
        predictions = model.predict(df.drop(columns=['FilePath']))  # Remove FilePath from features

        # Display predictions
        for file_path, prediction in zip(df['FilePath'], predictions):
            print(f"File: {file_path}, Prediction: {'Malicious' if prediction == 1 else 'Benign'}")
    else:
        print("No 'FilePath' column found in the DataFrame.")
else:
    print("No files found in the specified folder.")