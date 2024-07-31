# -*- coding: utf-8 -*-

import argparse

# Define dangerous permissions and OWASP security recommendations
DANGEROUS_PERMISSIONS = {
    "android.permission.INTERNET": "Ensure all data transmitted over the network is encrypted.",
    "android.permission.READ_EXTERNAL_STORAGE": "Limit this permission unless absolutely necessary. Use Scoped Storage to mitigate risks.",
    "android.permission.WRITE_EXTERNAL_STORAGE": "Limit this permission unless absolutely necessary. Use Scoped Storage to mitigate risks.",
    "android.permission.ACCESS_FINE_LOCATION": "Only request this permission when necessary and clearly inform the user.",
    "android.permission.ACCESS_COARSE_LOCATION": "Only request this permission when necessary and clearly inform the user.",
    "android.permission.RECORD_AUDIO": "Only request this permission when absolutely necessary and clearly inform the user.",
    "android.permission.CAMERA": "Only request this permission when necessary and clearly inform the user.",
    "android.permission.READ_CONTACTS": "Only request this permission when absolutely necessary and clearly inform the user.",
    "android.permission.WRITE_CONTACTS": "Only request this permission when absolutely necessary and clearly inform the user.",
    "android.permission.SEND_SMS": "Only request this permission when absolutely necessary and ensure the user understands the reason.",
    "android.permission.RECEIVE_SMS": "Only request this permission when absolutely necessary and ensure the user understands the reason.",
    "android.permission.READ_SMS": "Limit this permission unless the app needs to process SMS for authentication or specific services.",
}

DEFAULT_RECOMMENDATION = "Review this permission to ensure it is absolutely necessary and inform the user clearly why it is needed."

def analyze_permissions(file_path):
    with open(file_path, 'r', encoding='utf-8') as file:
        lines = file.readlines()
    
    requested_permissions = []
    granted_permissions = []
    current_list = None
    for line in lines:
        if "requested permissions" in line:
            current_list = requested_permissions
        elif "granted permissions" in line:
            current_list = granted_permissions
        elif "android.permission" in line:
            permission = line.strip().split(':')[0]  # Split to handle granted permissions format
            if current_list is not None:
                current_list.append(permission)
    
    print("Requested Permissions:")
    for perm in requested_permissions:
        print(f"  {perm}")
        recommendation = DANGEROUS_PERMISSIONS.get(perm, DEFAULT_RECOMMENDATION)
        print(f"    Recommendation: {recommendation}")
    
    print("\nGranted Permissions:")
    for perm in granted_permissions:
        print(f"  {perm}")
        recommendation = DANGEROUS_PERMISSIONS.get(perm, DEFAULT_RECOMMENDATION)
        print(f"    Recommendation: {recommendation}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyze permissions from adb shell dumpsys output.")
    parser.add_argument("-f", "--file", required=True, help="Path to the dumpsys output file.")
    args = parser.parse_args()
    
    analyze_permissions(args.file)
