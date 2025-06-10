import pandas as pd
import os
import re
import xml.etree.ElementTree as ET

input_file = r"C:\Users\MartyNattakit\Desktop\CodeSentinel\all_juliet_files.csv"
output_csv = r"C:\Users\MartyNattakit\Desktop\CodeSentinel\all_cwes_dataset.csv"

bad_paths = ["s01", "s03", "s05", "s07"]
batch_size = 10000

df = pd.read_csv(input_file)
for i in range(0, len(df), batch_size):
    data = {"file": [], "cwe": [], "label": [], "code": []}
    batch = df[i:i+batch_size]
    for file_path in batch["file_path"]:
        try:
            file_name = os.path.basename(file_path)

            # Skip non-CWE files
            if "testcasesupport" in file_path.lower() or not re.search(r"CWE\d+", file_name):
                print(f"Skipped: {file_name} (non-CWE or testcasesupport)")
                continue

            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                code = f.read()
            print(f"Processing: {file_name}")

            # Extract CWE
            cwe_match = re.search(r"CWE\d+", file_name)
            cwe = cwe_match.group(0) if cwe_match else "Unknown"

            # Path-based labeling
            normalized_path = file_path.lower().replace("\\", "/")
            is_bad_path = any(s in normalized_path for s in bad_paths) and re.search(r"_(0[13579]|[1-9][0-9])\.c$", file_name)

            # XML-based labeling
            xml_path = file_path.replace(".c", ".label.xml")
            label = "good"
            if os.path.exists(xml_path):
                tree = ET.parse(xml_path)
                if tree.find(".//flaw") is not None:
                    label = "bad"
            elif is_bad_path:
                label = "bad"

            print(f"File: {file_name}, CWE: {cwe}, Path: {is_bad_path}, Label: {label}")

            data["file"].append(file_name)
            data["cwe"].append(cwe)
            data["label"].append(label)
            data["code"].append(code)
        except Exception as e:
            print(f"Error: {file_path}: {e}")

    batch_df = pd.DataFrame(data)
    batch_df.to_csv(f"{output_csv}.{i//batch_size}.csv", index=False)
    print(f"Saved batch {i//batch_size} with {len(batch_df)} rows")