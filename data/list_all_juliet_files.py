import os
import pandas as pd

juliet_root = r"C:\Users\MartyNattakit\Desktop\Datasets\2022-08-11-juliet-c-cplusplus-v1-3-1-with-extra-support"
output_file = r"C:\Users\MartyNattakit\Desktop\CodeSentinel\all_juliet_files.csv"

files = []
for root, _, filenames in os.walk(juliet_root):
    for fname in filenames:
        if fname.endswith(".c"):
            files.append(os.path.join(root, fname))

df = pd.DataFrame(files, columns=["file_path"])
df.to_csv(output_file, index=False)
print(f"Saved {len(files)} files to {output_file}")