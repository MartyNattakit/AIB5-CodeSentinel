import pandas as pd

# Paths
all_cwes_csv = "C:\\Users\\MartyNattakit\\Desktop\\CodeSentinel\\Demo\\all_cwes_dataset.csv"
output_csv = "C:\\Users\\MartyNattakit\\Desktop\\CodeSentinel\\cwe_top5_sampled.csv"

# Load all CWEs dataset
df = pd.read_csv(all_cwes_csv)

# Top 5 CWEs (from all_cwes_dataset.csv)
top_cwes = ["CWE121", "CWE78", "CWE190", "CWE191", "CWE122"]

# Filter for top 5 CWEs (using 'cwe' column)
df_top5 = df[df['cwe'].isin(top_cwes)]

# Sample 400 files per CWE (or all if fewer)
df_sampled = pd.DataFrame()
for cwe in top_cwes:
    cwe_df = df_top5[df_top5['cwe'] == cwe]
    sample_size = min(400, len(cwe_df))
    if sample_size > 0:
        df_sampled = pd.concat([df_sampled, cwe_df.sample(n=sample_size, random_state=42)])

# Save
df_sampled.to_csv(output_csv, index=False, encoding='utf-8')
print(f"Created {output_csv} with {len(df_sampled)} files")
if not df_sampled.empty:
    print(f"CWE counts:\n{df_sampled['cwe'].value_counts().to_string()}")
else:
    print("No data sampled. Check column name or top_cwes list.")