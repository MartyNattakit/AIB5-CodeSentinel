import os
import glob

base_dir = "C:\\Users\\MartyNattakit\\Desktop\\Datasets\\2022-08-11-juliet-c-cplusplus-v1-3-1-with-extra-support"
pattern = os.path.join(base_dir, "**", "CWE121_Stack_Based_Buffer_Overflow*.c")
files = {os.path.basename(f): f for f in glob.glob(pattern, recursive=True)}
print(f"Found {len(files)} .c files")
for file in [
    "CWE121_Stack_Based_Buffer_Overflow__CWE805_wchar_t_declare_memcpy_32.c",
    "CWE121_Stack_Based_Buffer_Overflow__CWE131_memmove_18.c",
    "CWE121_Stack_Based_Buffer_Overflow__CWE135_01.c"
]:
    print(f"{file}: {'Found' if file in files else 'Not found'}")