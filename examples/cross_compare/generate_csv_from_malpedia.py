import os
import re
import sys


dump_file_pattern = re.compile("dump7?_0x[0-9a-fA-F]{8,16}")
unpacked_file_pattern = re.compile("_unpacked(_x64)?$")

if len(sys.argv) < 3:
    print("A script to generate a cross-compare CSV based on Malpedia")
    print(f"usage: {sys.argv[0]} <malpedia_root> <family_a> <family_b> ... <family_n>")
    sys.exit()

malpedia_root = os.path.abspath(sys.argv[1])
target_families = set(sys.argv[2:])

for root, subdir, files in sorted(os.walk(malpedia_root)):
    relative_root = root[len(malpedia_root) + 1:]
    path_split = relative_root.split(os.sep)
    family = path_split[0]
    version = path_split[1] if len(path_split) > 1 else ""
    if family in target_families:
        for filename in files:
            if not (re.search(unpacked_file_pattern, filename) or re.search(dump_file_pattern, filename)):
                continue
            print(f"{family},{version},{root + os.sep + filename}")