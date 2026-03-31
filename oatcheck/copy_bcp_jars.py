#!/usr/bin/env python3
"""
Copy BCP jars to target directory, preserving BOOTCLASSPATH structure
"""

import os
import sys
import shutil
from list_bcp_classes import BOOTCLASSPATH

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <target_root_directory>")
        print("Example: python3 copy_bcp_jars.py /ssd2/wyz/bcp_classes/15r3/")
        exit(1)

    # Get target root from command line argument
    target_root = sys.argv[1]
    os.makedirs(target_root, exist_ok=True)

    # Get Android product output path from environment variable
    host_prefix = os.environ.get('ANDROID_PRODUCT_OUT')
    if not host_prefix:
        print("Error: ANDROID_PRODUCT_OUT environment variable not found.")
        print("Please run the following commands first to set up the build environment:")
        print("  source build/envsetup.sh")
        print("  lunch aosp_lynx-trunk_staging-userdebug")
        exit(1)

    jar_paths = BOOTCLASSPATH.split(':')
    for jar_path in jar_paths:
        # Get relative path without leading /
        rel_path = jar_path.lstrip('/')
        full_jar_path = os.path.join(host_prefix, rel_path)

        if not os.path.exists(full_jar_path):
            print(f"Skipping non-existent jar: {full_jar_path}")
            continue

        # Target path for this jar
        target_jar_path = os.path.join(target_root, rel_path)
        # Create parent directory
        os.makedirs(os.path.dirname(target_jar_path), exist_ok=True)

        print(f"Copying {full_jar_path} to {target_jar_path}...")
        shutil.copy2(full_jar_path, target_jar_path)

    print(f"All BCP jars copied successfully to {target_root}")

if __name__ == "__main__":
    main()
