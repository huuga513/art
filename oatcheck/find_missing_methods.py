#!/usr/bin/env python3
import re
import sys

def convert_method_name(method_sig):
    """Convert Lcom/example/Class;->method to com.example.Class.method"""
    match = re.match(r'^L(.+);->(.+)$', method_sig)
    if match:
        class_path = match.group(1).replace('/', '.')
        method_name = match.group(2)
        return f"{class_path}.{method_name}"
    return None

def main():
    diff_file = sys.argv[1] if len(sys.argv) > 1 else '/ssd2/wyz/AOSP/art/oatcheck/qiyi_diff.log'
    result_file = sys.argv[2] if len(sys.argv) > 2 else '/ssd2/wyz/AOSP/art/oatcheck/qiyi_result.log'

    # Read result file content for searching
    with open(result_file, 'r') as f:
        result_content = f.read()

    # Parse diff file and find missing methods
    missing = []
    with open(diff_file, 'r') as f:
        for line_num, line in enumerate(f, 1):
            if line.startswith('METHOD: '):
                method_sig = line[8:].strip()
                converted = convert_method_name(method_sig)
                if converted and converted not in result_content:
                    missing.append((line_num, method_sig))

    # Output results
    if missing:
        print(f"Found {len(missing)} methods in diff but not in result:")
        for line_num, method_sig in missing:
            print(f"Line {line_num}: {method_sig}")
    else:
        print("All diff methods found in result")

if __name__ == '__main__':
    main()