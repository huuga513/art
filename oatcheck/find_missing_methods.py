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

    # Parse result file for "Total AOT-invalidated methods: XXXX"
    result_methods = 0
    for line in result_content.split('\n'):
        match = re.match(r'Total AOT-invalidated methods:\s*(\d+)', line)
        if match:
            result_methods = int(match.group(1))
            break

    # Parse diff file and find missing methods
    diff_methods = []
    with open(diff_file, 'r') as f:
        for line_num, line in enumerate(f, 1):
            if line.startswith('METHOD: '):
                method_sig = line[8:].strip()
                converted = convert_method_name(method_sig)
                diff_methods.append((line_num, method_sig, converted))

    # Find missing methods
    missing = [(ln, sig) for ln, sig, converted in diff_methods if converted and converted not in result_content]

    # Output results
    if missing:
        print(f"Found {len(missing)} methods in diff but not in result:")
        for line_num, method_sig, _ in missing:
            print(f"Line {line_num}: {method_sig}")
    else:
        print("All diff methods found in result")

    # Output ratio: diff_methods / result_methods
    if result_methods > 0:
        ratio = (len(diff_methods) / result_methods) * 100
        print(f"diff/result = {len(diff_methods)} / {result_methods} = {ratio:.2f}%")
    else:
        print("diff/result = N/A (result_methods is 0)")

if __name__ == '__main__':
    main()