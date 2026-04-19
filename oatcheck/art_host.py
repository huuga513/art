#!/usr/bin/env python3

import os
import glob
import re
import subprocess
import argparse

DEFAULT_AOSP_ROOT = "/ssd2/wyz/AOSP"

def extract_art_invocation_args(asop_root: str) -> dict:
    supported_kinds = {"BOOT_CLASS_PATH", "BOOT_CLASS_PATH_LOCATION", "IMAGE_LOCATION"}

    search_pattern = os.path.join(asop_root, "out", "soong", ".intermediates", "art", "**", "javalib.invocation")
    invocation_files = glob.glob(search_pattern, recursive=True)

    filtered = [f for f in invocation_files if "service-art.impl" in f]

    if not filtered:
        raise FileNotFoundError("Failed to find invocations for service-art.impl")

    invocation_file = filtered[0]

    result = {}

    with open(invocation_file, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
    for args_kind in supported_kinds:
        if args_kind == "BOOT_CLASS_PATH":
            match = re.search(r'-Xbootclasspath:([^\s]+)', content)
        elif args_kind == "BOOT_CLASS_PATH_LOCATION":
            match = re.search(r'-Xbootclasspath-locations:([^\s]+)', content)
        elif args_kind == "IMAGE_LOCATION":
            match = re.search(r'--boot-image=([^\s]+)', content)
        if match:
            result[args_kind] = match.group(1)

    return result

def run_host(app: str, aosp_root: str, mode: str = "", *args):
    runtime_args = extract_art_invocation_args(aosp_root)

    base_command = []

    if mode == "debug":
        base_command += ["lldb", "--"]
    elif mode == "perf":
        base_command += ["perf", "record", "-g", "--"]

    if os.path.isabs(app):
        base_command.append(app)
    else:
        base_command.append(os.path.join(aosp_root, app))

    base_command += ["--runtime-arg", "-Xms64m"]
    base_command += ["--runtime-arg", "-Xmx512m"]
    base_command += ["--runtime-arg", f"-Xbootclasspath:{runtime_args.get('BOOT_CLASS_PATH', '')}"]
    base_command += ["--runtime-arg", f"-Xbootclasspath-locations:{runtime_args.get('BOOT_CLASS_PATH_LOCATION', '')}"]
    base_command += ["--runtime-arg", f"-Ximage:{runtime_args.get('IMAGE_LOCATION', '')}"]
    base_command += ["--runtime-arg", "-Xgc:CMC"]
    base_command += ["--instruction-set=arm64"]
    base_command += [f"--boot-image={runtime_args.get('IMAGE_LOCATION', '')}"]

    command = base_command + list(args)

    print(" ".join(command))

    try:
        result = subprocess.run(command, cwd=aosp_root, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Command exited with error: {e}")
    except Exception as e:
        print(f"An error occurred while executing the command: {e}")

def main():
    parser = argparse.ArgumentParser(description="Run AOSP ART host binary with proper runtime arguments")
    parser.add_argument("app", help="Path to the host binary (relative to AOSP_ROOT or absolute)")
    parser.add_argument("--perf", action="store_true", help="Run with perf record -g")
    parser.add_argument("--lldb", action="store_true", help="Run with lldb debugger")
    parser.add_argument("--aosp-root", default=DEFAULT_AOSP_ROOT, help="AOSP root directory")
    parser.add_argument("extra_args", nargs="*", help="Extra arguments to pass to the binary")

    args = parser.parse_args()

    mode = ""
    if args.perf:
        mode = "perf"
    elif args.lldb:
        mode = "debug"

    run_host(args.app, args.aosp_root, mode, *args.extra_args)

if __name__ == "__main__":
    main()