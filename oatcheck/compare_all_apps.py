#!/usr/bin/env python3
"""
Compare OAT files between 15.0.0_r3 and 15.0.0_r5 for all apps.
Usage: python3 compare_all_apps.py [--max-diffs N] [--verbose]
"""

import os
import sys
import subprocess
import argparse

DEFAULT_AOSP_ROOT = "/ssd2/wyz/AOSP"
APP_OATS_BASE = "/ssd2/wyz/app_oats"

def run_test_fix_validation(aosp_root, fixed_oat, original_oat, max_diffs=100, verbose=False):
    """Run test_fix_validation to compare two OAT files."""
    host_script = "/ssd2/wyz/AOSP/art/oatcheck/test_fix_validation_host.py"

    cmd = [
        "python3", host_script,
        "--fixed-oat=" + fixed_oat,
        "--original-oat=" + original_oat,
        "--compare-code",
        "--max-diffs=" + str(max_diffs)
    ]

    env = os.environ.copy()
    env["AOSP_ROOT"] = aosp_root

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            env=env,
            timeout=300
        )
        return result.stdout + result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "TIMEOUT", -1
    except Exception as e:
        return f"ERROR: {e}", -1

def parse_output(output):
    """Parse test_fix_validation output to extract stats."""
    stats = {
        "identical": 0,
        "different": 0,
        "only_in_fixed": 0,
        "only_in_original": 0,
        "methods": []
    }

    lines = output.split("\n")
    for i, line in enumerate(lines):
        if "Identical methods:" in line:
            try:
                stats["identical"] = int(line.split(":")[-1].strip())
            except:
                pass
        elif "Different methods:" in line:
            try:
                stats["different"] = int(line.split(":")[-1].strip())
            except:
                pass
        elif "Only in fixed:" in line:
            try:
                stats["only_in_fixed"] = int(line.split(":")[-1].strip())
            except:
                pass
        elif "Only in original:" in line:
            try:
                stats["only_in_original"] = int(line.split(":")[-1].strip())
            except:
                pass
        elif "METHOD:" in line:
            method_info = line.replace("METHOD:", "").strip()
            stats["methods"].append(method_info)

    return stats

def compare_apps(r3_base, r5_base, max_diffs=100, verbose=False):
    """Compare all apps between r3 and r5."""
    apps = []

    # List all apps in r3
    if not os.path.exists(r3_base):
        print(f"Error: {r3_base} does not exist")
        return

    for app_name in sorted(os.listdir(r3_base)):
        app_dir = os.path.join(r3_base, app_name)
        if not os.path.isdir(app_dir):
            continue

        r3_odex = os.path.join(app_dir, "oat", "base.odex")
        r5_odex = os.path.join(r5_base, app_name, "oat", "base.odex")

        if not os.path.exists(r3_odex):
            continue
        if not os.path.exists(r5_odex):
            print(f"  [SKIP] {app_name}: r5 odex not found")
            continue

        apps.append({
            "name": app_name,
            "r3_odex": r3_odex,
            "r5_odex": r5_odex
        })

    return apps

def main():
    parser = argparse.ArgumentParser(description="Compare OAT files between r3 and r5 for all apps")
    parser.add_argument("--max-diffs", type=int, default=100, help="Maximum differences to show per app")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show detailed output")
    parser.add_argument("--aosp-root", default=DEFAULT_AOSP_ROOT, help="AOSP root directory")
    args = parser.parse_args()

    r3_base = os.path.join(APP_OATS_BASE, "15.0.0_r3")
    r5_base = os.path.join(APP_OATS_BASE, "15.0.0_r5")

    print(f"Comparing apps: {r3_base} -> {r5_base}")
    print("=" * 80)

    apps = compare_apps(r3_base, r5_base, args.max_diffs, args.verbose)
    print(f"Found {len(apps)} apps to compare\n")

    results = []
    for app in apps:
        print(f"Comparing {app['name']}...", end=" ", flush=True)

        output, returncode = run_test_fix_validation(
            args.aosp_root,
            app["r5_odex"],
            app["r3_odex"],
            args.max_diffs,
            args.verbose
        )

        stats = parse_output(output)

        total = stats["identical"] + stats["different"] + stats["only_in_fixed"] + stats["only_in_original"]
        if total == 0:
            print(f"ERROR - no methods found")
            results.append({**app, "status": "error", **stats})
            continue

        status = "different" if stats["different"] > 0 else "identical"
        print(f"identical={stats['identical']}, different={stats['different']}, only_in_fixed={stats['only_in_fixed']}, only_in_original={stats['only_in_original']}")

        if args.verbose and stats["methods"]:
            for method in stats["methods"][:5]:
                print(f"    {method}")
            if len(stats["methods"]) > 5:
                print(f"    ... and {len(stats['methods']) - 5} more")

        results.append({**app, "status": status, **stats})

    # Print summary table
    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print(f"{'App':<50} {'Identical':<12} {'Different':<12} {'Status'}")
    print("-" * 90)

    for r in results:
        if r["status"] == "identical":
            status_str = "OK"
        elif r["status"] == "different":
            status_str = "DIFF"
        else:
            status_str = "ERROR"
        print(f"{r['name']:<50} {r['identical']:<12} {r['different']:<12} {status_str}")

    # Count stats
    identical_count = sum(1 for r in results if r["status"] == "identical")
    different_count = sum(1 for r in results if r["status"] == "different")
    error_count = sum(1 for r in results if r["status"] == "error")

    print("-" * 90)
    print(f"Total: {len(results)} apps | {identical_count} identical | {different_count} different | {error_count} errors")

if __name__ == "__main__":
    main()