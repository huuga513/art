#!/usr/bin/env python3
"""Run oatcheck 3 times and generate efficiency table."""

import os
import sys
import re
import subprocess
import time
from pathlib import Path

OATCHECK_DIR = Path("/ssd2/wyz/AOSP/art/oatcheck")
OATCHECK_HOST = OATCHECK_DIR / "oatcheck_host.py"
BASE_DIR = Path("/ssd2/wyz/app_oats")
OLD_VER = "15.0.0_r3"
NEW_VER = "15.0.0_r5"
RESULT_PREFIX = "result_"

PACKAGE_INFO = {
    "com.UCMobile": (1, "18.1.8.1444"),
    "com.autonavi.minimap": (2, "16.03.0.2025"),
    "com.baidu.searchbox": (3, "15.33.0.12"),
    "com.dragon.read": (4, "6.9.5.32"),
    "com.eg.android.AlipayGphone": (5, "10.7.90.8100"),
    "com.qiyi.video": (6, "16.10.5"),
    "com.sina.weibo": (7, "15.10.3"),
    "com.smile.gifmaker": (8, "13.0.10.40231"),
    "com.ss.android.article.news": (9, "14.3.0"),
    "com.ss.android.article.video": (10, "9.9.4"),
    "com.ss.android.ugc.aweme": (11, "36.4.0"),
    "com.taobao.taobao": (12, "10.55.0"),
    "com.tencent.mm": (13, "8.0.64"),
    "com.tencent.mobileqq": (14, "9.2.27"),
    "com.tencent.mtt": (15, "19.5.5.5063"),
    "com.tencent.qqlive": (16, "9.02.30.30710"),
    "com.xingin.xhs": (17, "9.6.0"),
    "com.xunmeng.pinduoduo": (18, "7.81.0"),
    "com.youku.phone": (19, "11.1.61"),
    "tv.danmaku.bili": (20, "8.68.0"),
}

def get_app_list():
    apps = []
    app_dir = BASE_DIR / OLD_VER
    if not app_dir.exists():
        print(f"Error: {app_dir} does not exist", file=sys.stderr)
        return apps
    for app_path in sorted(app_dir.iterdir()):
        if app_path.is_dir():
            apps.append(app_path.name)
    return apps

def run_oatcheck(app_name, run_idx, result_log):
    apk = BASE_DIR / OLD_VER / app_name / "base.apk"
    oat = BASE_DIR / OLD_VER / app_name / "oat" / "base.odex"

    cmd = [
        "python3", str(OATCHECK_HOST),
        f"--apk={apk}",
        f"--oat={oat}",
        "--origin-bcp-prefix=/ssd2/wyz/bcp_classes/15r3",
        "--updated-bcp-prefix=/ssd2/wyz/bcp_classes/15r5",
    ]

    with open(result_log, 'w') as f:
        result = subprocess.run(cmd, capture_output=True, text=True)
        f.write(result.stdout)
        f.write(result.stderr)

def parse_processing_time(log_path):
    """Parse processing time from result log."""
    pattern = re.compile(r"Processing time: ([\d.]+) s")
    with open(log_path, 'r') as f:
        for line in f:
            m = pattern.search(line)
            if m:
                return float(m.group(1))
    return None

def parse_compiled_method_count(log_path):
    """Parse compiled method count from result log."""
    pattern = re.compile(r"Precomputed (\d+) compiled methods from OAT file")
    with open(log_path, 'r') as f:
        for line in f:
            m = pattern.search(line)
            if m:
                return int(m.group(1))
    return None

def generate_latex_table(timing_data):
    """Generate LaTeX table code."""
    lines = []
    lines.append(r"\begin{table}[htb]")
    lines.append(r"    \centering")
    lines.append(r"    \caption{OatCheck分析效率}")
    lines.append(r"    \label{tab:oatcheck-efficiency}")
    lines.append(r"    \begin{tabular}{l|l|l|l|l|l|l}")
    lines.append(r"    \toprule")
    lines.append(r"    序号 & 应用 & 方法数 & 耗时1(s) & 耗时2(s) & 耗时3(s) & 平均值(s) \\")
    lines.append(r"    \hline")

    for pkg_name in sorted(PACKAGE_INFO.keys(), key=lambda x: PACKAGE_INFO[x][0]):
        if pkg_name not in timing_data:
            continue
        data = timing_data[pkg_name]
        times = data['times']
        compiled = data['compiled_methods']
        seq = PACKAGE_INFO[pkg_name][0]
        avg = sum(times) / len(times)
        compiled_str = str(compiled) if compiled is not None else "-"
        lines.append(f"    {seq} & {pkg_name} & {compiled_str} & {times[0]:.3f} & {times[1]:.3f} & {times[2]:.3f} & {avg:.3f} \\\\")

    lines.append(r"    \bottomrule")
    lines.append(r"    \end{tabular}")
    lines.append(r"\end{table}")

    return "\n".join(lines)

def main():
    apps = get_app_list()
    if not apps:
        print("No apps found", file=sys.stderr)
        return

    timing_data = {}
    run_count = 3

    for app_name in apps:
        print(f"Processing {app_name}...", file=sys.stderr)
        times = []
        compiled_methods = None
        for run_idx in range(run_count):
            result_log = OATCHECK_DIR / f"{RESULT_PREFIX}{app_name}_run{run_idx}.log"
            print(f"  Run {run_idx + 1}...", file=sys.stderr)
            run_oatcheck(app_name, run_idx, result_log)

            time = parse_processing_time(result_log)
            if time is not None:
                times.append(time)
                print(f"    Processing: {time:.3f}s", file=sys.stderr)
            else:
                print(f"    WARNING: Processing time not found in log", file=sys.stderr)

            # Parse compiled method count from first run
            if run_idx == 0:
                compiled_methods = parse_compiled_method_count(result_log)
                if compiled_methods is not None:
                    print(f"    Compiled methods: {compiled_methods}", file=sys.stderr)

        if times:
            timing_data[app_name] = {'times': times, 'compiled_methods': compiled_methods}

    latex_code = generate_latex_table(timing_data)
    print(latex_code)

if __name__ == "__main__":
    main()