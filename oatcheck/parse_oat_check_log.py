#!/usr/bin/env python3
"""Parse oatcheck log and generate comparison table."""

import sys
import re
import argparse


# Package name to sequence number and version mapping from the reference table
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


def parse_log(filepath):
    """Parse oatcheck log file and extract data."""
    data = {}
    current_package = None

    with open(filepath, 'r') as f:
        for line in f:
            # Match package name line: "===== Processing com.example ====="
            pkg_match = re.match(r'^===== Processing (\S+) =====$', line.strip())
            if pkg_match:
                current_package = pkg_match.group(1)
                data[current_package] = {'diff_count': 0, 'oatcheck_count': 0, 'all_found': False}
                continue

            # Match diff/result line: "diff/result = 4 / 268 = 1.49%"
            diff_match = re.match(r'^diff/result = (\d+) / (\d+) = .*$', line.strip())
            if diff_match and current_package:
                data[current_package]['diff_count'] = int(diff_match.group(1))
                data[current_package]['oatcheck_count'] = int(diff_match.group(2))
                continue

            # Match "All diff methods found in result" - means no missed report
            if line.strip() == "All diff methods found in result" and current_package:
                data[current_package]['all_found'] = True

    return data


def generate_latex_table(data):
    """Generate LaTeX table code."""
    lines = []
    lines.append(r"\begin{table}[htb]")
    lines.append(r"    \centering")
    lines.append(r"    \caption{OatCheck comparison results (R3 vs R5).}")
    lines.append(r"    \label{tab:oatcheck-results}")
    lines.append(r"    \begin{tabular}{l|l|l|l|l}")
    lines.append(r"    \toprule")
    lines.append(r"    序号 & 包名 & 机器码存在差异的方法数 & OatCheck报告的方法数 & 是否存在漏报 \\")
    lines.append(r"    \hline")

    for pkg_name in sorted(PACKAGE_INFO.keys(), key=lambda x: PACKAGE_INFO[x][0]):
        if pkg_name not in data:
            continue

        seq, version = PACKAGE_INFO[pkg_name]
        diff_count = data[pkg_name]['diff_count']
        oatcheck_count = data[pkg_name]['oatcheck_count']

        # Check for missed reports: if "All diff methods found in result" appears, no miss
        has_miss = "否" if data[pkg_name]['all_found'] else "是"

        lines.append(f"    {seq} & {pkg_name} & {diff_count} & {oatcheck_count} & {has_miss} \\\\")

    lines.append(r"    \bottomrule")
    lines.append(r"    \end{tabular}")
    lines.append(r"\end{table}")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Parse oatcheck log and generate comparison table.")
    parser.add_argument("log_file", help="Path to the oatcheck log file (e.g., oatcheck/run_oat_check_r3-r5.log)")
    args = parser.parse_args()

    data = parse_log(args.log_file)
    latex_code = generate_latex_table(data)

    print(latex_code)


if __name__ == "__main__":
    main()