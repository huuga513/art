#!/usr/bin/env python3
"""Generate LaTeX table from oatcheck log file."""

import argparse
import re
import sys


PACKAGE_INFO = {
    1: ("com.UCMobile", "18.1.8.1444", "UC浏览器"),
    2: ("com.autonavi.minimap", "16.03.0.2025", "高德地图"),
    3: ("com.baidu.searchbox", "15.33.0.12", "百度APP"),
    4: ("com.dragon.read", "6.9.5.32", "番茄免费小说"),
    5: ("com.eg.android.AlipayGphone", "10.7.90.8100", "支付宝"),
    6: ("com.qiyi.video", "16.10.5", "爱奇艺"),
    7: ("com.sina.weibo", "15.10.3", "微博"),
    8: ("com.smile.gifmaker", "13.0.10.40231", "快手"),
    9: ("com.ss.android.article.news", "14.3.0", "今日头条"),
    10: ("com.ss.android.article.video", "9.9.4", "西瓜视频"),
    11: ("com.ss.android.ugc.aweme", "36.4.0", "抖音"),
    12: ("com.taobao.taobao", "10.55.0", "淘宝"),
    13: ("com.tencent.mm", "8.0.64", "微信"),
    14: ("com.tencent.mobileqq", "9.2.27", "QQ"),
    15: ("com.tencent.mtt", "19.5.5.5063", "QQ浏览器"),
    16: ("com.tencent.qqlive", "9.02.30.30710", "腾讯视频"),
    17: ("com.xingin.xhs", "9.6.0", "小红书"),
    18: ("com.xunmeng.pinduoduo", "7.81.0", "拼多多"),
    19: ("com.youku.phone", "11.1.61", "优酷"),
    20: ("tv.danmaku.bili", "8.68.0", "哔哩哔哩"),
}


def parse_log(log_path):
    """Parse oatcheck log file to extract method counts."""
    results = {}

    with open(log_path, 'r') as f:
        content = f.read()

    # Pattern to match package section
    package_pattern = re.compile(
        r'===== Processing ([^\s]+) =====.*?'
        r'result/compiled_methods = (\d+) / (\d+)',
        re.DOTALL
    )

    for match in package_pattern.finditer(content):
        pkg_name = match.group(1)
        result_count = int(match.group(2))
        compiled_count = int(match.group(3))
        results[pkg_name] = (result_count, compiled_count)

    return results


def generate_latex_table(results):
    """Generate LaTeX table code."""
    lines = []
    lines.append(r"\begin{table}[htb]")
    lines.append(r"\centering")
    lines.append(r"\caption{OatCheck method analysis results.}")
    lines.append(r"\label{tab:oatcheck}")
    lines.append(r"\begin{tabular}{l|l|r|r|r}")
    lines.append(r"\toprule")
    lines.append(r"序号 & 包名 & 报告方法数 & 总编译方法数 & 占比(\%) \\")
    lines.append(r"\hline")

    for idx in range(1, 21):
        pkg_name = PACKAGE_INFO[idx][0]
        if pkg_name in results:
            result_count, compiled_count = results[pkg_name]
            # Calculate percentage: result/compiled_methods * 100
            ratio = (result_count / compiled_count * 100) if compiled_count > 0 else 0
            lines.append(f"{idx} & {pkg_name} & {result_count} & {compiled_count} & {ratio:.2f} \\\\")
        else:
            lines.append(f"{idx} & {pkg_name} & - & - & - \\\\")

    lines.append(r"\bottomrule")
    lines.append(r"\end{tabular}")
    lines.append(r"\end{table}")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Generate LaTeX table from oatcheck log")
    parser.add_argument("log_file", help="Path to oatcheck log file (e.g., oatcheck/run_oat_check_r3-r5.log)")
    args = parser.parse_args()

    try:
        results = parse_log(args.log_file)
        latex_code = generate_latex_table(results)
        print(latex_code)
    except FileNotFoundError:
        print(f"Error: File not found: {args.log_file}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()