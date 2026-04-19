#!/usr/bin/env python3

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import art_host

DEFAULT_AOSP_ROOT = "/ssd2/wyz/AOSP"

def run_host(aosp_root: str, *args):
    app = os.path.join(aosp_root, "out", "host", "linux-x86", "bin", "test_fix_validation")
    art_host.run_host(app, aosp_root, "", *args)

if __name__ == "__main__":
    aosp_root = os.environ.get("AOSP_ROOT", DEFAULT_AOSP_ROOT)
    sys.exit(run_host(aosp_root, *sys.argv[1:]))