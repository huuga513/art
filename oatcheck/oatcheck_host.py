import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import art_host

if __name__ == "__main__":
    aosp_root = "/ssd2/wyz/AOSP"
    app = "out/host/linux-x86/bin/oatcheck"
    art_host.run_host(app, aosp_root, "", *sys.argv[1:])