import os
import glob
import re
import subprocess
config={
    "AOSP_ROOT":"/ssd2/wyz/AOSP"
}

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

def run_host(app: str, asop_root: str, dbg:bool, *args):
    # 获取运行时参数
    runtime_args = extract_art_invocation_args(asop_root)
    
    # 设置基本命令及其参数
    base_command = ["lldb", "--"] if dbg else []
    base_command += [app]
    base_command += ["--runtime-arg", "-Xms64m"]
    base_command += ["--runtime-arg", "-Xmx512m"]
    base_command += ["--runtime-arg", f"-Xbootclasspath:{runtime_args.get('BOOT_CLASS_PATH', '')}"]
    base_command += ["--runtime-arg", f"-Xbootclasspath-locations:{runtime_args.get('BOOT_CLASS_PATH_LOCATION', '')}"]
    base_command += ["--runtime-arg", f"-Ximage:{runtime_args.get('IMAGE_LOCATION', '')}"]
    base_command += ["--runtime-arg", "-Xgc:CMC"]
    base_command += ["--instruction-set=arm64"]
    base_command += [f"--boot-image={runtime_args.get('IMAGE_LOCATION', '')}"]

    # 添加额外的命令行参数
    command = base_command + list(args)

    print(" ".join(command))

    # 执行命令并传递控制权
    try:
        subprocess.run(command, cwd=config["AOSP_ROOT"], check=True)
    except Exception as e:
        print(f"An error occurred while executing the command: {e}")

if __name__ == "__main__":
    import sys
    run_host("oatcheck", config["AOSP_ROOT"],False, *sys.argv[1:])