#!/usr/bin/env python3

import os
import platform
import shutil
import subprocess


SUPPORTED_OS = ["Ubuntu", "Debian"] #TODO: add arch-like

currentOS = None

serverPublicIP = None
serverPublicName = None
serverIpv4 = None
serverPort = "56023"


def is_running_as_root() -> bool:
    return 'SUDO_UID' in os.environ


def check_os_support():
    os_info = platform.freedesktop_os_release()
    currentOS = os_info["NAME"]
    if currentOS not in SUPPORTED_OS:
        raise RuntimeError(f"ERROR: Unsupported OS. Looks like you are NOT running this installer on a {"/".join(SUPPORTED_OS)}")


def check_virtualization_support():
    tool = None

    if shutil.which("virt-what"):
        tool = "virt-what"
    elif shutil.which("systemd-detect-virt"):
        tool = "systemd-detect-virt"
    else:
        raise RuntimeError("Error: Cannot detect virtualization environment.\n"
                        "Please install 'virt-what' or use a systemd-based OS.")
    
    try:
        result = subprocess.run([tool], capture_output=True, text=True, check=True)
        virt_type = result.stdout.strip().lower()
    except subprocess.CalledProcessError:
        raise RuntimeError("Failed to execute virtualization detection tool.")
    
    if virt_type == "openvz":
        raise RuntimeError("ERROR: OpenVZ is not supported.")
    elif virt_type == "lxc":
        raise RuntimeError(
            "ERROR: LXC is not supported (yet).\n"
            "WireGuard can technically run in an LXC container,\n"
            "but the kernel module has to be installed on the host,\n"
            "the container has to be run with specific parameters,\n"
            "and only the tools need to be installed in the container."
        )



def prepare_server_info():
    def get_public_ip():
        result = subprocess.run(["ip", "-4", "addr"], capture_output=True, text=True, check=True)
        lines = result.stdout.strip().splitlines()

        for line in lines:
            line = line.strip()
            if "inet" in line and "scope global" in line:
                ip_part = line.split()[1]
                ip_addr = ip_part.split("/")[0]

    serverPublicIP = get_public_ip()
    print(serverPublicIP)
    pass
    



def main():
    root_acess = is_running_as_root()
    check_os_support()
    check_virtualization_support()



if __name__ == "setup_wg.py":
    main()
