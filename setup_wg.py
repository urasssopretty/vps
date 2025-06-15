#!/usr/bin/env python3

import os
import sys
import platform
import shutil
import subprocess


SUPPORTED_OS = ["Ubuntu", "Debian"] #TODO: add arch-like

currentOS = None

SERVER_PUB_IP = None
SERVER_PUB_NIC = None
SERVER_WG_NIC = "wg0"
SERVER_WG_IPV4 = "10.66.66.1"
SERVER_PORT = "56023"
MTU = "1420"
SERVER_PRIV_KEY = None
SERVER_PUB_KEY = None

CLIENT_DNS_1 = "1.1.1.1"
CLIENT_DNS_2 = "1.0s.0.1"
ALLOWED_IPS = "0.0.0.0/0,::0"


def run(cmd):
    print(f"Running: \"{cmd}\"")
    result = subprocess.run(
        cmd.split(),
        capture_output=True, text=True, check=False
    )

    if result.returncode != 0:
        raise RuntimeError(f"ERROR: {result.stderr}")

    return result.stdout.strip().splitlines()


# INITIALIZTION
def check_root_permission():
    # TODO: mb that way isn't too good
    if 'SUDO_UID'not  in os.environ:
        raise RuntimeError("ERROR: run script with sudo\n"
                           "EXAMPLE: sudo python3 ./setup_wg.py")


def check_os_support():
    global currentOS
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



# INSTALLATION
def install_wireguard():
    def get_public_ip():
        # TODO: IPv6
        result = run("ip -4 addr")
        lines = [result[i+1].strip() for i in range(0, len(result), 3)]

        for line in lines:
            if "inet" in line and "scope global" in line:
                return line.split()[1]

        raise RuntimeError("ERROR: there is no public ip, check ur connection to network")

    def get_public_interface():
        result = run("ip -4 route ls")
        for line in result:
            if "default" in line and "dev" in line:
                line = line.strip().split()
                index = line.index("dev") + 1
                return line[index]

        raise RuntimeError("ERROR: there no public interface, check ur connection to network")

    global SERVER_PUB_IP
    global SERVER_PUB_NIC
    global SERVER_PUB_NIC
    global SERVER_PUB_NIC
    SERVER_PUB_IP = get_public_ip()
    SERVER_PUB_NIC = get_public_interface()

    # if (currentOS == "Ubuntu"):
    #     run("apt-get install -y wireguard iptables resolvconf qrencode")
    # else:
    #     raise RuntimeError("ERROR: Your OS does NOT supported")
    
    # run("mkdir /etc/wireguard")

    # run("chmod 600 -R /etc/wireguard/")

    SERVER_PRIV_KEY = run("wg genkey")[0]
    SERVER_PRIV_KEY = run(f"echo {SERVER_PRIV_KEY} | wg pubkey")

    wireguard_server_config = f"""SERVER_PUB_IP={SERVER_PUB_IP}
SERVER_WG_NIC={SERVER_WG_NIC}
SERVER_WG_IPV4={SERVER_WG_IPV4}
SERVER_PORT={SERVER_PORT}
SERVER_PRIV_KEY={SERVER_PRIV_KEY}
SERVER_PUB_KEY={SERVER_PUB_KEY}
CLIENT_DNS_1={CLIENT_DNS_1}
CLIENT_DNS_2={CLIENT_DNS_2}
ALLOWED_IPS={ALLOWED_IPS}"""

    with open("/etc/wireguard/params", "w") as server_config:
        server_config.write(wireguard_server_config)

    wireguard_server_interface = f"""Address = {SERVER_WG_IPV4}/24
ListenPort = {SERVER_PORT}
PrivateKey = {SERVER_PRIV_KEY}
MTU = {MTU}"""
    
    with open(f"/etc/wireguard/{SERVER_WG_NIC}.conf") as wgconf:
        wgconf.write(wireguard_server_interface)
    



# MEN
def manage_menu():
    pass


def generate_server_keys():
    pass

# def wireguard_settings():
#     pass

# def wg_server_interface():
#     pass




def main():
    check_root_permission()
    check_os_support()
    check_virtualization_support()

    if (os.path.exists("/etc/wireguard/params")):
        manage_menu()
    else:
        install_wireguard()

    # prepare_server_info()


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(e)
