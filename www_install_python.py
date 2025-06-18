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
SERVER_WG_IPV4 = "10.0.0.1/8"
SERVER_PORT = "56023"
# MTU = "1420"
SERVER_PRIV_KEY = None
SERVER_PUB_KEY = None

CLIENT_DNS_1 = "1.1.1.1"
CLIENT_DNS_2 = "1.0s.0.1"
ALLOWED_IPS = "0.0.0.0/0,::0"



def run(cmd: str):
    print(f"Running: \"{cmd}\"")
    result = subprocess.run(
        cmd.split(),
        capture_output=True, text=True, check=False
    )

    if result.returncode != 0:
        raise RuntimeError(f"ERROR: {result.stderr}")

    return result.stdout.strip().splitlines()


def run_with_pipe(cmd: str):
    print(f"Running: \"{cmd}\"")
    result = subprocess.run(
        cmd.split(),
        capture_output=True, text=True, check=False, shell=True
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

    def get_private_key():
        return run("wg genkey")[0]
    
    def get_public_key(private_key: str):
        process = subprocess.Popen(
            ["wg", "pubkey"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        stdout, stderr = process.communicate(input=private_key + "\n")

        if (process.returncode != 0):
            raise RuntimeError(f"ERROR (pubkey generation): e")

        return stdout.strip()

    # if (currentOS == "Ubuntu"):
    #     run("apt-get install -y wireguard iptables resolvconf qrencode")
    # else:
    #     raise RuntimeError("ERROR: Your OS does NOT supported")
    
    # run("mkdir /etc/wireguard")

    # run("chmod 600 -R /etc/wireguard/")

    global SERVER_PUB_IP
    global SERVER_PUB_NIC
    global SERVER_PUB_NIC
    global SERVER_PUB_NIC

    SERVER_PUB_IP = get_public_ip()
    SERVER_PUB_NIC = get_public_interface()
    SERVER_PRIV_KEY = get_private_key()
    SERVER_PUB_KEY= get_public_key(SERVER_PRIV_KEY)
    
    wireguard_server_params = [
        f"SERVER_PUB_IP={SERVER_PUB_IP}",
        f"SERVER_WG_NIC={SERVER_WG_NIC}",
        f"SERVER_WG_IPV4={SERVER_WG_IPV4}",
        f"SERVER_PORT={SERVER_PORT}",
        f"SERVER_PRIV_KEY={SERVER_PRIV_KEY}",
        f"SERVER_PUB_KEY={SERVER_PUB_KEY}",
        f"CLIENT_DNS_1={CLIENT_DNS_1}",
        f"CLIENT_DNS_2={CLIENT_DNS_2}",
        f"ALLOWED_IPS={ALLOWED_IPS}"
    ]

    with open("/etc/wireguard/params", "w") as params:
        params.write(wireguard_server_params)

    wireguard_server_config = [
        "[Interface]"
        f"Address = {SERVER_WG_IPV4}/24",
        f"ListenPort = {SERVER_PORT}",
        f"PrivateKey = {SERVER_PRIV_KEY}",
        # f"MTU = {MTU}",
        f"PostUp = iptables -I INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT",
        f"PostUp = iptables -I FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_WG_NIC} -j ACCEPT",
        f"PostUp = iptables -I FORWARD -i ${SERVER_WG_NIC} -j ACCEPT",
        f"PostUp = iptables -t nat -A POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE",
        # f"PostUp = ip6tables -I FORWARD -i ${SERVER_WG_NIC} -j ACCEPT",
        # f"PostUp = ip6tables -t nat -A POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE",
        f"PostDown = iptables -D INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT",
        f"PostDown = iptables -D FORWARD -i ${SERVER_WG_NIC} -o ${SERVER_WG_NIC} -j ACCEPT",
        f"PostDown = iptables -D FORWARD -i ${SERVER_WG_NIC} -j ACCEPT",
        f"PostDown = iptables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE",
        # f"PostDown = ip6tables -D FORWARD -i ${SERVER_WG_NIC} -j ACCEPT",
        # f"PostDown = ip6tables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE",
    ]
    
    with open(f"/etc/wireguard/{SERVER_WG_NIC}.conf", "w") as synctl:
        synctl.write(wireguard_server_config)

    synctl_routing = [
        "net.ipv4.ip_forward = 1",
        "net.ipv6.conf.all.forwarding = 1"
    ]

    with open("/etc/synctl.d/wg.conf", "a") as synctl:
        synctl.write(synctl_routing)

    run("sysctl --system")
    run(f"systemctl start \"wg-quick@{SERVER_WG_NIC}\"")
    run(f"systemctl enable \"wg-quick@{SERVER_WG_NIC}\"")

    print(
        run(f"systemctl is-active --quite \"wg-quick{SERVER_WG_NIC}\"")
    )

    # run("wg-quick up wg0")



# MEN
def manage_menu():
    print("menu")


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


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(e)
        exit(-1)
