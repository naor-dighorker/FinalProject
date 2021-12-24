from scapy.all import*
from scapy.layers.l2 import ARP, Ether
import subprocess
import socket
import time

DIGITS = ["1","2","3","4","5","6","7","8","9","0"]


# Get the ip and subnet of the machine
def get_configs():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.connect(("8.8.8.8", 80))
    my_ip = sock.getsockname()[0]
    p = subprocess.Popen('cmd /u /c ipconfig', stdout=subprocess.PIPE)
    result = p.communicate()[0]
    result = str(result).replace("\\r\\n", "")
    result = result.split("  ")

    ip = ""
    ip_line = ""
    subnet_line = ""
    default_gateway = ""

    # finds the first ip and subnet
    for line in result:
        if line.find("IPv4") != -1:
            ip_line = line
            ip = ip_line.split(":")[1].strip()
        elif line.find("Subnet") != -1 and my_ip == ip:
            subnet_line = line
        elif line.find("Default Gateway") != -1 and my_ip == ip:
            default_gateway = line
        if default_gateway and subnet_line:
            break

    default_gateway = default_gateway.split(":")[1].strip().replace("'", "")
    default_gateway2 = ""
    for c in default_gateway:
        if c in DIGITS or c == ".":
            default_gateway2 += c

    subnet = subnet_line.split(":")[1].strip()

    subnet_number = subnet.split(".")
    sum_bin = 0
    # sums the active bits in the subnet
    for i in subnet_number:
        sum_bin += bin(int(i)).count("1")

    return ip, str(sum_bin), default_gateway2


def scan(ip, subnet, gateway):
    # Set the network range
    target_range = ip + "/" + subnet
    # create ARP packet
    arp_layer = ARP(pdst=target_range)
    # create the Ethernet broadcast packet
    ether_layer = Ether(dst="ff:ff:ff:ff:ff:ff")
    # creating the packets
    packets = ether_layer/arp_layer
    results = ""
    try_count = 0

    # srp - sends packets at layer 2 ,[0] - contains the answered packets, result is a list of [sent, received] packets
    while len(results) == 0 and try_count != 5:
        results = srp(packets, timeout=3, verbose=0)[0]
        try_count += 1

    clients = []

    if len(results) != 0:
        for sent, received in results:
            # psrc is the ip and hwsrc is the mac of the client that needs to be updated
            if received.psrc != gateway and received.psrc != ip:
                clients.append({'ip': received.psrc, 'mac': received.hwsrc})
    return clients


if __name__ == '__main__':
    ip, subnet, default_gate = get_configs()
    time.sleep(2)
    clients = scan(ip, subnet, default_gate)
    print("IP" + " "*15 + "MAC")
    if clients:
        for client in clients:
            print("{}   {}".format(client['ip'], client['mac']))
    else:
        print("scan failed")
