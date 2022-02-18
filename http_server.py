import socket
import os
import logging

DEFAULT_URL = r'C:\Users\USER\faweb\index.html'
IP = '0.0.0.0'
PORT = 80
SOCKET_TIMEOUT = 100


# gets data from file
def get_file_data(filename):
    if os.path.isfile(filename):
        file = open(filename, 'rb')
        data = file.read()
        size = os.stat(filename).st_size
        file.close()
        return data, size
    return "Error", None


# checks the required resource, generate proper HTTP response and send to client
def handle_client_request(resource, client_socket):
    if resource == '':
        url = DEFAULT_URL
    else:
        url = resource

    new_url = url
    new_url = new_url.split('.')
    http_header = "HTTP/1.1 200 OK\r\n"

    if len(new_url) != 1:
        filetype = new_url[1]
        filename = url
        # generates headers for the filetypes
        if filetype == 'html' or filetype == 'txt':
            http_header += "Content-Type: text/html; charset=utf-8\r\n"
        elif filetype == 'jpg':
            http_header += "Content-Type: image/jpeg\r\n"
        elif filetype == 'js':
            http_header += "Content-Type: text/javascript; charset=UTF-8\r\n"
        elif filetype == 'css':
            http_header += "Content-Type: text/css\r\n"

        # gets data from file
        data, size = get_file_data(filename)
        http_header += "Content-Length: " + str(size) + "\r\n"
        http_header += "\r\n"
        http_response = http_header.encode() + data
        client_socket.sendall(http_response)

    # plain text
    else:
        print(resource)
        http_header += "Content-Type: text/plain\r\n"
        http_header += "\r\n"
        http_response = http_header.encode()
        client_socket.sendall(http_response)


# checks if request is a valid HTTP request and returns TRUE / FALSE and the requested URL
def validate_http_request(request):
    # pieces[0] contains the GET request
    pieces = request.split("\n")
    try:
        if len(pieces) > 0:
            get_req = pieces[0].split(" ")
            # get_req[1] contains the resource
            if get_req[1] == '/':
                return True, DEFAULT_URL
            return True, r'C:\Users\USER\faweb' + get_req[1]
    except Exception as e:
        print(str(e))
    return False, None


# handles client requests: verifies client's requests are legal HTTP, calls function to handle the requests
def handle_client(client_socket):
    print('Client connected')
    while True:
        try:
            client_request = client_socket.recv(5000).decode()
        except Exception as e:
            print(str(e))
            break
        valid_http, resource = validate_http_request(client_request)
        if valid_http:
            print('Got a valid HTTP request')
            handle_client_request(resource, client_socket)
            break
        else:
            print('Error: Not a valid HTTP request')
            break
    print('Closing connection')
    client_socket.close()


def main():
    logging.basicConfig(filename="connections.log", level=logging.INFO,
                        format="%(asctime)s : %(message)s")
    logging.info("Starting http server")
    # opens a socket and loop forever while waiting for clients
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((IP, PORT))
    server_socket.listen()
    print("Listening for connections on port {}".format(PORT))

    while True:
        client_socket, client_address = server_socket.accept()
        logging.info("{} connected".format(client_address))
        print('New connection received')
        client_socket.settimeout(SOCKET_TIMEOUT)
        handle_client(client_socket)


if __name__ == "__main__":
    # calls the main handler function
    main()
