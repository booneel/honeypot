import socket
from threading import Thread
import uuid
import paramiko
from logger.attack_logger import save_login, disconnect
from server.shell import fake_shell
from server.state import active_connection, state_lock
from config import KEY_PATH

HOST_KEY = paramiko.RSAKey(filename=KEY_PATH)

class SSHServer(paramiko.ServerInterface):
    def __init__(self):
        super().__init__()
        username = None
        password = None

    def check_auth_password(self, username, password):
        self.username = username
        self.password = password
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, channel):
        return True

    def check_channel_pty_request(
            self,
            channel,
            term,
            width,
            height,
            pixelwidth,
            pixelheight,
            modes
    ):
        return True

def ssh_client_handler(client_socket, client_address):
    transport = None
    session_id = str(uuid.uuid4())
    client_ip, client_port = client_address

    try:
        transport = paramiko.Transport(client_socket)
        transport.add_server_key(HOST_KEY)

        server = SSHServer()
        transport.start_server(server=server)

        channel = transport.accept(20)

        if channel is None:
            return
        print("Successful Connect to Server")
        print("==========================Client info==========================")
        print(f"IP: {client_ip}, PORT: {client_port}")
        print()
        print(f"[{client_ip} -> USERNAME: {server.username}, PASSWORD: {server.password}]")
        save_login(session_id, client_ip, server.username, server.password, "SSH")

        with state_lock:
            active_connection[session_id] = {
                "ip": client_ip,
                "username": server.username,
                "protocol": "SSH"
            }

        fake_shell(
            channel,
            session_id,
            server.username,
            client_ip,
            False,
            "SSH"
        )

    finally:
        disconnect(session_id, client_ip, "SSH")

        with state_lock:
            active_connection.pop(session_id, None)

        if transport:
            transport.close()

        client_socket.close()

def start_ssh_server():
    server_socket = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM,
    )
    server_socket.setsockopt(
        socket.SOL_SOCKET,
        socket.SO_REUSEADDR,
        1
    )
    server_socket.bind(("0.0.0.0", 2222))
    server_socket.listen(100)
    print("[SSH] Listening on 0.0.0.0:2222")

    while True:
        client_socket, client_address = server_socket.accept()
        Thread(
            target=ssh_client_handler,
            args=(client_socket, client_address),
            daemon=True
        ).start()
