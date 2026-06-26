import uuid
import socket
from threading import Thread

from logger.attack_logger import save_login, disconnect
from server.shell import fake_shell
from server.state import active_connection, state_lock


def client_handler(client_sock, client_addr):
    is_root = False
    session_id = str(uuid.uuid4())
    client_ip, client_port = client_addr

    print("Successful Connect to Server")
    print("==========================Client info==========================")
    print(f"IP: {client_ip}, PORT: {client_port}")
    print()

    try:
        client_sock.send(b"username: ")
        username = client_sock.recv(1024).decode(errors="ignore").strip()
        client_sock.send(b"password: ")
        password = client_sock.recv(1024).decode(errors="ignore").strip()

        print(f"[{client_ip} -> USERNAME: {username}, PASSWORD: {password}]")
        save_login(session_id, client_ip, username, password, "TCP")

        with state_lock:
            active_connection[session_id] = {
                "ip": client_ip,
                "username": username,
                "protocol": "TCP"
            }

        fake_shell(client_sock, session_id, username, client_ip, is_root, "TCP")
    finally:
        disconnect(session_id, client_ip, "TCP")
        with state_lock:
            active_connection.pop(session_id, None)
        client_sock.close()


def start_tcp_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(("0.0.0.0", 7777))
    server_socket.listen()
    print("[TCP] Listening on 0.0.0.0:7777\n")

    while True:
        client_socket, client_address = server_socket.accept()
        Thread(target=client_handler,
               args=(client_socket, client_address),
               daemon=True).start()