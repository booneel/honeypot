import socket
from threading import Thread
from time import sleep
import uuid
from server.routes import *

from logger.attack_logger import *

def client_handler(client_sock, client_addr):
    is_root = False
    session_id = str(uuid.uuid4())
    print("Successful Connect to Server")
    print("==========================Client info==========================")
    client_ip, client_port = client_addr
    print(f"IP: {client_ip}, PORT: {client_port}")
    print()

    client_sock.send(b"username: ")
    username = client_sock.recv(1024).decode().strip()
    client_sock.send(b"password: ")
    password = client_sock.recv(1024).decode().strip()

    print(f"[{client_ip} -> USERNAME: {username}, PASSWORD: {password}]")
    save_login(session_id, client_ip, username, password)
    active_connection[session_id] = {
        "ip": client_ip,
        "username": username
    }
    fake_shell(client_sock, session_id, username, client_ip, is_root)

def fake_shell(client_sock, session_id, username, ip, has_root):
    client_sock.send(b"Login Successful\n")

    while True:
        prompt_user = "root" if has_root else username
        prompt_symbol = "#" if has_root else "$"

        client_sock.send(f"{prompt_user}@ubuntu:~{prompt_symbol} ".encode())
        data = client_sock.recv(1024).decode().strip()
        if not data:
            break
        save_command(session_id, ip, username, data)
        parts = data.split()

        command = parts[0]
        args = parts[1:]
        info = {
            "time": curr_time(),
            "session_id": session_id,
            "ip": ip,
            "username": username,
            "command": command,
        }
        recent_commands.append(info)

        if command == "whoami":
            client_sock.send(f"{prompt_user}\n".encode())
        elif command == "pwd":
            client_sock.send(f"/home/{username}\n".encode())
        elif command == "ls":
            client_sock.send(b"flag.txt  test.txt\n")
        elif command == "uname":
            if "-a" in args:
                client_sock.send(b"Linux ubuntu 5.15.0-generic x86_64 GNU/Linux\n")
            else:
                client_sock.send(b"Linux\n")
        elif command == "hostname":
            client_sock.send(b"ubuntu\n")
        elif command == "id":
            if has_root:
                client_sock.send(b"uid=0(root) gid=0(root)\n")
            else:
                client_sock.send(f"uid=1000({username}) gid=1000({username})\n".encode())
        elif command == "cat":
            if not args:
                client_sock.send(b"cat: missing operand\n")
            elif args[0] == "flag.txt":
                client_sock.send(b"CTF{fake_flag}\n")
            elif args[0] == "test.txt":
                client_sock.send(b"This is test file\n")
            else:
                client_sock.send(f"cat: {args[0]}: No such file\n".encode())
        elif command == "wget":
            if not args:
                client_sock.send(b"wget: missing URL\n")
            else:
                client_sock.send(f"Connecting to {args[0]}\n".encode())
                sleep(1000)
                client_sock.send(b"Connection timed out\n")
        elif data == "ip a":
            client_sock.send(
                b"""1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536
                    inet 127.0.0.1/8 scope host lo

                    2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500
                        inet 192.168.0.100/24 scope global eth0
                """)
        elif command == "curl":
            if not args:
                client_sock.send(b"curl: missing URL\n")
            else:
                sleep(1000)
                client_sock.send(b"curl: (7) Failed to connect\n")
        elif command == "su" or command == "sudo":
            has_root = True
        elif command == "exit":
            if has_root:
                has_root = False
            else:
                client_sock.send(b"logout\n")
                break
        else:
            client_sock.send(f"{command}: command not found\n".encode())
    disconnect(session_id, ip)
    del active_connection[session_id]
    client_sock.close()

def run_dashboard():
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False,
        use_reloader=False,
    )
Thread(
    target=run_dashboard,
    daemon=True
).start()

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(("0.0.0.0", 7777))
server_socket.listen()
print("Listening.....")

while True:
    client_socket, client_address = server_socket.accept()

    Thread(
        target=client_handler,
        args=(client_socket, client_address),
        daemon=True,
    ).start()