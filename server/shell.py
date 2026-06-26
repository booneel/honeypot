from logger.attack_logger import curr_time, save_command
from server.state import state_lock, recent_commands
from time import sleep
from config import DELAY

def recv_line(sock):
    buffer = bytearray()

    while True:
        ch = sock.recv(1)

        if not ch:
            return None

        if ch in (b"\r", b"\n"):
            break

        if ch in (b"\x08", b"\x7f"):
            if buffer:
                buffer.pop()
            continue

        buffer.extend(ch)

    return buffer.decode(errors="ignore").strip()

def fake_shell(client_sock, session_id, username, ip, has_root, protocol):

    if protocol == "SSH":
        client_sock.send(b"Login Successful\r\n")
    else:
        client_sock.send(b"Login Successful\n")

    while True:
        prompt_user = "root" if has_root else username
        prompt_symbol = "#" if has_root else "$"

        prompt = f"{prompt_user}@ubuntu:~{prompt_symbol} "
        client_sock.send(prompt.encode())

        if protocol == "SSH":
            data = recv_line(client_sock)
            if data is None:
                break
        else:
            raw = client_sock.recv(1024)

            if not raw:
                break

            data = raw.decode(errors="ignore").strip()

        if not data:
            continue

        save_command(session_id, ip, username, data, protocol)
        parts = data.split()
        command = parts[0]
        args = parts[1:]

        info = {
            "time": curr_time(),
            "session_id": session_id,
            "ip": ip,
            "username": username,
            "command": data,
            "protocol": protocol
        }
        with state_lock:
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
                sleep(DELAY)
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
                sleep(DELAY)
                client_sock.send(b"curl: (7) Failed to connect\n")
        elif command == "su" or command == "sudo":
            client_sock.send(b"Password: ")
            client_sock.recv(1024)
            if command == "sudo":
                client_sock.send(b"Sorry, try again.\n")
            else:
                has_root = True
        elif command == "exit":
            if has_root:
                has_root = False
            else:
                client_sock.send(b"logout\n")
                break
        else:
            client_sock.send(f"{command}: command not found\n".encode())
