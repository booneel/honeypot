from time import sleep

from config import DELAY
from logger.attack_logger import curr_time, save_command
from server.state import recent_commands, state_lock


def shell_print(sock, text, protocol, end=True):
    if end:
        newline = "\r\n" if protocol == "SSH" else "\n"
        sock.send((text + newline).encode())
    else:
        sock.send(text.encode())


def recv_line(sock):
    buffer = bytearray()

    while True:
        ch = sock.recv(1)

        if not ch:
            return None

        if ch in (b"\r", b"\n"):
            sock.send(b"\r\n")
            break

        if ch in (b"\x08", b"\x7f"):
            if buffer:
                buffer.pop()
                sock.send(b"\b \b")
            continue

        buffer.extend(ch)
        sock.send(ch)

    return buffer.decode(errors="ignore").strip()


def shell_input(sock, protocol):
    if protocol == "SSH":
        return recv_line(sock)

    raw = sock.recv(1024)

    if not raw:
        return None

    return raw.decode(errors="ignore").strip()


def fake_shell(client_sock, session_id, username, ip, has_root, protocol):

    shell_print(client_sock, "Login Successful", protocol)

    while True:

        prompt_user = "root" if has_root else username
        prompt_symbol = "#" if has_root else "$"

        prompt = f"{prompt_user}@ubuntu:~{prompt_symbol} "
        shell_print(client_sock, prompt, protocol, end=False)

        data = shell_input(client_sock, protocol)

        if data is None:
            break

        if not data:
            continue

        save_command(session_id, ip, username, data, protocol)

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

        parts = data.split()

        command = parts[0]
        args = parts[1:]

        if command == "whoami":
            shell_print(client_sock, prompt_user, protocol)

        elif command == "pwd":
            shell_print(client_sock, f"/home/{username}", protocol)

        elif command == "ls":
            shell_print(client_sock, "flag.txt  test.txt", protocol)

        elif command == "uname":
            if "-a" in args:
                shell_print(
                    client_sock,
                    "Linux ubuntu 5.15.0-generic x86_64 GNU/Linux",
                    protocol
                )
            else:
                shell_print(client_sock, "Linux", protocol)

        elif command == "hostname":
            shell_print(client_sock, "ubuntu", protocol)

        elif command == "id":
            if has_root:
                shell_print(
                    client_sock,
                    "uid=0(root) gid=0(root)",
                    protocol
                )
            else:
                shell_print(
                    client_sock,
                    f"uid=1000({username}) gid=1000({username})",
                    protocol
                )

        elif command == "cat":

            if not args:
                shell_print(client_sock, "cat: missing operand", protocol)

            elif args[0] == "flag.txt":
                shell_print(client_sock, "CTF{fake_flag}", protocol)

            elif args[0] == "test.txt":
                shell_print(client_sock, "This is test file", protocol)

            else:
                shell_print(
                    client_sock,
                    f"cat: {args[0]}: No such file",
                    protocol
                )

        elif command == "wget":

            if not args:
                shell_print(client_sock, "wget: missing URL", protocol)

            else:
                shell_print(
                    client_sock,
                    f"Connecting to {args[0]}",
                    protocol
                )

                sleep(DELAY)

                shell_print(
                    client_sock,
                    "Connection timed out",
                    protocol
                )

        elif data == "ip a":

            shell_print(
                client_sock,
                """1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536
                        inet 127.0.0.1/8 scope host lo

                        2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500
                        inet 192.168.0.100/24 scope global eth0""",
                protocol
            )

        elif command == "curl":
            if not args:
                shell_print(client_sock, "curl: missing URL", protocol)

            else:
                sleep(DELAY)
                shell_print(
                    client_sock,
                    "curl: (7) Failed to connect",
                    protocol
                )

        elif command in ("su", "sudo"):
            shell_print(client_sock, "Password: ", protocol, end=False)
            password = shell_input(client_sock, protocol)

            if password is None:
                break

            if command == "sudo":
                shell_print(
                    client_sock,
                    "Sorry, try again.",
                    protocol
                )

            else:
                has_root = True
            continue

        elif command == "exit":

            if has_root:
                has_root = False
                continue
            shell_print(client_sock, "logout", protocol)
            break

        else:
            shell_print(
                client_sock,
                f"{command}: command not found",
                protocol
            )