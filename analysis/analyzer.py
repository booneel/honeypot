from util import *

DISCOVERY = {
    "whoami",
    "ls",
    "ip",
    "hostname",
    "uname",
    "id",
    "pwd"
}

FILE_ACCESS = {
    "cat"
}

DOWNLOAD = {
    "curl",
    "wget"
}

PRIV_ESC = {
    "su",
    "sudo"
}

download_attempts = []
priv_esc_attempts = []
file_access_attempts = []
discovery_commands = []

logs = load_jsonl("../logger/commands.jsonl")
for log in logs:
    data = log['command'].split()
    command, args = data[0], data[1:]
    if command in DISCOVERY:
        discovery_commands.append(log)
    elif command in DOWNLOAD:
        download_attempts.append(log)
    elif command in PRIV_ESC:
        priv_esc_attempts.append(log)
    elif command in FILE_ACCESS:
        file_access_attempts.append(log)


print("=== Threat Analysis ===\n")
behavior_summary("Discovery", discovery_commands)
behavior_summary("File access", file_access_attempts)
behavior_summary("Download", download_attempts)
behavior_summary("Privilege escalation", priv_esc_attempts)