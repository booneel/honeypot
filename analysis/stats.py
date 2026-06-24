from collections import Counter
from util import *

ip_addresses = Counter()
usernames = Counter()
passwords = Counter()
commands = Counter()
session_total = 0

logs = load_jsonl("../logger/credentials.jsonl")
for log in logs:
    username, password = log['username'], log['password']
    usernames[username] += 1
    passwords[password] += 1

logs = load_jsonl("../logger/commands.jsonl")
for log in logs:
    command = log["command"].split()[0]
    commands[command] += 1

logs = load_jsonl("../logger/session.jsonl")
for log in logs:
    ip = log["ip"]
    ip_addresses[ip] += 1
    session_total += 1

print("=== Honeypot Statistics ===\n")
print(f"Total Sessions: {session_total}")

common_summary("IP Addresses", ip_addresses, 5)
common_summary("Usernames", usernames, 5)
common_summary("Passwords", passwords, 5)
common_summary("Commands", commands, 5)
