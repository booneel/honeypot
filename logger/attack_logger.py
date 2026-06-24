import datetime
import json

def curr_time():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def save_login(session_id, ip, username, password):
    log = {
        "session_id": session_id,
        "ip": ip,
        "username": username,
        "password": password,
        "time": curr_time()
    }
    with open("logger/credentials.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps(log, ensure_ascii=False) + "\n")

def save_command(session_id, ip, username, command):
    log = {
        "session_id": session_id,
        "ip": ip,
        "username": username,
        "command": command,
        "time": curr_time(),

    }
    with open("logger/commands.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps(log, ensure_ascii=False) + "\n")

def disconnect(session_id, ip):
    log = {
        "session_id": session_id,
        "ip": ip,
        "time": curr_time(),
    }
    with open("logger/session.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps(log, ensure_ascii=False) + "\n")