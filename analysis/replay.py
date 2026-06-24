from util import *
import sys

credentials = load_jsonl("../logger/credentials.jsonl")
commands = load_jsonl("../logger/commands.jsonl")

print("=== Session Replay ===\n")

if len(sys.argv) < 2:
    sessions = {}

    for cred in credentials:
        sessions[cred["session_id"]] = {
            "username": cred["username"],
            "password": cred["password"]
        }


    for session_id, info in sessions.items():

        print("=" * 50)
        print(f"Session ID : {session_id}")
        print(f"USERNAME   : {info['username']}")
        print(f"PASSWORD   : {info['password']}")
        print("=" * 50)

        for log in commands:
            if log["session_id"] == session_id:
                session_summary(log)

        print()

else:
    target_session = sys.argv[1]
    username = None
    password = None

    for cred in credentials:
        if cred["session_id"] == target_session:
            username = cred["username"]
            password = cred["password"]
            break
    if username is None:
        print("Session not found.")
        exit()
    print("=" * 50)
    print(f"Session ID : {target_session}")
    print(f"USERNAME   : {username}")
    print(f"PASSWORD   : {password}")
    print("=" * 50)
    for log in commands:
        if log["session_id"] == target_session:
            session_summary(log)