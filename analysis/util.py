import json

def load_jsonl(path):
    logs = []

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            logs.append(json.loads(line))

    return logs

def common_summary(name, target, n):
    print(f"\nTop {name}")
    print("-" * 30)

    for key, value in target.most_common(n):
        print(f"{key:<20} {value:>5}")
    print()

def behavior_summary(name, target):
    print(f"\n{name}")
    print("-" * 100)
    for log in target:
        ip = log['ip']
        command = log['command']
        time = log['time']
        username = log['username']
        print(f"[{time}] {ip} {username} {command}\n")
    print(f"total: {len(target)}\n")

def session_summary(target):
    time = target['time']
    command = target['command']
    print(f"[{time}] {command}")