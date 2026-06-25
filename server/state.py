from collections import deque

active_connection = {}
recent_commands = deque(maxlen=10)

