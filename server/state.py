from collections import deque
from threading import Lock

state_lock = Lock()

active_connection = {}
recent_commands = deque(maxlen=10)
