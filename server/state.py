from collections import deque
from threading import Lock
from config import MAX_COMMAND_SPACE

state_lock = Lock()

active_connection = {}
recent_commands = deque(maxlen=MAX_COMMAND_SPACE)
