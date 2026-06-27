import os

DELAY = 15
MAX_COMMAND_SPACE = 10

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR  = os.path.join(BASE_DIR, "logger")

CRED_PATH = os.path.join(LOG_DIR, "credentials.jsonl")
CMD_PATH  = os.path.join(LOG_DIR, "commands.jsonl")
SESSION_PATH = os.path.join(LOG_DIR, "session.jsonl")

KEY_PATH = os.path.join(BASE_DIR, "server", "server.key")