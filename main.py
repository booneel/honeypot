from threading import Thread
from time import sleep
from config import DELAY

from server.app import app
import server.routes

from server.tcp_server import start_tcp_server
from server.ssh_server import start_ssh_server


def run_dashboard():
    print("[WEB] Dashboard running on http://127.0.0.1:5000")
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
        use_reloader=False,
    )


def main():
    Thread(target=run_dashboard, daemon=True).start()
    Thread(target=start_tcp_server, daemon=True).start()
    Thread(target=start_ssh_server, daemon=True).start()

    while True:
        sleep(DELAY)


if __name__ == "__main__":
    main()
