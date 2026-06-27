from analysis.util import load_jsonl
from flask import jsonify, render_template, request
from server.app import app
from server.state import active_connection, recent_commands, state_lock
from config import CMD_PATH, CRED_PATH
@app.route('/')
def dashboard():
    return render_template('index.html')

@app.route('/connections')
def connections():
    with state_lock:
        return jsonify(dict(active_connection))


@app.route('/recent_commands')
def recent_command():
    with state_lock:
        return jsonify(list(recent_commands))

@app.route('/session/<session_id>')
def session_detail(session_id):
    cred = next(
        (c for c in load_jsonl(CRED_PATH) if c["session_id"] == session_id),
        None
    )
    if cred is None:
        return jsonify({"error": "session not found"}), 404
    commands = [c for c in load_jsonl(CMD_PATH) if c["session_id"] == session_id]
    return jsonify({
        "session_id": session_id,
        "username": cred["username"],
        "password": cred["password"],
        "ip": cred.get("ip"),
        "protocol": cred.get("protocol"),
        "commands": commands,        # 시간순 그대로
    })


@app.route('/history')
def history():
    q = request.args.get("q")
    session = request.args.get("session")
    ip = request.args.get("ip")
    username = request.args.get("username")

    cmds = load_jsonl(CMD_PATH)

    if q:
        needle = q.lower()
        cmds = [
            c for c in cmds
            if needle in str(c.get("session_id", "")).lower()
               or needle in str(c.get("ip", "")).lower()
               or needle in str(c.get("username", "")).lower()
               or needle in str(c.get("command", "")).lower()
        ]
    elif session:
        cmds = [c for c in cmds if c.get("session_id") == session]
    elif ip:
        cmds = [c for c in cmds if c.get("ip") == ip]
    elif username:
        cmds = [c for c in cmds if c.get("username") == username]
    else:
        return jsonify({"error": "q, session, ip, or username required"}), 400

    return jsonify(cmds)