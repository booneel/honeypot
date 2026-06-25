from flask import jsonify, render_template
from server.app import app
from server.state import active_connection, recent_commands, state_lock


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
