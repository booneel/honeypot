from flask import jsonify, render_template, request
from server.app import app
from server.state import *

@app.route('/')
def dashboard():
    return render_template('index.html')
@app.route('/connection')
def connection():
    return jsonify(active_connection)

@app.route('/recent_commands')
def recent_command():
    return jsonify(list(recent_commands))