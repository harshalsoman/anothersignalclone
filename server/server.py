import websockets.sync.server

from _thread import *
import sys, os, socket
import os
import traceback

import datastore
import transport
from flask import Flask, request
import base64
import threading

app = Flask(__name__)

sessions = {}

@app.route("/registration", methods=['POST'])
def register_user():
    username, password = request.form['username'], request.form['password']
    connection = datastore.get_connection()
    status = datastore.register(connection, username, password)
    datastore.close_connection(connection)
    if status:

        return "", 201
    else:
        return {"error": "User already exists"}, 400

@app.route("/authentication", methods=['POST'])
def authenticate():
    username, password = request.form['username'], request.form['password']
    connection = datastore.get_connection()
    status = datastore.authenticate(connection, username, password)
    datastore.close_connection(connection)
    if status:
        return "", 200
    else:
        return {"error": "Unauthorized"}, 401

@app.route("/keybundle/<user>", methods=['POST', 'GET'])
def handle_key_bundle(user):

    if request.method == "POST":
        key_bundle = base64.decodebytes(request.json['key_bundle'].encode())
        connection = datastore.get_connection()
        datastore.store_key_bundle(connection, user, key_bundle)
        datastore.close_connection(connection)
        return "", 201
    elif request.method == "GET":
        connection = datastore.get_connection()
        key_bundle_g = datastore.fetch_key_bundle(connection, user)
        datastore.close_connection(connection)
        return {
            "key_bundle": base64.encodebytes(key_bundle_g[0][0]).decode()
        }, 200
    else:
        return "", 405

@app.route("/users")
def fetch_users():
    users = []
    connection = datastore.get_connection()
    result = datastore.fetch_all_users(connection)
    for user in result:
        user_data = {
            "user": user[0],
            "active": user[0] in sessions.keys()
        }
        users.append(user_data)
    datastore.close_connection(connection)
    return {
        "users": users
    }, 200

@app.route("/messages/<user>", methods=['GET', 'DELETE'])
def handle_messages(user):
    if request.method == "GET":
        connection = datastore.get_connection()
        messages = datastore.fetch_all_messages(connection, user)
        print(messages)
        outermsg = []
        for message in messages:
            msg = {}
            msg['content'] = base64.encodebytes(message[0]).decode()
            msg['by'] = message[1]
            msg['type'] = message[2]
            outermsg.append(msg)
        datastore.close_connection(connection)
        return {
            "messages": outermsg
        }, 200
    elif request.method == "DELETE":
        connection = datastore.get_connection()
        datastore.delete_all_messages(connection, user)
        datastore.close_connection(connection)
        return "", 204
    else:
        return "", 405

def client_handler(client):
    username = None
    connection = datastore.get_connection()
    try:
        username = client.recv()

        sessions[username] = client

        for user in sessions.keys():
            if user == username:
                continue
            sessions[user].send('server')
            sessions[user].send('add')
            sessions[user].send(username)

        while True:

            recipient = client.recv()
            type = client.recv()
            header = client.recv()
            cipher = client.recv()
            if recipient in sessions:
                sessions[recipient].send(username)
                sessions[recipient].send(type)
                sessions[recipient].send(header)
                sessions[recipient].send(cipher)
            else:
                datastore.store_message(connection, username, recipient, header + cipher, type)

    except Exception as e:
        print(traceback.format_exception(e))
        datastore.close_connection(connection)
        if username is not None:
            sessions.pop(username)
            for user in sessions.keys():
                sessions[user].send('server')
                sessions[user].send('remove')
                sessions[user].send(username)
        client.close()
        sys.exit()


def launch_websockets_server():
    with websockets.sync.server.serve(client_handler, '127.0.0.1', 9000) as server:
        print('WebSocket Server Started')
        server.serve_forever()

if __name__ == "__main__":

    # build database if it does not exist
    if not os.path.exists('server.db'):
        datastore.init_datastore()

    threading.Thread(target=launch_websockets_server).start()
    app.run(host='127.0.0.1', port=8000)

