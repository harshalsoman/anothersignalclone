from _thread import *
import sys, os, socket
import os
import traceback

import datastore
import transport

sessions = {}


def client_handler(client, addr):
    username = None
    connection = datastore.get_connection()
    try:
        msg_type = client.recv(8)
        print(msg_type)

        if msg_type == transport.REGISTRATION:
            username, password = transport.fetch_user_creds(client)
            datastore.register(connection, username, password)
            client.send(transport.SUCCESS)

            key_bundle = transport.receive_key_bundle(client)
            datastore.store_key_bundle(connection, username, key_bundle)
            client.close()
            sys.exit()

        username, password = transport.fetch_user_creds(client)
        if datastore.authenticate(connection, username, password):
            client.send(transport.SUCCESS)
        else:
            client.send(transport.AUTHENTICATION_FAILURE)
            client.close()
            sys.exit()

        sessions[username] = client
        for session in sessions:
            transport.send_online_users(session, sessions.keys())

        while True:
            msg_type = client.recv(8)

            if msg_type == transport.UPLOADBUNDLE:
                key_bundle = transport.receive_key_bundle()
                datastore.store_key_bundle(connection, username, key_bundle)

            elif msg_type == transport.DOWNLOADBUNDLE:
                recipient = transport.fetch_recipient(client)
                key_bundle = datastore.fetch_key_bundle(connection, recipient)
                transport.share_key_bundle(client, key_bundle)

            elif msg_type == transport.X3DHINIT:
                recipient = transport.fetch_recipient(client)
                header, cipher = transport.recv_msg(client, 96)
                if recipient in sessions:
                    transport.send_sender(sessions[recipient], username)
                    transport.send_msg(sessions[recipient], header, cipher)
                else:
                    datastore.store_message(connection, username, recipient, header + cipher)

            elif msg_type == transport.MESSAGEEXCHANGE:
                recipient = transport.fetch_recipient(client)
                header, cipher = transport.recv_msg(client, 128)
                if recipient in sessions:
                    transport.send_sender(sessions[recipient], username)
                    transport.send_msg(sessions[recipient], header, cipher)
                else:
                    datastore.store_message(connection, username, recipient, header + cipher)

            elif msg_type == transport.FETCHOLDMESSAGES:
                messages = datastore.fetch_all_messages(connection, username)
                for message in messages:
                    transport.send_sender(client, message[1])
                    transport.send_msg(client, message[0][:96], message[0][96:])

            elif msg_type == transport.FETCHALLUSERS:
                users = datastore.fetch_all_users(connection)
                userlst = []
                for user in users:
                    userlst.append(user[0])
                transport.share_contacts()

    except Exception as e:
        print(traceback.format_exception(e))
        datastore.close_connection(connection)
        if username is not None:
            sessions.pop(username)
            for session in sessions:
                transport.send_online_users(session, sessions.keys())
        client.close()
        sys.exit()


if __name__ == "__main__":

    # build database if it does not exist
    if not os.path.exists('server.db'):
        datastore.init_datastore()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    server.bind(('127.0.0.1', 9000))
    server.listen(50)
    print('Relay server up and running...')

    while True:
        try:
            client, addr = server.accept()
            if client:
                print('Connected')
                start_new_thread(client_handler, (client, addr))

        except KeyboardInterrupt:
            print('Shutting down...')
            server.close()
            break
