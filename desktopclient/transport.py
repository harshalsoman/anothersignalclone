REGISTRATION = int.to_bytes(1, 8, "little")
AUTHENTICATION = int.to_bytes(2, 8, "little")
MESSAGEEXCHANGE = int.to_bytes(3, 8, "little")
UPLOADBUNDLE = int.to_bytes(4, 8, "little")
DOWNLOADBUNDLE = int.to_bytes(5, 8, "little")
X3DHINIT = int.to_bytes(6, 8, "little")
FETCHOLDMESSAGES = int.to_bytes(7, 8, "little")
FETCHALLUSERS = int.to_bytes(8, 8, "little")

SENDONLINEUSERS = int.to_bytes(99, 8, "little")
SENDSAVEDMESSAGES = int.to_bytes(98, 8, "little")

SUCCESS = int.to_bytes(200, 8, "little")
AUTHENTICATION_FAILURE = int.to_bytes(401, 8, "little")
INTERNAL_ERROR = int.to_bytes(500, 8, "little")


def send_identification(server, username):
    return server.send(pad_str(username))


def get_recipient(server):
    return remove_padding_and_decode(server.recv(32))


def recv_msg(client, header_length):
    header = client.recv(header_length)
    cipher_length = int.from_bytes(client.recv(8), "little")
    cipher = client.recv(cipher_length)
    return header, cipher


def send_msg(client, header, cipher):
    client.send(header)
    client.send(int.to_bytes(len(cipher), 8, "little"))
    client.send(cipher)


def get_online_users(server):
    user_len = int.from_bytes(server.recv(8), "little")
    return server.recv(user_len)


def receive_key_bundle(server):
    return server.recv(1024)


def upload_key_bundle(server, key_bundle):
    server.send(UPLOADBUNDLE)
    server.send(int.to_bytes(len(key_bundle), 8, "little"))
    server.send(key_bundle)

def send_user_credentials(server, username, password):
    userpass = pad_str(username.encode()) + pad_str(password.encode())
    server.send(userpass)


def remove_padding_and_decode(input):
    len = 0
    for b in input:
        if b != 0:
            len += 1
    return input[:len].decode()


def pad_str(input):
    padlength = 32 - len(input)
    return input + (b'\x00' * padlength)
