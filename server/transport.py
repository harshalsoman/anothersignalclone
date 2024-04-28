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


def fetch_recipient(client):
    return remove_padding_and_decode(client.recv(32))

def send_sender(client, sender):
    client.send(pad_str(sender))


def recv_msg(client, header_length):
    header = client.recv(header_length)
    cipher_length = int.from_bytes(client.recv(8), "little")
    cipher = client.recv(cipher_length)
    return header, cipher


def send_msg(client, header, cipher):
    client.send(header)
    client.send(int.to_bytes(len(cipher), 8, "little"))
    client.send(cipher)


def send_online_users(client, users):
    client.send(SENDONLINEUSERS)
    client.send(int.to_bytes(len(users), 8, "little"))
    client.send(users)

def receive_key_bundle():
    print()


def share_key_bundle(client, key_bundle):
    client.send(key_bundle)


def authentication_exchange(client):
    client.recv()
    print()


def fetch_user_creds(client):
    userpass = client.recv(64)
    username = remove_padding_and_decode(userpass[:32])
    password = remove_padding_and_decode(userpass[32:])
    return username, password

def remove_padding_and_decode(input):
    len = 0
    for b in input:
        if b != 0:
            len += 1
    return input[:len].decode()


def pad_str(input):
    padlength = 32 - len(input)
    return input + (b'\x00' * padlength)
