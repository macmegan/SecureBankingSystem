import socket
import json
import random
import string
import rsa
import threading

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from base64 import b64encode, b64decode


HOST = 'localhost'
PORT = 5000
BUFFER_SIZE = 2048
ENCODING = 'utf-8'
ID = 'K'
CLIENT_SOCKETS = dict()


def get_keys():
    with open('keys/public_K.pem', 'rb') as f:
        pub = rsa.PublicKey.load_pkcs1(f.read())

    with open('keys/private_K.pem', 'rb') as f:
        priv = rsa.PrivateKey.load_pkcs1(f.read())

    return pub, priv


def get_first_message(client_socket):
    return client_socket.recv(BUFFER_SIZE).decode(ENCODING)


def print_received_message(message):
    print(f'received: {message}')


def update_public_keys(message):
    with open(f'keys/public_{message}.pem', 'rb') as f:
        # noinspection PyTypeChecker
        client_public_keys[message] = rsa.PublicKey.load_pkcs1(f.read())


def construct_id_message(client_id, nonce_k):
    kid_message_dump = json.dumps({
        'id': ID,
        'N': nonce_k,
        'client_id': client_id
    })
    return rsa.encrypt(kid_message_dump.encode(), client_public_keys[client_id])


def send_message(client_socket, message):
    client_socket.send(message)


def receive_message(client_socket):
    return client_socket.recv(BUFFER_SIZE)


def decrypt_message(message):
    return rsa.decrypt(message, private_key).decode(ENCODING)


def print_received_message_json(message):
    print(f'received: {json.loads(message)}')


def construct_message_four(client_id, nonce_k):
    return rsa.encrypt(nonce_k.encode(), client_public_keys[client_id])


def construct_message_five(master_secret, client_id):
    message = json.dumps({
        f'K{client_id}': client_public_keys[f'K{client_id}'],
        'MS': master_secret
    })
    return rsa.encrypt(message.encode(), client_public_keys[client_id])


client_received_nonces = {}


def handle_client(client_socket, client_id):
    nonce_k = ''.join(random.choice(string.ascii_letters) for _ in range(16))
    client_id_message = construct_id_message(client_id, nonce_k)
    send_message(client_socket, client_id_message)

    message_three = receive_message(client_socket)
    decrypted_message_three = decrypt_message(message_three)
    print_received_message_json(decrypted_message_three)

    message_four = construct_message_four(client_id, nonce_k)
    send_message(client_socket, message_four)

    master_secret = ''.join(random.choice(string.ascii_letters) for _ in range(32))

    client_public_keys[f'K{client_id}'] = ''.join(random.choice(string.ascii_letters) for _ in range(16))
    message_five = construct_message_five(master_secret, client_id)
    send_message(client_socket, message_five)

    client_received_nonces[client_id] = set()

def handle_client_thread(c_socket, c_address):
    print_received_message(client_id)
    update_public_keys(client_id)
    handle_client(c_socket, client_id)


public_key, private_key = get_keys()

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, PORT))
server_socket.listen()

client_public_keys = dict()

while True:
    client_socket, client_address = server_socket.accept()
    client_id = get_first_message(client_socket)

    CLIENT_SOCKETS[client_id] = client_socket

    t = threading.Thread(target=handle_client_thread, args=[client_socket, client_address])
    t.start()
