import json
import random

import rsa
import socket
import string

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

from base64 import b64decode


HOST = 'localhost'
PORT = 5000
BUFFER_SIZE = 2048
ENCODING = 'utf-8'
session_key = ''
client_public_keys = dict()


def get_keys(username):
    with open(f'keys/public_{username}.pem', 'rb') as f:
        pub = rsa.PublicKey.load_pkcs1(f.read())

    with open(f'keys/private_{username}.pem', 'rb') as f:
        priv = rsa.PrivateKey.load_pkcs1(f.read())

    return pub, priv


def send_message(client_socket, message):
    client_socket.send(message)


def receive_message(client_socket):
    return client_socket.recv(BUFFER_SIZE)


def decrypt_message(private_key, message):
    return rsa.decrypt(message, private_key).decode(ENCODING)


def print_received_message_json(message):
    print(f'received: {json.loads(message)}')


def print_received_message(message):
    print(f'received: {message}')


def update_foreign_keys(foreign_keys, message):
    with open(f'keys/public_{message}.pem', 'rb') as f:
        foreign_keys[message] = rsa.PublicKey.load_pkcs1(f.read())


def construct_message_three(foreign_keys, nonce_a, message):
    kdc_dict = json.loads(message)

    update_foreign_keys(foreign_keys, kdc_dict['id'])

    nonce_message = json.dumps({
        'N': nonce_a,
        'NK': kdc_dict['N']
    })

    return rsa.encrypt(nonce_message.encode(), foreign_keys['K'])


def get_master_secret(message):
    global session_key
    kdc_dict = json.loads(message)
    return kdc_dict['MS']


def decrypt_chat_message(message):
    message_cipher = AES.new(bytes(session_key, encoding=ENCODING), AES.MODE_CBC, iv=bytes(session_key, encoding=ENCODING))
    return unpad(message_cipher.decrypt(b64decode(message)), AES.block_size).decode(encoding=ENCODING)


received_nonces = set()


def check_nonce_replay(nonce):
    if nonce in received_nonces:
        return True
    else:
        received_nonces.add(nonce)
        return False

def authenticate(username):
    public_key, private_key = get_keys(username)
    nonce_a = ''.join(random.choice(string.ascii_letters) for i in range(16))
    foreign_keys = dict()

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((HOST, PORT))

    message_one = username
    send_message(client_socket, bytes(message_one, encoding=ENCODING))

    message_two = receive_message(client_socket)
    decrypted_kdc_id_message = decrypt_message(private_key, message_two)
    print_received_message_json(decrypted_kdc_id_message)

    message_three = construct_message_three(foreign_keys, nonce_a, decrypted_kdc_id_message)
    send_message(client_socket, message_three)

    message_four = receive_message(client_socket)
    decrypted_message_four = decrypt_message(private_key, message_four)
    print_received_message(decrypted_message_four)

    message_five = receive_message(client_socket)
    decrypted_message_five = decrypt_message(private_key, message_five)
    print_received_message_json(decrypted_message_five)
    master_secret = get_master_secret(decrypted_message_five)

    with open(f'master_secrets/symmetric_keys/{username}.txt', 'wb') as f:
        f.write(bytes(master_secret[:16], 'utf-8'))

    with open(f'master_secrets/mac_keys/{username}.txt', 'wb') as f:
        f.write(bytes(master_secret[16:], 'utf-8'))