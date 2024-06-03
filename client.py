from decimal import Decimal
import requests

import rsa

import hashlib
import hmac
import json

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from base64 import b64encode, b64decode

BASE_URL = 'http://localhost:8000/api'
ENCODING = 'utf-8'
token = ''

def decrypt_message(encrypted_message, username):
    with open(f'master_secrets/symmetric_keys/{username}.txt', 'rb') as f:
        session_key = f.read()

    with open(f'master_secrets/mac_keys/{username}.txt', 'rb') as f:
        mac_key = f.read()

    message_cipher = AES.new(session_key, AES.MODE_CBC, iv=session_key)
    message = unpad(message_cipher.decrypt(b64decode(encrypted_message)), AES.block_size).decode(encoding=ENCODING)

    message_dict = json.loads(message)
    message_to_verify = message_dict['message']
    mac_to_verify = message_dict['mac']

    test_mac = hmac.new(mac_key, message_to_verify.encode(), hashlib.sha256).hexdigest()

    if not hmac.compare_digest(test_mac, mac_to_verify):
            print('mac does not match\n')
    else:
        print('mac matches')
        print(f'response: {message_to_verify}\n')

def login():
    global token
    username = input('enter your username\n')
    password = input('enter your password\n')

    body = {
        'username': username,
        'password': password
    }
    headers = {"Content-Type": "application/json; charset=utf-8"}

    result = requests.post(f'{BASE_URL}/login', headers=headers, json=body)

    if result.ok:
        token = result.json()['token']
        print(token)
        print()
        return username
    else:
        print(result.json()['errors'])
        print()

def signup():
    username = input('enter your username\n')
    password = input('enter your password\n')
    balance = input('enter your balance\n')

    body = {
        'username': username,
        'password': password,
        'balance': balance
    }
    headers = {"Content-Type": "application/json; charset=utf-8"}

    result = requests.post(f'{BASE_URL}/signup', headers=headers, json=body)

    if not result.ok:
        print(result.json()['errors'])
        print()


def do_transaction(inp, username):
    session_key = ''
    mac_key = ''

    with open(f'master_secrets/symmetric_keys/{username}.txt', 'rb') as f:
        session_key = f.read()

    with open(f'master_secrets/mac_keys/{username}.txt', 'rb') as f:
        mac_key = f.read()

    ENCODING = 'utf-8'

    msg = inp

    message_to_encrypt = json.dumps({
        'message': msg,
        'mac': hmac.new(mac_key, msg.encode(), hashlib.sha256).hexdigest()
    })

    cipher = AES.new(session_key, AES.MODE_CBC, iv=session_key)

    encrypted_input_message = b64encode(cipher.encrypt(pad(bytes(message_to_encrypt, encoding=ENCODING), AES.block_size))).decode()
    
    body = {
        'encrypted_message': encrypted_input_message,
    }

    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {token}'
    }

    result = requests.post(f'{BASE_URL}/transaction', headers=headers, json=body)

    if result.ok:
        print(result.json())
        encrypted_message = result.json()['encrypted_response']
        print()
        decrypt_message(encrypted_message, username)
    else:
        print(result.json()['errors'])
        print()


operation = None
while operation != 'exit':
    operation = input('login/signup or exit\n')

    match operation:
        case 'login':
            username = login()
        case 'signup':
            signup()
            continue
        case _:
            continue

    inp = None

    while inp != 'exit':
        if username == 'admin':
            inp = input('input an admin command (read x) or exit\n')
            if inp != 'exit':
                do_transaction(inp, username)
        else:
            inp = input('input a transaction (deposit x, withdraw x, or inquire) or exit\n')

            if inp.startswith('deposit') or inp.startswith('withdraw') or inp.startswith('inquire'):
                do_transaction(inp, username)
