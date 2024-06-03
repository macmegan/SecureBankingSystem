import json
import hashlib
import hmac
import os
import rsa

from decimal import Decimal

from datetime import datetime
from pytz import timezone

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from base64 import b64encode, b64decode

from base64 import b64decode

# Create your views here.
from rest_framework.views import APIView

from .models import User
from .serializers import UserSerializer
from .forms import SignupForm

from .utils.login import create_token, create_keys
from .utils.auth_helpers import authenticate
from .utils.constants import (
    NO_USER_WITH_USERNAME,
    INCORRECT_PASSWORD,
    AMOUNT_GREATER_THAN_BALANCE,
    INVALID_MAC_HASH
)  

from core.network import make_success_response, make_error_response
from core.authorization import get_username

class SignUpView(APIView):
    def post(self, request):
        form = SignupForm(request.data)

        if not form.is_valid():
            return make_error_response(form.errors)
        
        serializer = UserSerializer(data=form.cleaned_data)

        if not serializer.is_valid():
            return make_error_response(serializer.errors)
                
        serializer.save()

        create_keys(request.data['username'])

        return make_success_response()

class LoginView(APIView):
    def post(self, request):
        username = request.data['username']
        password = request.data['password']

        authenticate(username)

        try:
            user = User.objects.get(username=username)

        except User.DoesNotExist:
            return make_error_response(NO_USER_WITH_USERNAME)
        
        if not user.check_password(password):
            return make_error_response(INCORRECT_PASSWORD)

        return make_success_response({ 'token': create_token(user.id) })
    
class TransactionView(APIView):
    def write_to_audit_log(self, id, transaction, value):
            log_number = len([f for f in os.listdir('audit_logs') if os.path.isfile(os.path.join('audit_logs', f))])
            print(log_number)
        
            with open(f'audit_logs/{log_number}.txt', 'wb') as f:
                tz = timezone('EST')
                time_taken = datetime.now(tz).strftime("%Y-%m-%d %H:%M:%S")
                if value:
                    message_to_encrypt = '-'.join([id, f'{transaction} {value}', time_taken])
                else:
                    message_to_encrypt = '-'.join([id, transaction, time_taken])
                pub = None

                with open('keys/public_K.pem', 'rb') as fi:
                    pub = rsa.PublicKey.load_pkcs1(fi.read())

                message_to_write = rsa.encrypt(message_to_encrypt.encode(), pub)
                f.write(b64encode(message_to_write))

    def post(self, request):
        ENCODING = 'utf-8'
        session_key = ''
        mac_key = ''
        username = get_username(request)

        with open(f'master_secrets/symmetric_keys/{username}.txt', 'rb') as f:
            session_key = f.read()

        with open(f'master_secrets/mac_keys/{username}.txt', 'rb') as f:
            mac_key = f.read()

        encrypted_message = request.data['encrypted_message']

        message_cipher = AES.new(session_key, AES.MODE_CBC, iv=session_key)
        message = unpad(message_cipher.decrypt(b64decode(encrypted_message)), AES.block_size).decode(encoding=ENCODING)

        message_dict = json.loads(message)
        message_to_verify = message_dict['message']
        mac_to_verify = message_dict['mac']

        test_mac = hmac.new(mac_key, message_to_verify.encode(), hashlib.sha256).hexdigest()

        user = User.objects.get(username=username)

        if not hmac.compare_digest(test_mac, mac_to_verify):
            return make_error_response(INVALID_MAC_HASH)
        
        if message_to_verify.startswith('deposit'):
            transaction, value = message_to_verify.split(' ')

            user.balance += Decimal(value)
            user.save()

            self.write_to_audit_log(str(user.id), transaction, value)

            message_to_encrypt = json.dumps({
                'message': 'transaction success',
                'mac': hmac.new(mac_key, 'transaction success'.encode(), hashlib.sha256).hexdigest()
            })

            cipher = AES.new(session_key, AES.MODE_CBC, iv=session_key)

            encrypted_response = b64encode(cipher.encrypt(pad(bytes(message_to_encrypt, encoding=ENCODING), AES.block_size))).decode()
            
            return make_success_response({'encrypted_response': encrypted_response})
        
        elif message_to_verify.startswith('withdraw'):
            transaction, value = message_to_verify.split(' ')

            if user.balance < Decimal(value):
                return make_error_response(AMOUNT_GREATER_THAN_BALANCE)
            
            user.balance -= Decimal(value)
            user.save()

            self.write_to_audit_log(str(user.id), transaction, value)

            message_to_encrypt = json.dumps({
                'message': 'transaction success',
                'mac': hmac.new(mac_key, 'transaction success'.encode(), hashlib.sha256).hexdigest()
            })

            cipher = AES.new(session_key, AES.MODE_CBC, iv=session_key)

            encrypted_response = b64encode(cipher.encrypt(pad(bytes(message_to_encrypt, encoding=ENCODING), AES.block_size))).decode()
            
            return make_success_response({'encrypted_response': encrypted_response})
        
        elif message_to_verify.startswith('inquire'):
            transaction = message_to_verify

            cipher = AES.new(session_key, AES.MODE_CBC, iv=session_key)

            message_to_encrypt = json.dumps({
                'message': str(user.balance),
                'mac': hmac.new(mac_key, str(user.balance).encode(), hashlib.sha256).hexdigest()
            })

            encrypted_response = b64encode(cipher.encrypt(pad(bytes(message_to_encrypt, encoding=ENCODING), AES.block_size))).decode()

            self.write_to_audit_log(str(user.id), transaction, None)

            return make_success_response({'encrypted_response': encrypted_response})
        
        elif message_to_verify.startswith('read'):
            transaction, value = message_to_verify.split(' ')
            message = ''

            with open('keys/private_K.pem', 'rb') as fi:
                priv = rsa.PrivateKey.load_pkcs1(fi.read())
            
            with open(f'audit_logs/{value}.txt', 'rb') as f:
                message = rsa.decrypt(b64decode(f.read()), priv)

            message_to_encrypt = json.dumps({
                'message': str(message),
                'mac': hmac.new(mac_key, str(message).encode(), hashlib.sha256).hexdigest()
            })

            cipher = AES.new(session_key, AES.MODE_CBC, iv=session_key)

            encrypted_response = b64encode(cipher.encrypt(pad(bytes(message_to_encrypt, encoding=ENCODING), AES.block_size))).decode()
            
            return make_success_response({'encrypted_response': encrypted_response})
        
        return make_error_response()
    
'''
TEST ENCRYPTION LINES TO COPY PASTE INTO SHELL


import hashlib
import hmac
import json

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from base64 import b64encode, b64decode

session_key = ''
mac_key = ''

with open(f'master_secrets/symmetric_keys/abcde.txt', 'rb') as f:
    session_key = f.read()

with open(f'master_secrets/mac_keys/abcde.txt', 'rb') as f:
    mac_key = f.read()

ENCODING = 'utf-8'

msg = 'inquire'

message_to_encrypt = json.dumps({
    'message': msg,
    'mac': hmac.new(mac_key, msg.encode(), hashlib.sha256).hexdigest()
})

cipher = AES.new(session_key, AES.MODE_CBC, iv=session_key)

encrypted_input_message = b64encode(cipher.encrypt(pad(bytes(message_to_encrypt, encoding=ENCODING), AES.block_size))).decode()
encrypted_input_message
'''