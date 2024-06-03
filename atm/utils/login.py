import jwt
import os
import datetime
import rsa

def create_token(user_id):
    payload = {
        'id': user_id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=9999),
        'iat': datetime.datetime.utcnow()
    }
    
    # Use a development secret if 'JWT_SECRET_KEY' is not set in the environment
    secret_key = os.environ.get('JWT_SECRET_KEY', 'secretkey')
    
    return jwt.encode(payload, secret_key, algorithm='HS256')

def create_keys(username):
    pub, priv = rsa.newkeys(1024)

    with open(f'keys/public_{username}.pem', 'wb') as f:
        f.write(pub.save_pkcs1('PEM'))

    with open(f'keys/private_{username}.pem', 'wb') as f:
        f.write(priv.save_pkcs1('PEM'))