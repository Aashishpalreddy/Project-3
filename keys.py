import time
import uuid
from cryptography.hazmat.primitives.asymmetric import rsa

keys = {}

def generate_rsa_key():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_numbers = private_key.public_key().public_numbers()
    public_key = {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": str(uuid.uuid4()),
        "n": public_numbers.n,
        "e": public_numbers.e,
        "exp": int(time.time()) + 3600
    }
    keys[public_key["kid"]] = {
        "private": private_key,
        "public": public_key
    }
    return public_key["kid"]
