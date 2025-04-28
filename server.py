import os
import time
import uuid
import jwt
import sqlite3
import base64
import json
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from dotenv import load_dotenv
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from argon2 import PasswordHasher
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from keys import keys, generate_rsa_key

# Load .env
load_dotenv()

# FastAPI + rate limiter
app = FastAPI()
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter

# AES key for encrypting private DER
AES_KEY = os.getenv("NOT_MY_KEY", "ThisIsASecretKeyOf32BytesLen1234").encode()

# Password hasher
ph = PasswordHasher()

# SQLite setup
db = sqlite3.connect("jwks.db", check_same_thread=False)
c = db.cursor()

def encrypt_private_key(der_bytes: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(AES_KEY), modes.ECB(), backend=default_backend())
    enc = cipher.encryptor()
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(der_bytes) + padder.finalize()
    return enc.update(padded) + enc.finalize()

def decrypt_private_key(enc_bytes: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(AES_KEY), modes.ECB(), backend=default_backend())
    dec = cipher.decryptor()
    padded = dec.update(enc_bytes) + dec.finalize()
    unpad = sym_padding.PKCS7(128).unpadder()
    return unpad.update(padded) + unpad.finalize()

def base64url_encode(num: int) -> str:
    b = num.to_bytes((num.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")

class RegisterRequest(BaseModel):
    username: str
    email: str

class AuthRequest(BaseModel):
    username: str
    password: str

@app.get("/.well-known/jwks.json")
def get_jwks():
    now = time.time()
    c.execute("SELECT public_key FROM keys WHERE exp > ?", (now,))
    return {"keys": [json.loads(r[0]) for r in c.fetchall()]}

@app.post("/register")
def register(req: RegisterRequest):
    pwd = str(uuid.uuid4())
    pwd_hash = ph.hash(pwd)
    try:
        c.execute("INSERT INTO users(username,password_hash,email) VALUES(?,?,?)",
                  (req.username, pwd_hash, req.email))
        db.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(400, "Username or email already exists")
    return {"password": pwd}

@app.post("/auth")
@limiter.limit("10/second")
async def auth(request: Request, creds: AuthRequest):
    # 1) verify user
    c.execute("SELECT id,password_hash FROM users WHERE username=?", (creds.username,))
    row = c.fetchone()
    if not row or not ph.verify(row[1], creds.password):
        raise HTTPException(401, "Invalid credentials")
    user_id = row[0]

    # 2) generate RSA keypair
    kid = generate_rsa_key()
    kp = keys[kid]

    # 3) DER‐encode private key
    priv_der = kp["private"].private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # 4) build flat JWK
    nums = kp["private"].public_key().public_numbers()
    exp_ts = int(time.time()) + 3600
    jwk = {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": kid,
        "n": base64url_encode(nums.n),
        "e": base64url_encode(nums.e),
        "exp": exp_ts
    }

    # 5) encrypt private DER → base64
    enc_priv = encrypt_private_key(priv_der)
    enc_b64 = base64.b64encode(enc_priv).decode()

    # 6) store in DB
    c.execute("INSERT OR REPLACE INTO keys(kid,public_key,private_key,exp) VALUES(?,?,?,?)",
              (kid, json.dumps(jwk), enc_b64, exp_ts))
    db.commit()

    # 7) sign and return JWT
    dec_priv = decrypt_private_key(base64.b64decode(enc_b64))
    token = jwt.encode({"sub":creds.username,"iat":int(time.time()),"exp":exp_ts},
                       dec_priv, algorithm="RS256", headers={"kid":kid})

    # 8) log auth
    c.execute("INSERT INTO auth_logs(request_ip,user_id) VALUES(?,?)",
              (request.client.host, user_id))
    db.commit()

    return {"token": token}

@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(429, {"detail": "Too Many Requests"})
