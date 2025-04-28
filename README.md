# Project-3
JWKS Server 

Author: Aashishpal Reddy Kandala (11733180)

Overview
This project implements a secure JSON Web Key Set (JWKS) server using FastAPI. It supports:

AES encryption of private keys in the database (DER format encrypted with AES-ECB and PKCS7 padding).

User registration with Argon2-hashed passwords.

Authentication endpoint issuing JWTs signed with RS256.

Logging of authentication requests (IP address, timestamp, user ID).

Optional rate limiting on authentication (10 requests/second).

JWKS endpoint serving unexpired public keys in JWK format.

Repository Structure

bash
Copy
Edit
new_jwks_server/
├── server.py         # FastAPI application
├── keys.py           # RSA key generation utility
├── fix_db.py         # Database schema creation/reset script
├── .env              # Environment variables (NOT_MY_KEY for AES)
├── jwks.db           # SQLite database (after running fix_db.py)
└── README.md         # Project documentation
Setup & Running

Clone the repo
git clone https://github.com/Aashishpalreddy/Project-3.git
cd Project-3

Install dependencies
pip install fastapi uvicorn python-dotenv cryptography argon2-cffi slowapi PyJWT

Configure AES key
Create a .env file in the root with:

vbnet
Copy
Edit
NOT_MY_KEY=your-32-byte-base64-or-text-key
Initialize the database
python fix_db.py

Start the server
uvicorn server:app --host 0.0.0.0 --port 8080 --reload

Run tests
pytest

Grade with Gradebot
gradebot project3 --code-dir . --database-file jwks.db

Endpoints

POST /register – Register a new user, returns generated password.

POST /auth – Authenticate user and receive a JWT token.

GET /.well-known/jwks.json – Retrieve current public JWKs.

Notes

For production, switch AES mode to GCM or CBC with random IVs.

Secure your .env and do not commit secret keys to source control.
