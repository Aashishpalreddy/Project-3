import sqlite3

conn = sqlite3.connect("jwks.db")
c = conn.cursor()

# DROP any leftover tables from previous runs
c.execute("DROP TABLE IF EXISTS auth_logs")
c.execute("DROP TABLE IF EXISTS users")
c.execute("DROP TABLE IF EXISTS keys")

# Recreate keys table
c.execute('''
CREATE TABLE keys(
  kid TEXT PRIMARY KEY,
  public_key TEXT NOT NULL,
  private_key TEXT NOT NULL,
  exp INTEGER NOT NULL
)
''')

# Recreate users table
c.execute('''
CREATE TABLE users(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  email TEXT UNIQUE,
  date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  last_login TIMESTAMP
)
''')

# Recreate auth_logs table
c.execute('''
CREATE TABLE auth_logs(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  request_ip TEXT NOT NULL,
  request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  user_id INTEGER,
  FOREIGN KEY(user_id) REFERENCES users(id)
)
''')

conn.commit()
conn.close()
print("✅ jwks.db schema reset and recreated successfully.")
