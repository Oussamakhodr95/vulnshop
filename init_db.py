"""Create vulnshop.db and fill it with a couple of demo users."""

import sqlite3
from werkzeug.security import generate_password_hash

conn = sqlite3.connect("vulnshop.db")
cur = conn.cursor()

cur.execute("DROP TABLE IF EXISTS users")
cur.execute(
    """
    CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        password TEXT NOT NULL,
        email TEXT,
        credit_card TEXT
    )
    """
)

# For the VULNERABLE app, passwords are stored in plaintext (that's part of
# the point). The FIXED app expects hashes, so we store a hash too and the
# fixed login verifies it. To keep one DB working for both, we store the
# plaintext here; when you run the fixed app, re-seed with the hashed version
# below (see README).
users = [
    ("admin", "SuperSecret123", "admin@vulnshop.local", "4111-1111-1111-1111"),
    ("oussama", "hunter2", "oussama@vulnshop.local", "5500-0000-0000-0004"),
]

for username, password, email, cc in users:
    cur.execute(
        "INSERT INTO users (username, password, email, credit_card) VALUES (?, ?, ?, ?)",
        (username, password, email, cc),
    )

conn.commit()
conn.close()
print("Database created: vulnshop.db  (users: admin, oussama)")
