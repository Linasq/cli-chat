import sqlite3
import Crypto.Cipher.AES as aes

def encrypt_db(db_name: str, key: bytes):
    # cipher = aes.new(key, aes.MODE_ECB)
    # print(cipher)
    pass


def decrypt_db(db_name: str, key: bytes):
    pass


def open_db(db_name: str):
    db = sqlite3.connect(db_name)
    cursor = db.cursor()
    cursor.execute('''create table if not exists chat(
        id SERIAL PRIMARY KEY,
        timestamp DATE,
        name TEXT,
        text TEXT,
        users TEXT
    );''')
    return cursor


def get_names(cursor: sqlite3.Cursor):
    cursor.execute('select name from chat')
    names = cursor.fetchall()
    return names
