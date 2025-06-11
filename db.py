from base64 import b64decode, b64encode
import sqlite3
from sqlite3.dbapi2 import Cursor
import Crypto.Cipher.AES as aes
from datetime import datetime

def encrypt_db(db_name: str, key: bytes):
    # cipher = aes.new(key, aes.MODE_ECB)
    # print(cipher)
    pass


def decrypt_db(db_name: str, key: bytes):
    pass


def open_db(db_name: str):
    db = sqlite3.connect(db_name)
    cursor = db.cursor()
    return cursor


def get_names(cursor: Cursor):
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';")
    names = cursor.fetchall()
    return names


def get_history(cursor: Cursor, name: str):
    cursor.execute(f'''create table if not exists {name}(
        id INTEGER PRIMARY KEY autoincrement,
        timestamp DATE,
        name TEXT,
        text TEXT,
        users TEXT
    );''')
    cursor.execute(f'select timestamp, name, text, users from {name}')
    chat = cursor.fetchall()
    return chat


def insert_chat(cursor: Cursor, table_name: str, name: str, text: str, users: list[str]):
    date_now = datetime.now()
    text_base = b64encode(text.encode())
    cursor.execute(f'''insert into {table_name}(timestamp, name, text, users) values(?, ?, ?, ?)''', (date_now, name, text_base, ','.join(users)))


def sanitize_input(msg:str):
    bad_actors = [',', '.', ';', '"', "'", '(', ')', '|', '-', '#', '[', ']', '{','}', ':']
    for i in bad_actors:
        msg=msg.replace(i, '')
    return msg
