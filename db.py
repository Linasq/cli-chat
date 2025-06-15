from base64 import b64decode, b64encode
import sqlite3
from cryptography.hazmat.primitives.ciphers.algorithms import AES256
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
    return cursor, db


def close_db(cursor: sqlite3.Cursor, db: sqlite3.Connection):
    db.commit()
    cursor.close()
    db.close()


def get_names(cursor: sqlite3.Cursor):
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';")
    names = cursor.fetchall()
    return names


def get_history(cursor: sqlite3.Cursor, name: str):
    cursor.execute(f'''create table if not exists {name}(
        id INTEGER PRIMARY KEY autoincrement,
        timestamp DATE,
        name TEXT,
        text TEXT,
        users TEXT
    );''')
    cursor.execute(f'select timestamp, name, text, users from {name}')
    chat = cursor.fetchall()
    if not chat:
        return chat

    results = []
    for i in chat:
        results.append((i[0], i[1], b64decode(i[2]).decode(), i[3]))

    return results


def insert_chat(cursor: sqlite3.Cursor, table_name: str, name: str, text: str, users: list[str]):
    date_now = datetime.now()
    text_base = b64encode(text.encode())
    date_str = datetime.strftime(date_now, '\[%H:%M, %d.%m]')
    cursor.execute(f'''insert into {table_name}(timestamp, name, text, users) values(?, ?, ?, ?)''', (date_str, name, text_base, ','.join(users)))


def sanitize_input(msg:str) -> str:
    bad_actors = [',', '.', ';', '"', "'", '(', ')', '|', '-', '#', '[', ']', '{','}', ':']
    for i in bad_actors:
        msg=msg.replace(i, '')
    return msg
