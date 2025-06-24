from base64 import b64decode, b64encode
import sqlite3
from cryptography.hazmat.primitives.ciphers.algorithms import AES256
from datetime import datetime
from os import mkdir

def encrypt_db(db_name: str, key: bytes):
    # cipher = aes.new(key, aes.MODE_ECB)
    # print(cipher)
    pass


def decrypt_db(db_name: str, key: bytes):
    pass


def open_db(db_name: str):
    try:
        db = sqlite3.connect(db_name)
    except:
        mkdir('db')
        db = sqlite3.connect(db_name)

    cursor = db.cursor()
    return cursor, db


def close_db(cursor: sqlite3.Cursor, db: sqlite3.Connection):
    db.commit()
    cursor.close()
    db.close()
    return


def get_names(db_name: str):
    cursor, db = open_db(db_name)
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';")
    names = cursor.fetchall()
    close_db(cursor, db)
    return names


def get_history(db_name: str, name: str):
    cursor, db = open_db(db_name)
    cursor.execute(f'''create table if not exists {name}(
        id INTEGER PRIMARY KEY autoincrement,
        timestamp TEXT,
        name TEXT,
        msg TEXT,
        users TEXT
    );''')
    cursor.execute(f'select timestamp, name, msg, users from {name}')
    chat = cursor.fetchall()
    close_db(cursor, db)
    if not chat:
        return chat

    results = []
    for i in chat:
        results.append((i[0], i[1], b64decode(i[2]).decode(), i[3]))

    return results


def insert_chat(db_name: str, timestamp:str, table_name: str, name: str, text: str, users: list[str]):
    cursor, db = open_db(db_name)
    text_base = b64encode(text.encode())
    cursor.execute(f'''insert into {table_name}(timestamp, name, msg, users) values(?, ?, ?, ?)''', (timestamp, name, text_base, ','.join(users)))
    close_db(cursor, db)
    return


def sanitize_input(msg:str) -> str:
    bad_actors = [',', '.', ';', '"', "'", '(', ')', '|', '-', '#', '[', ']', '{','}', ':']
    for i in bad_actors:
        msg=msg.replace(i, '')
    return msg


# --- SERVER ----


def srv_open_db(db_name: str):
    db = sqlite3.connect(db_name)
    cursor = db.cursor()
    cursor.execute(f'''create table if not exists registered_users(
        id INTEGER PRIMARY KEY autoincrement,
        username TEXT,
        password TEXT
    );''')

    '''
    timestamp
    src - nick wysylajacego
    dst - nick do ktorego idzie wiadomosc
    name - nazwa uzytkownika / grupy
    msg - wiadomosc
    '''
    cursor.execute(f'''create table if not exists messages(
        id INTEGER PRIMARY KEY autoincrement,
        timestamp TEXT,
        src TEXT,
        dst TEXT,
        name TEXT,
        text TEXT
    );''')
    return cursor, db


def srv_get_messages(username: str):#(cursor: sqlite3.Cursor, username: str):
    cursor, db = open_db('server.db')
    cursor.execute(f'''
        select timestamp, src, dst, msg from messages
        where dst like ?
           ''', (username, ))

    msg = cursor.fetchall()
    close_db(cursor, db)
    return msg


def srv_get_logins(username: str):#(cursor: sqlite3.Cursor, username: str):
    cursor, db = open_db('server.db')
    cursor.execute('''
        select username, password from registered_users where username like ?
                   ''', (username,))
    users = cursor.fetchall()
    close_db(cursor, db)
    return users


def srv_insert_messages(table_name: str, *args):#(db: sqlite3.Connection, cursor: sqlite3.Cursor, table_name: str, *args):
    cursor, db = srv_open_db('server.db')
    if table_name == 'registered_users' and len(args) == 2:
        cursor.execute(f'''
            insert into {table_name}(username, password)
                    values(?, ?)''',
                       (args[0], args[1],))

    elif table_name == 'messages' and len(args) == 4:
        cursor.execute(f'''
            insert into {table_name}(timestamp, src, dst, msg)
                    values(?, ?, ?, ?)''',
                       (args[0], args[1], args[2], args[3],))
    
    close_db(cursor, db)
