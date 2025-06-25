from base64 import b64decode, b64encode
import sqlite3
import crypto_functions as cr
from os import mkdir

def encrypt_db(db_name: str, key: bytes):
    '''
    Encrypts Database under given directory
    '''
    sha3 = cr.hash_sha3(key)
    cr.encrypt_db(sha3, db_name)


def decrypt_db(db_name: str, key: bytes):
    '''
    Decrypts Database under given directory
    '''
    sha3 = cr.hash_sha3(key)
    cr.decrypt_db(sha3, db_name)


def open_db(db_name: str):
    '''
    Opens Database located under given directory.
    It's used only in other DB functions

    Returns:
        sqlite3.Cursor
        sqlite3.Connection
    '''
    try:
        db = sqlite3.connect(db_name)
    except:
        mkdir('db')
        db = sqlite3.connect(db_name)

    cursor = db.cursor()
    return cursor, db


def close_db(cursor: sqlite3.Cursor, db: sqlite3.Connection):
    '''
    Closes Connection and Cursor from given DB.
    It also commits all changes that have been made.
    '''
    db.commit()
    cursor.close()
    db.close()
    return


def get_names(db_name: str):
    '''
    Returns table names from db_name
    '''
    cursor, db = open_db(db_name)
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';")
    names = cursor.fetchall()
    close_db(cursor, db)
    return names


def get_history(db_name: str, name: str):
    '''
    Creates table if not exists and return its contents

    Return: -> List[Tuple(str)]
        timestamp, name, msg, users
    '''
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
    '''
    Inserts into DB values:
        timestamp, name, msg, users
    '''
    cursor, db = open_db(db_name)
    text_base = b64encode(text.encode())
    cursor.execute(f'''insert into {table_name}(timestamp, name, msg, users) values(?, ?, ?, ?)''', (timestamp, name, text_base, ','.join(users)))
    close_db(cursor, db)
    return


def sanitize_input(msg:str) -> str:
    '''
    Sanitizes input :O

    Return:
        safe input
    '''
    bad_actors = [',', '.', ';', '"', "'", '(', ')', '|', '-', '#', '[', ']', '{','}', ':']
    for i in bad_actors:
        msg=msg.replace(i, '')
    return msg


# --- SERVER ----


def srv_open_db(db_name: str):
    '''
    Opens server.db and creates 2 tables if those do not exist:
        registered_users - storage with every registered user
        messages - storage with messages to offline clients

    Return:
        sqlite3.Cursor, sqlite3.Connection 
    '''
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


def srv_get_messages(username: str):
    '''
    Returns messages from given offline user

    Returs:
        timestamp, src, dst, name, msg
    '''
    cursor, db = open_db('server.db')
    cursor.execute(f'''
        select timestamp, src, dst, name, text from messages
        where dst like ?
           ''', (username, ))

    msg = cursor.fetchall()
    close_db(cursor, db)
    return msg


def srv_get_logins(username: str):
    '''
    Returns credentials for given username (if exists)

    Returs:
        timestamp, src, dst, name, msg
    '''
    cursor, db = open_db('server.db')
    cursor.execute('''
        select username, password from registered_users where username like ?
                   ''', (username,))
    users = cursor.fetchall()
    close_db(cursor, db)
    return users


def srv_insert_messages(table_name: str, *args):
    '''
    Inserts messages into DB.
    You can choose whether you inserts into "registered_users" or "messages"
    
    "registered_users" needs:
        username, password

    "messages" needs:
        timestamp, src, dst, name, msg
    '''
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
