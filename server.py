from os import wait
from typing import Any, Dict, Tuple
import json
from db import srv_open_db, srv_insert_messages , srv_get_logins # assuming these functions are in the db module
import network_backend as net


active_clients = {} 
DB_NAME = "server.db"  # or another path, depending on your project structure
curcor, db = srv_open_db(DB_NAME)


published_keys: Dict[str, Dict[str, str]] = {}     # user_id -> {"IK_sign_pub", "IK_dh_pub", "PK_pub", "SPK_sig"}
ephemeral_keys: Dict[str, Dict[str, str]] = {}     # user_id -> {"EK_pub"}


def handle_client(ip: str, msg: bytes) -> None:
    """
    Handles a single client request.
    """
    try:
        data = json.loads(msg.decode())
        msg_type= data.get("type")

        if msg_type == "publish_keys":
            handle_publish_keys(ip, data)
        elif msg_type == "fetch_keys":
            handle_fetch_keys(ip, data)
        elif msg_type == "publish_ephemeral":
            handle_publish_ephemeral(ip, data)
        elif msg_type == "fetch_ephemeral":
            handle_fetch_ephemeral(ip, data)
        elif msg_type == "register":
            register_handler(ip, data)
        elif msg_type == "login":
            login_handler(ip, data, curcor)
        elif msg_type == "msg":
            handle_message(ip,data)


        else:
            net.send_to_client(ip,json.dumps({"error": "Unknown request type"}).encode())
            net.send_to_client(ip, msg)

    except Exception as e:
        error_msg = f"[ERROR] {str(e)}"
        print(error_msg)
        net.send_to_client(ip, json.dumps({"error": error_msg}).encode())


def handle_publish_keys(ip: str,data: Dict[str, Any]) -> None:
    user_id: str = data["user_id"]
    published_keys[user_id] = {
        "IK_sign_pub": data["IK_sign_pub"],
        "IK_dh_pub": data["IK_dh_pub"],
        "PK_pub": data["PK_pub"],
        "SPK_sig": data["SPK_sig"]
    }
    print(f"[INFO] Stored keys for user {user_id}")
    net.send_to_client(ip, json.dumps({"status": "ok"}).encode())


def handle_fetch_keys(ip: str, data: Dict[str, Any]) -> None:
    user_id: str = data["user_id"]
    if user_id in published_keys:
        net.send_to_client(ip, json.dumps(published_keys[user_id]).encode())
        print(f"[INFO] Sent keys for user {user_id}")
    else:
        net.send_to_client(ip, json.dumps({"error": "No keys found for user"}).encode())
        print(f"[WARN] No keys found for user {user_id}")


def handle_publish_ephemeral(ip: str, data: Dict[str, Any]) -> None:
    user_id: str = data["user_id"]
    ephemeral_keys[user_id] = {
        "EK_pub": data["EK_pub"]
    }
    print(f"[INFO] Stored ephemeral key for user {user_id}")
    net.send_to_client(ip, json.dumps({"status": "ok"}).encode())


def handle_fetch_ephemeral(ip: str, data: Dict[str, Any]) -> None:
    user_id: str = data["user_id"]
    if user_id in ephemeral_keys:
        net.send_to_client(ip, json.dumps(ephemeral_keys[user_id]).encode())
        print(f"[INFO] Sent ephemeral key for user {user_id}")
    else:
        net.send_to_client(ip, json.dumps({"error": "No ephemeral key found for user"}).encode())
 



def handle_message(ip, message: dict):
    src_username = message.get("src")
    name = message.get("name")
    data = message.get("msg")
    dst_username = message.get("dst")
    try: 
        dst_ip = active_clients[dst_username]
    except:
        #TODO zrobić zapis do bazy
        return
    
    msg_to_send = {
            "type": "msg",
            "src": src_username,
            "name": name,
            "msg": data
            }
    try:
        net.send_to_client(dst_ip, json.dumps(msg_to_send).encode())
    except Exception as e:
        error_response = {
            "type": "error",
            "msg": "Server error while sending message to client"
        }
        net.send_to_client(ip,json.dumps(error_response).encode())
        return 






def register_handler(ip: str, message: dict) -> None:
    """
    Handles incoming 'register' messages from a client and stores the user in the database.
    """
    username = message.get("login")
    password = message.get("password")

    if not username or not password:
        error_response = {
            "type": "error",
            "msg": "Invalid register message. Both 'login' and 'password' are required."
        }
        net.send_to_client(ip,json.dumps(error_response).encode())
        return

    try:
        # Open connection to the database and create tables if they don't exist
        cursor, db = srv_open_db(DB_NAME)

        # Insert the new user into the registered_users table
        srv_insert_messages(cursor, 'registered_users', username, password)

        # Commit changes and close the database connection
        db.commit()
        db.close()
        # type: register
        # text: OK
        payload = {
                "type": "register",
                "msg": "OK"
                }
        net.send_to_client(ip, json.dumps(payload).encode())

    except Exception as e:
        error_response = {
            "type": "error",
            "msg": f"Server error during registration: {str(e)}"
        }
        net.send_to_client(ip,json.dumps(error_response).encode())


def login_handler(ip:str, message: dict, cursor) -> None:
    """
    Handles 'login' messages: checks if username exists and verifies password hash.
    Assumes the database connection is already open and cursor is passed in.
    """
    username = message.get("username")
    password = message.get("password")

    if not username or not password:
        error_response = {
            "type": "login_response",
            "msg": "Missing 'username' or 'password'."
        }
        net.send_to_client(ip, json.dumps(error_response).encode())
        return

    try:
        # Get list of registered usernames
        # Fetch stored password hash for the user
        username, password = srv_get_logins(cursor, username)[0]

        if username not in existing_logins:
            error_response = {
                "type": "login_response",
                "msg": "Username not found."
            }
            net.send_to_client(ip,json.dumps(error_response).encode())
            return


        if not stored_password or stored_password[0] != password:
            error_response = {
                "type": "login_response",
                "msg": "Incorrect password."
            }
            net.send_to_client(ip,json.dumps(error_response).encode())
            return

        # Credentials correct — send success response
        success_response = {
            "type": "login_response",
            "msg": "OK"
        }
        active_clients[username] = ip
        net.send_to_client(ip,json.dumps(success_response).encode())

    except Exception as e:
        error_response = {
            "type": "login_response",
            "msg": f"Internal server error: {str(e)}"
        }
        net.send_to_client(ip,json.dumps(error_response).encode())


# Stores keys published by clients
published_keys: Dict[str, Dict[str, str]] = {}     # user_id -> {"IK_sign_pub", "IK_dh_pub", "PK_pub", "SPK_sig"}
ephemeral_keys: Dict[str, Dict[str, str]] = {}     # user_id -> {"EK_pub"}


net.init_server('192.168.122.1', 12345, handle_client)
try:
    while True:
        pass
except KeyboardInterrupt:
    print("\nZamykanie serwera.")
