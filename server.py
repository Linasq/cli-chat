from typing import Any, Dict, Tuple
import json
from db import srv_open_db, srv_insert_messages , srv_get_logins # assuming these functions are in the db module
import network_backend as net



DB_NAME = "server.db"  # or another path, depending on your project structure
curcor, db = srv_open_db(DB_NAME)


published_keys: Dict[str, Dict[str, str]] = {}     # user_id -> {"IK_sign_pub", "IK_dh_pub", "PK_pub", "SPK_sig"}
ephemeral_keys: Dict[str, Dict[str, str]] = {}     # user_id -> {"EK_pub"}


def handle_client(ip: str, data) -> None:
    """
    Handles a single client request.
    """
    try:
        data_raw = sock.recv(4096)
        if not data_raw:
            return
        data: Dict[str, Any] = json.loads(data_raw.decode())
        msg_type: str = data.get("type", "")

        if msg_type == "publish_keys":
            handle_publish_keys(sock, data)
        elif msg_type == "fetch_keys":
            handle_fetch_keys(sock, data)
        elif msg_type == "publish_ephemeral":
            handle_publish_ephemeral(sock, data)
        elif msg_type == "fetch_ephemeral":
            handle_fetch_ephemeral(sock, data)
        else:
            sock.sendall(json.dumps({"error": "Unknown request type"}).encode())

    except Exception as e:
        error_msg = f"[ERROR] {str(e)}"
        print(error_msg)
        sock.sendall(json.dumps({"error": error_msg}).encode())


def handle_publish_keys(sock: socket.socket, data: Dict[str, Any]) -> None:
    user_id: str = data["user_id"]
    published_keys[user_id] = {
        "IK_sign_pub": data["IK_sign_pub"],
        "IK_dh_pub": data["IK_dh_pub"],
        "PK_pub": data["PK_pub"],
        "SPK_sig": data["SPK_sig"]
    }
    print(f"[INFO] Stored keys for user {user_id}")
    sock.sendall(json.dumps({"status": "ok"}).encode())


def handle_fetch_keys(sock: socket.socket, data: Dict[str, Any]) -> None:
    user_id: str = data["user_id"]
    if user_id in published_keys:
        sock.sendall(json.dumps(published_keys[user_id]).encode())
        print(f"[INFO] Sent keys for user {user_id}")
    else:
        sock.sendall(json.dumps({"error": "No keys found for user"}).encode())
        print(f"[WARN] No keys found for user {user_id}")


def handle_publish_ephemeral(sock: socket.socket, data: Dict[str, Any]) -> None:
    user_id: str = data["user_id"]
    ephemeral_keys[user_id] = {
        "EK_pub": data["EK_pub"]
    }
    print(f"[INFO] Stored ephemeral key for user {user_id}")
    sock.sendall(json.dumps({"status": "ok"}).encode())


def handle_fetch_ephemeral(sock: socket.socket, data: Dict[str, Any]) -> None:
    user_id: str = data["user_id"]
    if user_id in ephemeral_keys:
        sock.sendall(json.dumps(ephemeral_keys[user_id]).encode())
        print(f"[INFO] Sent ephemeral key for user {user_id}")
    else:
        sock.sendall(json.dumps({"error": "No ephemeral key found for user"}).encode())
 



def register_handler(message: dict) -> None:
    """
    Handles incoming 'register' messages from a client and stores the user in the database.
    """
    username = message.get("login")
    password = message.get("password")

    if not username or not password:
        error_response = {
            "type": "error",
            "message": "Invalid register message. Both 'login' and 'password' are required."
        }
#        client.send_message(json.dumps(error_response).encode())
        return

    try:
        # Open connection to the database and create tables if they don't exist
        cursor, db = srv_open_db(DB_NAME)

        # Insert the new user into the registered_users table
        srv_insert_messages(cursor, 'registered_users', username, password)

        # Commit changes and close the database connection
        db.commit()
        db.close()

    except Exception as e:
        error_response = {
            "type": "error",
            "message": f"Server error during registration: {str(e)}"
        }
 #       client.send_message(json.dumps(error_response).encode())


def login_handler(message: dict, cursor) -> None:
    """
    Handles 'login' messages: checks if username exists and verifies password hash.
    Assumes the database connection is already open and cursor is passed in.
    """
    username = message.get("username")
    password = message.get("password")

    if not username or not password:
        error_response = {
            "type": "login_response",
            "status": "error",
            "message": "Missing 'username' or 'password'."
        }
        client.send_message(json.dumps(error_response).encode())
        return

    try:
        # Get list of registered usernames
        existing_logins = [row[0] for row in srv_get_logins(cursor)]

        if username not in existing_logins:
            error_response = {
                "type": "login_response",
                "status": "error",
                "message": "Username not found."
            }
            client.send_message(json.dumps(error_response).encode())
            return

        # Fetch stored password hash for the user
        cursor.execute("SELECT password FROM registered_users WHERE username = ?", (username,))
        stored_password = cursor.fetchone()

        if not stored_password or stored_password[0] != password:
            error_response = {
                "type": "login_response",
                "status": "error",
                "message": "Incorrect password."
            }
            client.send_message(json.dumps(error_response).encode())
            return

        # Credentials correct — send success response
        success_response = {
            "type": "login_response",
            "status": "ok",
            "message": "OK"
        }
        client.send_message(json.dumps(success_response).encode())

    except Exception as e:
        error_response = {
            "type": "login_response",
            "status": "error",
            "message": f"Internal server error: {str(e)}"
        }
        client.send_message(json.dumps(error_response).encode())


# Stores keys published by clients
published_keys: Dict[str, Dict[str, str]] = {}     # user_id -> {"IK_sign_pub", "IK_dh_pub", "PK_pub", "SPK_sig"}
ephemeral_keys: Dict[str, Dict[str, str]] = {}     # user_id -> {"EK_pub"}


sock = net.init_server('192.168.122.1', 12345, handle_client)
