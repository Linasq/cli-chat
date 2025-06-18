import json
from db import srv_open_db, srv_insert_messages  # assuming these functions are in the db module

DB_NAME = "server.db"  # or another path, depending on your project structure

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



# Stores keys published by clients
published_keys: Dict[str, Dict[str, str]] = {}     # user_id -> {"IK_sign_pub", "IK_dh_pub", "PK_pub", "SPK_sig"}
ephemeral_keys: Dict[str, Dict[str, str]] = {}     # user_id -> {"EK_pub"}


