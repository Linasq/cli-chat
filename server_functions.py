import json

# Przechowuje dane publikowane przez klientów
published_keys = {}      # user_id -> {"IK_sign_pub", "IK_dh_pub", "PK_pub", "SPK_sig"}
ephemeral_keys = {}      # user_id -> {"EK_pub"}

def handle_client(sock):
    """
    Obsługuje pojedyncze żądanie od klienta.
    """
    try:
        data_raw = sock.recv(4096)
        if not data_raw:
            return
        data = json.loads(data_raw.decode())
        msg_type = data.get("type")

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


def handle_publish_keys(sock, data):
    user_id = data["user_id"]
    published_keys[user_id] = {
        "IK_sign_pub": data["IK_sign_pub"],
        "IK_dh_pub": data["IK_dh_pub"],
        "PK_pub": data["PK_pub"],
        "SPK_sig": data["SPK_sig"]
    }
    print(f"[INFO] Zapisano klucze użytkownika {user_id}")
    sock.sendall(json.dumps({"status": "ok"}).encode())


def handle_fetch_keys(sock, data):
    user_id = data["user_id"]
    if user_id in published_keys:
        sock.sendall(json.dumps(published_keys[user_id]).encode())
        print(f"[INFO] Wysłano klucze użytkownika {user_id}")
    else:
        sock.sendall(json.dumps({"error": "No keys found for user"}).encode())
        print(f"[WARN] Brak kluczy dla użytkownika {user_id}")


def handle_publish_ephemeral(sock, data):
    user_id = data["user_id"]
    ephemeral_keys[user_id] = {
        "EK_pub": data["EK_pub"]
    }
    print(f"[INFO] Zapisano ephemeral key użytkownika {user_id}")
    sock.sendall(json.dumps({"status": "ok"}).encode())


def handle_fetch_ephemeral(sock, data):
    user_id = data["user_id"]
    if user_id in ephemeral_keys:
        sock.sendall(json.dumps(ephemeral_keys[user_id]).encode())
        print(f"[INFO] Wysłano ephemeral key użytkownika {user_id}")
    else:
        sock.sendall(json.dumps({"error": "No ephemeral key found for user"}).encode())
        print(f"[WARN] Brak ephemeral key dla użytkownika {user_id}")

