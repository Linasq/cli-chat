import json
import socket
from typing import Dict, Any

# Stores keys published by clients
published_keys: Dict[str, Dict[str, str]] = {}     # user_id -> {"IK_sign_pub", "IK_dh_pub", "PK_pub", "SPK_sig"}
ephemeral_keys: Dict[str, Dict[str, str]] = {}     # user_id -> {"EK_pub"}


def handle_client(sock: socket.socket) -> None:
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
        print(f"[WARN] No ephemeral key found for user {user_id}")
