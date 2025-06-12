import socket
import threading
import json

# Pamięć na klucze: user_id -> keys dict
user_keys_db = {}

def client_handler(conn, addr):
    print(f"Connected: {addr}")
    try:
        while True:
            data = conn.recv(4096)
            if not data:
                break
            try:
                message = json.loads(data.decode())
            except Exception as e:
                print("Invalid JSON:", e)
                continue

            msg_type = message.get("type")
            if msg_type == "publish_keys":
                user_id = message.get("user_id")
                if not user_id:
                    conn.sendall(b'{"error":"Missing user_id"}')
                    continue
                # Zapisz klucze
                user_keys_db[user_id] = {
                    "IK_sign_pub": message.get("IK_sign_pub"),
                    "IK_dh_pub": message.get("IK_dh_pub"),
                    "PK_pub": message.get("PK_pub"),
                    "SPK_sig": message.get("SPK_sig")
                }
                print(f"Stored keys for {user_id}")
                conn.sendall(b'{"status":"ok"}')

            elif msg_type == "fetch_keys":
                user_id = message.get("user_id")
                if not user_id:
                    conn.sendall(b'{"error":"Missing user_id"}')
                    continue
                keys = user_keys_db.get(user_id)
                if not keys:
                    conn.sendall(b'{"error":"User keys not found"}')
                    continue
                resp = json.dumps(keys).encode()
                conn.sendall(resp)

            else:
                conn.sendall(b'{"error":"Unknown type"}')

    except Exception as e:
        print(f"Connection error {addr}: {e}")
    finally:
        conn.close()
        print(f"Disconnected: {addr}")

def run_server(host='0.0.0.0', port=5555):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((host, port))
    sock.listen()
    print(f"Server listening on {host}:{port}")

    try:
        while True:
            conn, addr = sock.accept()
            threading.Thread(target=client_handler, args=(conn, addr), daemon=True).start()
    except KeyboardInterrupt:
        print("Server stopped")

if __name__ == "__main__":
    run_server()

