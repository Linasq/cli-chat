import socket
import threading

MSG_SIZE = 2048

class PersistentClient:
    def __init__(self):
        self.sock = None
        self.running = False
        self.thread = None
        self.handle_message = None

    def connect(self, ip, port, handle_message):
        try:
            self.handle_message = handle_message
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((ip, port))
            self.running = True
            self.thread = threading.Thread(target=self._listen_loop, daemon=True)
            self.thread.start()
            return True
        except Exception:
            self.running = False
            self.sock = None
            return False

    def _listen_loop(self):
        try:
            while self.running:
                data = b''
                while len(data) < MSG_SIZE:
                    packet = self.sock.recv(MSG_SIZE - len(data))
                    if not packet:
                        self.running = False
                        break
                    data += packet
                if len(data) == MSG_SIZE and self.handle_message:
                    self.handle_message(data)
        except Exception:
            self.running = False

    def send_message(self, message_bytes):
        if not self.running or not self.sock:
            return
        try:
            # message_bytes musi mieć dokładnie MSG_SIZE bajtów
            if len(message_bytes) > MSG_SIZE:
                message_bytes = message_bytes[:MSG_SIZE]
            else:
                message_bytes = message_bytes.ljust(MSG_SIZE, b'\x00')
            self.sock.sendall(message_bytes)
        except Exception:
            self.running = False

    def close(self):
        self.running = False
        if self.sock:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
                self.sock.close()
            except Exception:
                pass


# ----------------- SERWER ---------------------


_active_clients = {}  # IP -> socket

def init_server(ip, port, handle_client):
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.bind((ip, port))
    server_sock.listen()

    def client_thread(conn, addr):
        client_ip = addr[0]
        _active_clients[client_ip] = conn
        try:
            while True:
                data = b''
                while len(data) < MSG_SIZE:
                    packet = conn.recv(MSG_SIZE - len(data))
                    if not packet:
                        raise ConnectionError("Client disconnected")
                    data += packet
                handle_client(client_ip, data)
        except Exception:
            pass
        finally:
            conn.close()
            _active_clients.pop(client_ip, None)

    def accept_loop():
        while True:
            conn, addr = server_sock.accept()
            threading.Thread(target=client_thread, args=(conn, addr), daemon=True).start()

    threading.Thread(target=accept_loop, daemon=True).start()
    return server_sock


def send_to_client(client_ip, message_bytes):
    conn = _active_clients.get(client_ip)
    if not conn:
        return False
    try:
        if len(message_bytes) > MSG_SIZE:
            message_bytes = message_bytes[:MSG_SIZE]
        else:
            message_bytes = message_bytes.ljust(MSG_SIZE, b'\x00')
        conn.sendall(message_bytes)
        return True
    except Exception:
        _active_clients.pop(client_ip, None)
        return False
