import socket
import threading
import select
import struct
from typing import Callable

MSG_SIZE = 2048
MULTICAST_GROUP = '224.0.0.1'
MULTICAST_PORT = 50000
active_clients = {}  # IP -> socket


def recv_exact(conn, size):
    data = b''
    while len(data) < size:
        chunk = conn.recv(size - len(data))
        if not chunk:
            raise ConnectionError("Client disconnected")
        data += chunk
    return data


def start_multicast_responder(tcp_ip, tcp_port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('', MULTICAST_PORT))

    mreq = struct.pack('4sl', socket.inet_aton(MULTICAST_GROUP), socket.INADDR_ANY)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

    while True:
        try:
            data, addr = sock.recvfrom(1024)
            if data == b"DISCOVER_SERVER":
                response = f"{tcp_ip}:{tcp_port}"
                sock.sendto(response.encode('utf-8'), addr)
        except Exception:
            continue


def init_server(ip:str, port:int, handle_client: Callable[[str,bytes], None]):
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((ip, port))
    server_sock.listen()
    server_sock.setblocking(False)

    poller = select.poll()
    fd_to_sock = {server_sock.fileno(): server_sock}
    poller.register(server_sock, select.POLLIN)

    def server_loop():
        while True:
            events = poller.poll()
            for fd, event in events:
                sock = fd_to_sock.get(fd)
                if not sock:
                    continue

                if sock is server_sock:
                    try:
                        conn, addr = server_sock.accept()
                        conn.setblocking(False)
                        fd_to_sock[conn.fileno()] = conn
                        active_clients[addr[0]] = conn
                        poller.register(conn, select.POLLIN)
                    except Exception:
                        continue
                elif event & select.POLLIN:
                    conn = sock
                    try:
                        client_ip = conn.getpeername()[0]
                        data = recv_exact(conn, MSG_SIZE)
                        handle_client(client_ip, data)
                    except Exception:
                        poller.unregister(fd)
                        conn.close()
                        fd_to_sock.pop(fd, None)
                        for ip, s in list(active_clients.items()):
                            if s == conn:
                                active_clients.pop(ip, None)

    threading.Thread(target=server_loop, daemon=True).start()
    threading.Thread(target=lambda: start_multicast_responder(ip, port), daemon=True).start()

    return server_sock


def send_to_client(client_ip:str, message: bytes):
    conn = active_clients.get(client_ip)
    if not conn:
        return False
    try:
        if len(message) > MSG_SIZE:
            message = message[:MSG_SIZE]
        else:
            message = message.ljust(MSG_SIZE, b'\x00')
        conn.sendall(message)
        return True
    except Exception:
        conn.close()
        active_clients.pop(client_ip, None)
        return False


# -------------------- KLIENT ------------------

def discover_server(timeout=3):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    sock.settimeout(timeout)

    try:
        sock.sendto(b"DISCOVER_SERVER", (MULTICAST_GROUP, MULTICAST_PORT))
        data, server = sock.recvfrom(1024)
        ip, port = data.decode('utf-8').split(':')
        return ip, int(port)
    except socket.timeout:
        return None, None
    finally:
        sock.close()

class PersistentClient:
    def __init__(self):
        self.sock = None
        self.running = False
        self.thread = None
        self.handle_message = None
        self.lock = threading.Lock()
        self.event = threading.Event()


    def get_lock(self):
        return self.lock


    def get_event(self):
        return self.event


    def set_event(self):
        if self.event.is_set:
            self.event.clear()
        else:
            self.event.set()


    def connect(self, ip:str, port:int, handle_message: Callable[[bytes], None]):
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
                data = recv_exact(self.sock, MSG_SIZE)
                if data and self.handle_message:
                    self.handle_message(data)
        except Exception:
            self.running = False

    def send_message(self, message: bytes):
        if not self.running or not self.sock:
            return
        try:
            if len(message) > MSG_SIZE:
                message = message[:MSG_SIZE]
            else:
                message = message.ljust(MSG_SIZE, b'\x00')
            self.sock.sendall(message)
        except Exception:
            self.running = False

    def close(self):
        self.running = False
        if self.sock:
            try:
                #self.sock.shutdown(socket.SHUT_RDWR)
                self.sock.close()
            except Exception:
                pass   
