import socket
import threading
import select
import struct

MSG_SIZE = 2048
MULTICAST_GROUP = '224.0.0.1'
MULTICAST_PORT = 50000
_active_clients = {}  # IP -> socket


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



# ----------------- SERWER ---------------------



def _start_multicast_responder(tcp_ip, tcp_port):
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


def init_server(ip, port, handle_client):
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
                sock = fd_to_sock[fd]
                if sock is server_sock:
                    conn, addr = server_sock.accept()
                    conn.setblocking(False)
                    fd_to_sock[conn.fileno()] = conn
                    _active_clients[addr[0]] = conn
                    poller.register(conn, select.POLLIN)
                elif event & select.POLLIN:
                    conn = sock
                    client_ip = None
                    try:
                        client_ip = conn.getpeername()[0]
                        data = conn.recv(MSG_SIZE)
                        if data:
                            handle_client(client_ip, data)
                        else:
                            raise ConnectionError
                    except:
                        poller.unregister(fd)
                        conn.close()
                        if client_ip:
                            _active_clients.pop(client_ip, None)
                            fd_to_sock.pop(fd, None)    
    threading.Thread(target=server_loop, daemon=True).start()
    threading.Thread(target=lambda: _start_multicast_responder(ip, port), daemon=True).start()

    return server_sock



def send_to_client(client_ip, message_bytes):
    for fd, (conn, ip) in _active_clients.items():
        if ip == client_ip:
            try:
                if len(message_bytes) > MSG_SIZE:
                    message_bytes = message_bytes[:MSG_SIZE]
                else:
                    message_bytes = message_bytes.ljust(MSG_SIZE, b'\x00')
                conn.sendall(message_bytes)
                return True
            except Exception:
                conn.close()
                _active_clients.pop(fd, None)
                return False
    return False
