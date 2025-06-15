from network_backend import PersistentClient, discover_server

def handle_message(message_bytes):
    print("Otrzymano od serwera:", message_bytes.rstrip(b'\x00').decode('utf-8', 'replace'))

ip,port = discover_server()


if __name__ == "__main__":
    client = PersistentClient()
    if client.connect(ip, port, handle_message):
        print("Połączono z serwerem.")
        try:
            while True:
                msg = input("Wpisz wiadomość (enter kończy): ")
                if not msg:
                    break
                client.send_message(msg.encode('utf-8'))
        finally:
            client.close()
            print("Rozłączono klienta.")
    else:
        print("Nie udało się połączyć z serwerem.")
