from network_backend import init_server

def handle_client(message_bytes):
    print("Odebrano wiadomość:", message_bytes.rstrip(b'\x00').decode('utf-8', 'replace'))

if __name__ == "__main__":
    init_server("192.168.18.101", 12345, handle_client)
    print("Serwer działa. Naciśnij Ctrl+C, aby zakończyć.")
    try:
        while True:
            pass
    except KeyboardInterrupt:
        print("\nZamykanie serwera.")
