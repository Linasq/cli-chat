from network_backend import init_server, send_to_client

def handle_client(client_ip, message_bytes):
    clean_msg = message_bytes.rstrip(b'\x00').decode('utf-8', 'replace')
    print(f"[{client_ip}] -> {clean_msg}")
    
    response = f"Echo od serwera do {client_ip}".encode('utf-8')
    send_to_client(client_ip, response)

if __name__ == "__main__":
    init_server("192.168.122.1", 12345, handle_client)
    print("Serwer działa. Naciśnij Ctrl+C, aby zakończyć.")
    try:
        while True:
            pass
    except KeyboardInterrupt:
        print("\nZamykanie serwera.")
