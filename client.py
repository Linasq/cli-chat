import interface
import network_backend as net

ip, port = net.discover_server()
client = net.PersistentClient()
app = interface.ChatClientApp()
if ip and port:
    client.connect(ip, port, app.recv_msg)
    app.set_client(client)
else:
    print('could not connect to server')
    exit()
app.run()
